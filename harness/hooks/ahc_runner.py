#!/usr/bin/env python3
"""ahc runner (GoodQA goodqa#16034, Gate 1: receipt-only, no merge authority).

One tick: ingest the queue into the ledger, recover orphans, process due items (packet integrity, lint/fix, live PR
resolve, daemon clone, one exact-head `peer_review.py pr` run, verify), then dispatch outbound effects (ticket
comment, owner inbox, digest), escalate unacknowledged owner notices, and beat the heartbeat.

Ledger (spec D13): one SQLite database in WAL mode. Invariants enforced here:
  I1  an accepted item keeps its id (sha of repo|pr|head|packet sha) and survives restart;
  I2  every non-terminal item and every pending effect carries `next_action_at`;
  I3  a worker settles an item only while it holds the item's lease token (fencing);
  I4  every external effect has an intent row committed before dispatch; an effect left at `intent` is read back
      (file present, digest key present, idempotent ticket key) before any redispatch, and a review left at
      `intent` is never relaunched: it goes to outcome-unknown (D26) for usage_guard reconciliation;
  I5  attempt counts live on the item and on its PR lineage and survive restart and resubmission;
  I9  a missing observation (gh failure, unknown review outcome) is never read as success.
Retry classes live in one function, `retry_policy`.

Gate 1 never binds the review (`--github-repo/--pr`), never calls a merge, never reads credentials and contains no
LLM call. Every child is an argv list; finding text reaches `ah ticket comment` as one argv element.
"""
from __future__ import annotations

import argparse
import fcntl
import fnmatch
import hashlib
import json
import logging
import logging.handlers
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ahc_core as core  # noqa: E402
import ahc_fs as fs  # noqa: E402
import ahc_contracts  # noqa: E402
import ahc_migrate  # noqa: E402
import ahc_packet  # noqa: E402
from ahc_crash import crash_after, crash_before  # noqa: E402
import redact  # noqa: E402

STOP_AFTER = None   # test hook: raise after this state is persisted (simulates a kill)

# The state table (spec D20 coverage rule, NEG-23): one row per item state, and the only place a state is declared.
#   settled   no daemon action follows (next_action_at is NULL); otherwise the item is non-terminal (I2)
#   waits_on  who acts next: daemon, owner, main, owner-or-main, or None (finished, nobody owes anything)
#   cover     how a person-waiting state escalates past main: "d20" (age-based: 4 h after entry, then every 24 h,
#             until disposition, supersession or the PR merging/closing) or "ack" (the owner notice needs an ack and
#             escalates once at its deadline, AC-19)
#   alert     terminal-unsuccessful: a high alert as well as the ticket (D14)
#   notice    the owner gets a notice when the item enters the state
#   dispose   who may record a disposition that stops D20 (main is verified, never just claimed)
# P1 states (repo halt, review-invalid, authority expired, merged-not-delivered, waiting:cap) join this table with
# their P1 code; the NEG-23 test enumerates whatever the table holds.
STATE_TABLE = {
    "queued": {"settled": False, "waits_on": "daemon"},
    "deferred": {"settled": False, "waits_on": "daemon"},
    "reviewing": {"settled": False, "waits_on": "daemon"},
    "routed-to-main": {"settled": False, "waits_on": "main", "cover": "d20", "dispose": ("main",)},
    "needs-attention": {"settled": True, "waits_on": "owner-or-main", "cover": "d20", "alert": True, "notice": True,
                        "dispose": ("main",)},
    "refused": {"settled": True, "waits_on": "owner", "cover": "ack", "alert": True, "notice": True},
    "lint-failed": {"settled": True, "waits_on": "owner", "cover": "ack", "alert": True, "notice": True},
    "review-error": {"settled": True, "waits_on": "owner", "cover": "ack", "alert": True, "notice": True},
    # v6e T14: invalid reviewer output with the head's invalid repeat spent, or a cause inside the packet
    "review-invalid": {"settled": True, "waits_on": "owner-or-main", "cover": "d20", "alert": True, "notice": True,
                       "dispose": ("main",)},
    "stale-head": {"settled": True, "waits_on": "owner", "cover": "ack", "notice": True},
    # D14 / v6e M4: a BLOCK verdict delivered to the owner and awaiting the ack. `ahc ack` moves it to
    # `acknowledged`, which only acknowledges receipt: the repair deadline (D20, timed from the ack) still runs until
    # a new head (superseded-by-head), the PR closing or merging, or a main disposition (M3: closing a BLOCK without
    # a repair is main's call, never an owner's).
    "block-delivered": {"settled": True, "waits_on": "owner", "cover": "d20", "notice": True, "dispose": ("main",)},
    "acknowledged": {"settled": True, "waits_on": "owner", "cover": "d20", "dispose": ("main",)},
    # D26 recovery states (spec v23b). blocked = a guard or policy refusal, routed to the decision-maker (v6e M4;
    # never an alternate path).
    "blocked": {"settled": True, "waits_on": "main", "cover": "d20", "notice": True, "dispose": ("main",)},
    # outcome-unknown: a step that is not replay-safe (a provider review) was in flight or its result could not be
    # read; nothing is relaunched and no failure or success is recorded until a readback (usage_guard reconcile).
    "outcome-unknown": {"settled": True, "waits_on": "owner-or-main", "cover": "d20", "alert": True, "notice": True,
                        "dispose": ("main",)},
    # cancel-requested: a cancel the daemon has not yet confirmed (the cancel request arrives with the submit API);
    # it escalates under D20 if the confirmation never comes. cancelled-confirmed: the cancel was read back.
    "cancel-requested": {"settled": False, "waits_on": "daemon", "cover": "d20", "dispose": ("main",)},
    "cancelled-confirmed": {"settled": True, "waits_on": None},
    # v6e T2: a PR head with no submission (here: the new head that superseded a delivered or acknowledged BLOCK),
    # waiting on the owner under D20 so the obligation never disappears; a submission at that head supersedes it
    "unsubmitted": {"settled": True, "waits_on": "owner", "cover": "d20", "notice": True, "dispose": ("main",)},
    "superseded": {"settled": True, "waits_on": None},
    "merged": {"settled": True, "waits_on": None},
    "closed": {"settled": True, "waits_on": None},
}
TERMINAL = {s for s, row in STATE_TABLE.items() if row["settled"]}
NON_TERMINAL = {s for s, row in STATE_TABLE.items() if not row["settled"]}
ALERT_STATES = {s for s, row in STATE_TABLE.items() if row.get("alert")}  # terminal-unsuccessful (D14)
OWNER_NOTICE_STATES = {s for s, row in STATE_TABLE.items() if row.get("notice")}
D20_STATES = {s for s, row in STATE_TABLE.items() if row.get("cover") == "d20"}
PERSON_ACTORS = ("owner", "main", "owner-or-main")
UNKNOWN_OUTCOME = "outcome-unknown"
REVIEW_TIMEOUT = 720                     # per provider, peer_review's cap
REVIEW_WALL = core.TIMEOUTS["review"]    # primary plus one fallback (D21)
LEASE_SECONDS = REVIEW_WALL + 60         # lease = timeout + 60 s; a reclaim mints a new fencing token
PASS_RECHECK = 3600             # routed-to-main: re-read the PR this often
# D19 email route: ops-watch mails only CRITICAL raises through its deadman command; the daemon never sends mail
# itself and never reads ops-watch's private state. Proof of handoff is `ops_watch.py delivered --key K --json`.
EMAIL_UNDELIVERED_SECONDS = 30 * 60   # no receipt this long after the raise: email-undelivered (ticket + high alert)
MAIL_CHECK_MAX = 7 * 86400            # stop re-checking a receipt after this; the email-undelivered alert stands
OPS_WATCH_TIMEOUT = 30
EMAIL_CAPABILITIES = ("forward-foreign-critical", "deadman-delivered")
SYSTEM_ITEM = "ahc-system"            # effects that belong to the daemon, not to an item (email-route readiness)
UNDELIVERED_PREFIX = "ahc:email-undelivered:"
D20_FIRST = 4 * 3600            # D20: escalate 4 h after entering a covered state ...
D20_REPEAT = 24 * 3600          # ... then every 24 h while it still waits
MAX_BODY = 6000
PROTECTED = ("merge_gate*", "peer_review*", "caller_identity*", "native_main*", "ahc*", "usage_guard*",
             "commit_policy*", "review_diagnostics*", "settings.json", "settings.local.json", "hooks_manifest.json",
             "coordinator-authority*")
DIAG = re.compile(r"REVIEW_DIAGNOSTIC code=([A-Z_]+)")
RESET = re.compile(r"reset(?:s)?(?: at)?[ :=]+(\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?Z)", re.I)

log = logging.getLogger("ahc")
logging.raiseExceptions = False


class _Stop(Exception):
    """Raised by the STOP_AFTER test hook."""


class Fenced(RuntimeError):
    """The worker's lease token is no longer current; it must not settle state."""


# ---------------------------------------------------------------- retry classes (D13)

BOUNDS = {  # spec D19 defaults; `bounds` in ahc.json overrides each key
    "tick_seconds": 60,
    "dispatch_seconds": 120,
    "pre_provider_runs": 2,
    "quota_auth_deadline_seconds": 24 * 3600,
    "delivery_backoff_cap_seconds": 1800,
    "delivery_escalate_seconds": 2 * 3600,
    "block_ack_seconds": 4 * 3600,
    "queue_capacity": 50,
    "invalid_output_repeat": True,
}


def bounds(config):
    limits = dict(BOUNDS)
    limits.update((config or {}).get("bounds", {}))
    return limits


def unstamped_argv_problem(argv):
    """Why a daemon review argv may not launch, or None (M-1 NEG-7). The daemon's review is bound to one PR and
    carries --no-main-stamp, so it can never take main's review-auth stamp; it never asserts --author-harness and
    never passes a main approval."""
    if "--no-main-stamp" not in argv:
        return "daemon review argv lacks --no-main-stamp"
    if "--author-harness" in argv or "--approved-by" in argv:
        return "daemon review argv asserts an author harness or an approval"
    if not ("--github-repo" in argv and "--pr" in argv):
        return "daemon review argv is not bound to a PR"
    return None


def retry_policy(failure_class, attempts, now, retry_at=None, first_at=None, config=None):
    """(state, next_action_at) for a failure. `attempts` counts this class's failures so far, this one included;
    For provider-transient, invalid-output and freshness, `attempts` is 1 when the head's one retry of that class
    was still unused and 2 when it was already spent (v6e retry budget, per (lineage, head), first-come). `first_at`
    is the head's first deferral (v6f: the 24 h deferred deadline, T8, never reset by re-entry). Bounds from D19.

    gh-transient        live PR read failed: capped exponential backoff, then needs-attention after 8
    pre-provider        clone or other deterministic repair: at most pre_provider_runs (2), then needs-attention
    provider-transient  peer_review already used its primary and fallback: the head's one deferred retry (T11),
                        then needs-attention (T16)
    invalid-output      reviewer output unusable for a reason outside the packet: the head's one declared repeat
                        when invalid_output_repeat is on (T12), then review-invalid (T14); never a second repeat
    freshness           D24 ticket-freshness STALE (pre-launch, no provider spend): the head's one re-run after the
                        note (T13), then needs-attention (T16)
    quota               durable retry_at from the reset time (default 1 h), no probing, no class consumed (T15);
                        review-error once 24 h have passed since the head's first deferral (T8)
    auth                opens the provider circuit and defers (T15): the item re-checks the circuit every 30 min
                        and never launches while it is open (no timed retry, no class consumed); T8 ends it in
                        review-error 24 h after the head's first deferral
    contention          pool busy (REVIEW_NOT_STARTED on a held pool): wait; waiting is not an attempt
    unknown-outcome     launch or supervision outcome unknown: outcome-unknown until usage_guard reconciliation
    environment         local reviewer environment defect (EXEC_*, SNAPSHOT_*): needs-attention
    advisory            an advisory opinion is not a signoff: review-error, no retry
    inconsistent        a receipt whose verdict contradicts its exit status: review-error, no retry
    block               never re-run unchanged
    stale               superseded by the owner's next submission
    delivery            ticket/inbox/digest outage: backoff doubling from 1 min, capped at 30 min
    """
    limits = bounds(config)
    if failure_class == "gh-transient":
        if attempts >= 8:
            return "needs-attention", None
        return "queued", now + min(60 * 2 ** (attempts - 1), 1800)
    if failure_class == "pre-provider":
        return ("queued", now + 300) if attempts <= limits["pre_provider_runs"] else ("needs-attention", None)
    if failure_class == "provider-transient":
        return ("deferred", now + 900) if attempts <= 1 else ("needs-attention", None)
    if failure_class == "invalid-output":
        if limits["invalid_output_repeat"] and attempts <= 1:
            return "deferred", now + 60
        return "review-invalid", None
    if failure_class == "freshness":
        return ("deferred", now + 60) if attempts <= 1 else ("needs-attention", None)
    if failure_class == "quota":
        if first_at is not None and now - first_at >= limits["quota_auth_deadline_seconds"]:
            return "review-error", None
        return "deferred", max(now + 60, retry_at or now + 3600)
    if failure_class == "auth":
        return "deferred", now + 1800
    if failure_class == "contention":
        return "deferred", now + 120
    if failure_class in ("advisory", "inconsistent"):
        return "review-error", None
    if failure_class == "unknown-outcome":
        return UNKNOWN_OUTCOME, None   # D26 / NEG-51: never a failure without a readback
    if failure_class == "environment":
        return "needs-attention", None
    if failure_class == "block":
        return "block-delivered", None   # v6e M4: a BLOCK verdict; `blocked` is a guard or policy refusal
    if failure_class == "stale":
        return "stale-head", None
    if failure_class == "delivery":
        return "pending", now + min(60 * 2 ** max(attempts - 1, 0), limits["delivery_backoff_cap_seconds"])
    raise ValueError("unknown failure class: " + str(failure_class))


TRANSIENT_CODES = {"PROVIDER_UNAVAILABLE", "PROVIDER_TIMEOUT", "BUDGET_EXHAUSTED", "REVIEW_NOT_STARTED",
                   "SNAPSHOT_TIMEOUT", "SNAPSHOT_SOURCE_CHANGED", "SNAPSHOT_GIT_FAILED"}
UNKNOWN_CODES = {"REVIEW_LAUNCH_UNCONFIRMED", "PROVIDER_IO_UNKNOWN", "ISOLATION_FAILED"}
CONTENTION = re.compile(r"\b(?:pool|reservation|reserved|cooldown|held by)\b", re.I)


HEAD_REVIEW_LIMIT = 3     # v6e: packet revisions per (lineage, head) that may reach reviewing
BUDGET_CLASSES = {"provider-transient": "transient", "invalid-output": "invalid", "freshness": "freshness"}
HEAD_BUDGET_DEFAULT = {"reviewed": [], "transient": 0, "invalid": 0, "freshness": 0, "first_deferred_at": None}
D24_LABEL = "coordinator bookkeeping (ahc)"
TICKET_LINE = re.compile(r"^\s+ticket (.+): ([A-Z]+)\s*$", re.M)


def stale_tickets(stderr, rc):
    """The tickets of a peer_review refusal caused ONLY by commit_policy ticket freshness (D24), or []. Pre-launch:
    rc 2 and "PR review not started"; every ticket line STALE or UPDATED, at least one STALE, no blocked commit and
    nothing unverifiable."""
    text = stderr or ""
    if rc != 2 or "PR review not started" not in text or "Commit policy BLOCKED" not in text:
        return []
    if " BLOCKED: " in text or "could not verify" in text:
        return []
    lines = TICKET_LINE.findall(text)
    if not lines or any(status not in ("STALE", "UPDATED") for _ticket, status in lines):
        return []
    return sorted({ticket.strip() for ticket, status in lines if status == "STALE"})


def d24_note(req, commits):
    """The D24 note: facts already in git and nothing else (no test, status or completion claim)."""
    lines = ["%s: receipt bookkeeping posted by ahc." % D24_LABEL,
             "PR: https://github.com/%s/pull/%s at head %s" % (req["repo"], req["pr"], req["head"]), "Commits:"]
    lines += ["- %s %s" % (sha, " ".join(str(subject).split())[:120]) for sha, subject in commits[:50]]
    return "\n".join(lines)


def classify_review_failure(stderr, rc=None):
    """Map peer_review's exit and REVIEW_DIAGNOSTIC code to a retry class. Only an explicit list is transient; an
    uncertain launch or supervision outcome, our own timeout (124), a missing executable (127) or a missing code is
    `unknown-outcome`, which is never retried until usage_guard reconciliation (code-inspection r1 F3)."""
    if rc in (core.TIMEOUT_RC, 127):
        return "unknown-outcome", "AHC_CHILD_%s" % rc
    codes = DIAG.findall(stderr or "")
    code = codes[-1] if codes else ""
    if not code or code in UNKNOWN_CODES:
        return "unknown-outcome", code or "NO_DIAGNOSTIC"
    if code == "PROVIDER_USAGE_LIMIT":
        return "quota", code
    if code == "PROVIDER_AUTH":
        return "auth", code
    if code in ("PROVIDER_INVALID_OUTPUT", "FALLBACK_NO_RESULT"):
        return "invalid-output", code
    if code == "REVIEW_NOT_STARTED" and CONTENTION.search(stderr or ""):
        return "contention", code
    if code in TRANSIENT_CODES:
        return "provider-transient", code
    if code.startswith("EXEC_") or code.startswith("SNAPSHOT_") or code == "PYTHON_UNSUPPORTED":
        return "environment", code   # a named local environment defect, not a retry
    return "unknown-outcome", code   # unlisted: the provider may have launched; reconcile before any retry


def _reset_time(stderr):
    match = RESET.search(stderr or "")
    if not match:
        return None
    text = match.group(1)
    if len(text) == 17:
        text = text[:-1] + ":00Z"
    try:
        return time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
    except ValueError:
        return None


# ---------------------------------------------------------------- ledger

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY, lineage TEXT NOT NULL, owner TEXT NOT NULL, ticket TEXT NOT NULL,
  state TEXT NOT NULL, next_action_at REAL, submitted REAL NOT NULL,
  lease_token INTEGER NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
  attempts TEXT NOT NULL DEFAULT '{}', request TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', updated REAL,
  entered_at REAL, esc_n INTEGER NOT NULL DEFAULT 0, esc_at REAL, disposed_at REAL, cause TEXT);
CREATE INDEX IF NOT EXISTS items_due ON items(state, next_action_at);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT NOT NULL, event TEXT NOT NULL, at REAL NOT NULL, data TEXT);
CREATE TABLE IF NOT EXISTS effects (
  key TEXT PRIMARY KEY, item TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, next_action_at REAL, payload TEXT NOT NULL, result TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS notices (
  key TEXT PRIMARY KEY, item TEXT NOT NULL, state TEXT NOT NULL, audience TEXT NOT NULL,
  requires_ack INTEGER NOT NULL, deadline REAL, acked_at REAL, escalated_at REAL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS lineage (
  lineage TEXT PRIMARY KEY, attempts TEXT NOT NULL DEFAULT '{}', block_rounds INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS circuits (provider TEXT PRIMARY KEY, opened REAL NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


# v3 (goodqa#16049 M-1): items.cause (why the item is in its state: a dependency or budget name) and the Review,
# Grant, Operation and transition tables of ahc_contracts, in the fresh path and the v2 -> v3 step alike.
# v4 (spec ahc-m1-v2g2, folded into v4 by the spec owner's ruling since no v4 ledger was ever installed): Grants
# scoped (repo, pr, H, B), Operations keyed (kind, repo, pr, B, H, revision, g) for the fast-forward integration,
# Review code rows bound to B_r, epochs, CAP1 slots, the proven-absent count, contract_meta and repo_flags. A v3
# ledger's grants, operations and reviews (either committed v3 layout) are kept intact as *_v3_legacy; an unsettled
# legacy grant or operation is reported by Contracts.legacy_unsettled() and fails eligibility until main reconciles
# it (legacy reviews authorize nothing and are not reconcile items).
SCHEMA += ahc_contracts.SCHEMA
SCHEMA_VERSION = ahc_migrate.SCHEMA_VERSION   # 5 (goodqa#16049 slice 1 (b), AC-11)
# D20 timing columns (v2): entered_at = when the item entered its current state (a same-state settle keeps it);
# esc_n = the escalation number <n> in the critical alert key ahc:<item>:<n>, bumped once per escalation in the same
# transaction as its notice, never by a retry; esc_at = the last D20 escalation; disposed_at = a recorded disposition.
V2_COLUMNS = (("entered_at", "REAL"), ("esc_n", "INTEGER NOT NULL DEFAULT 0"), ("esc_at", "REAL"),
              ("disposed_at", "REAL"))


def _migrate_v2(db):
    have = {row[1] for row in db.execute("PRAGMA table_info(items)")}
    for name, decl in V2_COLUMNS:
        if name not in have:  # the v0 path ran SCHEMA (which already has them) first
            db.execute("ALTER TABLE items ADD COLUMN %s %s" % (name, decl))
    for row in db.execute("SELECT id, data, updated, submitted, entered_at, esc_n FROM items").fetchall():
        try:
            routed = int(json.loads(row[1] or "{}").get("routed_escalations", 0) or 0)
        except (ValueError, TypeError, AttributeError):
            routed = 0
        db.execute("UPDATE items SET entered_at=COALESCE(entered_at, ?), esc_n=MAX(esc_n, ?) WHERE id=?",
                   (row[2] if row[2] is not None else row[3], routed, row[0]))


# Forward-only migrations: MIGRATIONS[n] takes a database at version n-1 to version n; each step is a list of SQL
# statements or callables taking the connection. Version 0 is a ledger written before schema_version existed (same
# tables). All steps run inside one transaction after a verified online backup (spec v14 NEG-37, v17 F2); a failure
# restores that backup and moves the failed database files aside, never deleting them.
def _migrate_v3(db):
    if "cause" not in {row[1] for row in db.execute("PRAGMA table_info(items)")}:
        db.execute("ALTER TABLE items ADD COLUMN cause TEXT")
    for statement in _statements(ahc_contracts.SCHEMA):
        db.execute(statement)


# A table is in the v4 layout when it has its v4 marker column; any other committed layout (either v3 layout of
# grants/operations, the v3 reviews table without B_r) is renamed aside. merge_sha is gone in v4 (spec ahc-m1-v2g2),
# so its absence no longer tells v3 from v4: the markers are columns only v4 has.
V4_MARKERS = {"grants": "cap_held", "operations": "proven_absent", "reviews": "snapshot_base"}


def _migrate_v4(db):
    def cols(table):
        return {row[1] for row in db.execute("PRAGMA table_info(%s)" % table)}
    for table, marker in V4_MARKERS.items():
        present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if present and marker not in cols(table):
            if table == "grants":
                db.execute("DROP INDEX IF EXISTS grants_one_live_per_scope")
            db.execute("ALTER TABLE %s RENAME TO %s_v3_legacy" % (table, table))
    for statement in _statements(ahc_contracts.SCHEMA):
        db.execute(statement)


def _migrate_v5(db):
    """v5 (AC-11, AC-16): every ahc_contracts table whose v5 definition differs is rebuilt (renamed aside as
    {table}_v4_legacy, recreated from SCHEMA, rows copied as round 1); new tables are created from SCHEMA. The layout
    is detected on the reviews table's marker columns; the earlier v4 layout and any unknown one refuse."""
    layout = ahc_migrate.detect_layout(db)
    if layout not in ("pr258", "4d45fe40", "v5"):
        raise ahc_migrate.MigrationRefused("ledger reviews layout %s is not migratable to v5" % layout)
    ahc_migrate.rebuild_changed_tables(db, ahc_contracts.SCHEMA, layout)
    for statement in _statements(ahc_contracts.SCHEMA):
        db.execute(statement)


MIGRATIONS = {1: [], 2: [_migrate_v2], 3: [_migrate_v3], 4: [_migrate_v4], 5: [_migrate_v5]}


SCHEMA_EXIT = 3
ROOT_EXIT = SCHEMA_EXIT   # a foreign state root (core.ForeignRoot): also a no-restart exit


SchemaError = ahc_migrate.SchemaError   # the ledger's schema is unknown, newer, fenced or refused; do not start
MigrationPending = ahc_migrate.MigrationPending
MigrationRefused = ahc_migrate.MigrationRefused


_NO_DIGEST = object()   # an interrupted-restore record with no "sha256" key: written by an ahc before PR 258 v5


class RestoreAbandoned(SchemaError):
    """A restore could not copy its verified backup (gone, partial, changed or unreadable) while the live database
    had never been moved: the intent is dropped and the live database is left in place, unchanged (PR 258 v5 F1)."""


def _restore_progress(stage, copied):
    """The mid-copy crash point: called by ahc_fs.copy_to_temp around each chunk it writes into the staged copy."""
    if stage == "before":
        crash_before("runner.restore_chunk")
    else:
        crash_after("runner.restore_chunk")


SQLITE_SIDECARS = ("-wal", "-shm", "-journal")
REPORT_NAME = "report.md"
# The largest ledger ahc migrates, and so the largest backup it may have to restore. Checked before a migration
# starts (nothing changes if it is over) and again on the backup's descriptor before the restore copies anything.
# The copy streams in ahc_fs.COPY_CHUNK pieces, so memory use does not grow with this cap (MemoryMax=512M).
RESTORE_MAX_BYTES = 2 * 1024 ** 3


def _check_sidecars(path):
    for extra in SQLITE_SIDECARS:
        problem = core._entry_problem(Path(str(path) + extra), False)
        if problem:
            raise core.ForeignRoot("ledger file %s%s is %s; refusing to open" % (Path(path).name, extra, problem))


def connect_nofollow(root, path, exclusive=False, **kwargs):
    """Open a ledger database without following a link (PR 258 v1 BLOCK). Python's sqlite3 cannot take
    SQLITE_OPEN_NOFOLLOW, so: the sidecar files must not be links; the database file is opened (or created) first
    by an O_NOFOLLOW descriptor, which must be a regular file and gets its mode by fchmod; sqlite then opens the
    path, and the path's device and inode are compared with the descriptor's right after. A mismatch or a link
    closes the connection and raises ForeignRoot before any statement runs (sqlite reads nothing until the first
    statement). Remaining window, stated: a process with write access to the 0700 root (the same uid, L10) could
    swap the path to a link and back between sqlite's open and the comparison; the sidecars that sqlite creates at
    the first WAL statement are re-checked after it (_check_sidecars), not before their creation."""
    path = Path(path)
    _check_sidecars(path)
    flags = os.O_RDWR | os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    try:
        fd = fs.open_file(root, path, flags)          # checked directories, O_NOFOLLOW, regular, our uid, fchmod
    except OSError as error:
        raise core.ForeignRoot("ledger file %s cannot be opened without following a link (%s); refusing to open"
                               % (path.name, error if isinstance(error, fs.UnsafePath) else type(error).__name__))
    try:
        info = os.fstat(fd)
        os.fchmod(fd, 0o600)
        db = sqlite3.connect(str(path), **kwargs)     # sqlite takes only a path: the inode compare below binds it
        try:
            after = os.lstat(str(path))
        except OSError:
            after = None
        if after is None or stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
            db.close()
            raise core.ForeignRoot("ledger file %s was replaced while it was being opened; refusing to open"
                                   % path.name)
        return db
    finally:
        os.close(fd)


def _guarded_probe(argv, timeout):
    """The open-file probe's launcher: AC-13's lsof/fuser form under the active policy (cwd at the root)."""
    import ahc_guard  # noqa: PLC0415
    return ahc_guard.probe_run(argv, timeout)


class Ledger:
    """migrate=False (status, ack, the journal facade, the review role) refuses a ledger at an older schema instead
    of migrating it: only ahc-core, holding its lock, migrates, so a failed migration can never move the database
    aside under another process (advisor review of the unit split)."""

    # Injectable for tests only (AC-11): the open-file probe's runner, the hooks directory whose entry points the
    # preflight verifies, and the bound on waiting for a role lock or the exclusive maint lock.
    PROBE_RUN = staticmethod(lambda argv, timeout: _guarded_probe(argv, timeout))
    HOOKS_DIR = Path(__file__).resolve().parent
    LOCK_WAIT = ahc_migrate.ROLE_WAIT_SECONDS

    def __init__(self, paths, migrate=True):
        paths.ensure()
        self.migrate = migrate
        self.paths = paths
        self.path = paths.root / "ledger.sqlite3"
        self.verified = {}          # backup name -> sha256 of the bytes Ledger.backup proved (PR 258 v5)
        self._maint = None
        self.db = None
        if migrate:
            self._resume_restore()
        elif self._intent_path().exists():
            raise SchemaError("the ledger has an interrupted restore; ahc-core completes it at start, this process "
                              "does not")
        if migrate and os.path.lexists(str(self.path)):
            self._v5_gate()             # AC-11: migration holds the role locks and the exclusive maint lock
        # every connection holds the maint flock shared for as long as it is open (AC-11)
        self._maint = ahc_migrate.maint_lock(self.paths.root, shared=True)
        try:
            fresh = not os.path.lexists(str(self.path))
            self.db = connect_nofollow(self.paths.root, self.path, timeout=30, isolation_level=None)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            _check_sidecars(self.path)
            self._schema(fresh)
        except Exception:
            if self.db is not None:
                self.db.close()
            self._maint.close()
            raise

    def _version(self):
        """The schema version; a `v5-migrating-from-n` fence is reported by _schema, never read as a version."""
        try:
            version, _fenced = ahc_migrate.read_version(self.db)
        except SchemaError as error:
            raise SchemaError("%s in %s" % (error, self.path)) from None
        return version

    def _schema(self, fresh):
        version, fenced = (None, False) if fresh else ahc_migrate.read_version(self.db)
        if version is None:
            with self.tx():
                for statement in _statements(SCHEMA):
                    self.db.execute(statement)
                self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)",
                                (str(SCHEMA_VERSION),))
            return
        if fenced:
            raise MigrationPending("ledger %s is fenced (%s%d): a v5 migration was interrupted or refused; v5 "
                                   "ahc-core reruns it at start (migration pending), this process does not open it"
                                   % (self.path.name, ahc_migrate.FENCE_PREFIX, version))
        if version > SCHEMA_VERSION or version < 0:
            raise SchemaError("ledger schema_version %d is not supported by this ahc (knows %d); refusing to start"
                              % (version, SCHEMA_VERSION))
        if version == SCHEMA_VERSION:
            return
        raise SchemaError("ledger schema_version %d is older than this ahc (%d); ahc-core migrates it at start, "
                          "this process does not" % (version, SCHEMA_VERSION))

    # ------------------------------------------------------------ schema version 5 (AC-11)

    def _v5_gate(self):
        """Migration runs only in v5 ahc-core, holding (1) the core role lock, then the review role lock, then the
        exclusive maint lock, each until the reopen. 4d45fe40's roles take their role locks but not the maint lock,
        so the role locks are what prove an old-version role has stopped. A lock not taken within LOCK_WAIT refuses
        (nothing written). With the locks held, a v5 ledger is left as it is; anything older, or fenced, migrates."""
        root = self.paths.root
        held = []
        try:
            for role in ("core", "review"):
                mine = _HELD_ROLES.get((str(root), role))
                if mine is not None and not mine.closed:
                    continue
                handle = ahc_migrate.wait_role_lock(root, role, self.LOCK_WAIT)
                if handle is None:
                    raise MigrationRefused("migration-locks: the %s role lock is held by another process; stop the "
                                           "ahc units and CLI users first (nothing was written)" % role)
                held.append(handle)
            exclusive = ahc_migrate.maint_lock(root, shared=False, timeout=self.LOCK_WAIT)
            if exclusive is None:
                raise MigrationRefused("migration-locks: a ledger connection holds %s; migration waits for it and "
                                       "refuses after %.0f s (nothing was written)" % (ahc_migrate.MAINT_NAME,
                                                                                      self.LOCK_WAIT))
            held.append(exclusive)
            self.db = connect_nofollow(root, self.path, timeout=30, isolation_level=None)
            self.db.row_factory = sqlite3.Row
            try:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA synchronous=FULL")
                _check_sidecars(self.path)
                version, fenced = ahc_migrate.read_version(self.db)
                if version is None or (version == SCHEMA_VERSION and not fenced):
                    return
                if version > SCHEMA_VERSION or version < 0:
                    raise SchemaError("ledger schema_version %d is not supported by this ahc (knows %d); refusing "
                                      "to start" % (version, SCHEMA_VERSION))
                self._migrate_guarded(version)
            finally:
                if self.db is not None:
                    self.db.close()
                self.db = None
        finally:
            for handle in reversed(held):
                handle.close()

    @classmethod
    def rollback_v5(cls, paths, backup_name):
        """AC-11 code rollback, the run kit's v5 step with every unit stopped: under the same locks, restore the
        kept pre-v5 backup through the same restore, clear its fence back to the prior version n in one
        transaction, and check that the old `_version()` reads n. Returns n. Only then is the old code installed
        (e0e4ac46 for a PR 258 layout, 4d45fe40 for its own layout and for a ledger below version 4)."""
        self = cls.__new__(cls)
        self.migrate, self.paths, self.path, self.verified = True, paths, paths.root / "ledger.sqlite3", {}
        self._maint, self.db = None, None
        root = paths.root
        name = Path(backup_name).name
        if not re.fullmatch(r"ledger\.sqlite3\.pre-v5\.[0-9]+\.bak", name):
            raise SchemaError("rollback names a kept pre-v5 backup beside the ledger, not %r" % backup_name)
        copy = self.path.with_name(name)
        held = []
        try:
            for role in ("core", "review"):
                handle = ahc_migrate.wait_role_lock(root, role, cls.LOCK_WAIT)
                if handle is None:
                    raise MigrationRefused("rollback: the %s role lock is held; stop the units first" % role)
                held.append(handle)
            exclusive = ahc_migrate.maint_lock(root, shared=False, timeout=cls.LOCK_WAIT)
            if exclusive is None:
                raise MigrationRefused("rollback: a ledger connection is open; stop the CLI users first")
            held.append(exclusive)
            check = sqlite3.connect("file:%s?mode=ro" % copy, uri=True)
            try:
                if [tuple(r) for r in check.execute("PRAGMA integrity_check").fetchall()] != [("ok",)]:
                    raise SchemaError("rollback: backup %s fails integrity_check" % name)
                n, fenced = ahc_migrate.read_version(check)
            finally:
                check.close()
            if not fenced:
                raise SchemaError("rollback: backup %s is not a fenced pre-v5 backup" % name)
            self.verified[name] = fs.digest_file(root, copy, RESTORE_MAX_BYTES)
            self.db = connect_nofollow(root, self.path, timeout=30, isolation_level=None)
            self.restore(copy)
            ahc_migrate.clear_fence(self.db, n)
            got, still = ahc_migrate.read_version(self.db)
            if (got, still) != (n, False) or not self._old_version_reads(n):
                raise SchemaError("rollback: the restored ledger does not read as version %d" % n)
            return n
        finally:
            if self.db is not None:
                self.db.close()
            for handle in reversed(held):
                handle.close()

    def _old_version_reads(self, n):
        """The old `_version()` rule (4d45fe40 and e0e4ac46): no meta table and no items -> fresh; no row -> 0;
        otherwise int(v), which must be n."""
        row = self.db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        try:
            return (0 if row is None else int(row[0])) == n
        except (TypeError, ValueError):
            return False

    def _installed_extras(self):
        """(path, expected sha256) of the installed wrapper and unit files, when an install record says so. The
        expected text is derived from the v5 code (ahc_install), never read from what is installed."""
        import ahc_install  # noqa: PLC0415
        record = ahc_install.read_record(self.paths)
        if not record:
            return []
        out = []
        for path in record.get("files", []) or []:
            name = Path(path).name
            text = None
            if name in getattr(ahc_install, "UNITS", ()):
                text = ahc_install.unit_text(name)
            elif name == "ahc":
                text = ahc_install.wrapper_text()
            if text is not None and os.path.exists(path):
                out.append((path, hashlib.sha256(text.encode("utf-8")).hexdigest()))
        return out

    def _probe(self, files):
        return ahc_migrate.open_file_holders(files, self.PROBE_RUN)

    def _migrate_guarded(self, n):
        """AC-11 under AC-13: the active policy's migrating gate (lsof and fuser on the ledger files) is open only
        for this migration, which only ahc-core runs, holding its lock."""
        import ahc_guard  # noqa: PLC0415
        policy = ahc_guard.active()
        if policy is not None:
            policy.migrating = True
        try:
            self._migrate_to_v5(n)
        finally:
            if policy is not None:
                policy.migrating = False

    def _migrate_to_v5(self, n):
        """Steps 2-8 of AC-11 on the open connection, every lock held. n is the ledger's version (or the prior
        version a fence names). A refusal before the backup leaves every row and schema_version as they were."""
        # (2) read-only preflight: entry points, layout, size and a probe that must list this migrator's own pid
        ahc_migrate.verify_entry_points(self.HOOKS_DIR, self._installed_extras())
        if n == 4:
            layout = ahc_migrate.detect_layout(self.db)
            if layout not in ("pr258", "4d45fe40", "v5"):
                raise MigrationRefused("migration-layout: the reviews table is in the %s layout, which is not "
                                       "migratable (the earlier version 4 layout was never installed); nothing was "
                                       "written" % layout)
        size = sum(os.lstat(str(self.path) + extra).st_size for extra in ("", "-wal")
                   if os.path.lexists(str(self.path) + extra))
        if size > RESTORE_MAX_BYTES:
            raise SchemaError("ledger %s is %d bytes, over the %d-byte migration cap; refusing to migrate from "
                              "v%d (nothing was changed)" % (self.path.name, size, RESTORE_MAX_BYTES, n))
        try:
            probe = self._probe([self.path])
        except ahc_migrate.ProbeError as error:
            raise MigrationRefused("migration-preflight: the open-file probe failed (%s); nothing was written"
                                   % error) from None
        if os.getpid() not in probe:
            raise MigrationRefused("migration-preflight: the open-file probe did not list this migrator's own pid; "
                                   "it cannot see who holds the ledger, so nothing was written")
        # (3) the fence, so old code that opens from now on refuses before any write
        crash_before("runner.v5_fence")
        ahc_migrate.set_fence(self.db, n)
        crash_after("runner.v5_fence")
        # (4) the open-file check and (5) the TRUNCATE checkpoint; a held file or any probe error clears the fence
        try:
            files = [Path(str(self.path) + extra) for extra in ("", "-wal", "-shm")
                     if os.path.lexists(str(self.path) + extra)]
            try:
                others = self._probe(files) - {os.getpid()}
            except ahc_migrate.ProbeError as error:
                raise MigrationRefused("migration-held: the open-file check failed (%s), which counts as held"
                                       % error) from None
            if others:
                raise MigrationRefused("migration-held: the ledger is open in pid(s) %s; stop them first"
                                       % ", ".join(str(p) for p in sorted(others)))
            busy = self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
            if busy:
                raise MigrationRefused("migration-held: the TRUNCATE checkpoint did not complete")
        except MigrationRefused as refused:
            ahc_migrate.clear_fence(self.db, n)
            raise MigrationRefused("%s; the fence was cleared back to schema_version %d" % (refused, n)) from None
        # (6) the verified online backup, which carries the fence
        copy = self.backup("pre-v%d" % SCHEMA_VERSION)
        # (7) the migration in one transaction, writing schema_version 5 at its end
        try:
            with self.tx():
                for step in range(n + 1, SCHEMA_VERSION + 1):
                    if step == 1:
                        for statement in _statements(SCHEMA):
                            self.db.execute(statement)
                    for statement in MIGRATIONS[step]:
                        statement(self.db) if callable(statement) else self.db.execute(statement)
                self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)",
                                (str(SCHEMA_VERSION),))
        except Exception as error:
            # (8) the restore, then the reopen; the restored copy carries the fence, so the ledger stays fenced
            aside = self.restore(copy)
            raise SchemaError("ledger migration v%d->v%d failed (%s); restored the verified backup %s (still fenced "
                              "%s%d) and moved the failed database files aside as %s"
                              % (n, SCHEMA_VERSION, type(error).__name__, copy.name, ahc_migrate.FENCE_PREFIX, n,
                                 ", ".join(aside))) from error

    def _counts(self, db):
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE "
                                               "'sqlite_%' ORDER BY name")]
        return {table: db.execute('SELECT COUNT(*) FROM "%s"' % table.replace('"', '""')).fetchone()[0]
                for table in tables}

    def backup(self, label):
        """Copy the whole database with the SQLite online backup API (it includes committed rows still in the -wal
        file), then prove the copy: integrity_check is ok and every table has the same row count as the source.
        Returns the copy path; raises SchemaError (and the migration does not start) if the copy is not proven."""
        target = self.path.with_name("%s.%s.%d.bak" % (self.path.name, label, time.time_ns()))
        crash_before("runner.backup")
        copy = connect_nofollow(self.paths.root, target, exclusive=True)   # a new name, never a link
        try:
            self.db.backup(copy)
            check = copy.execute("PRAGMA integrity_check").fetchall()
            source, copied = self._counts(self.db), self._counts(copy)
        finally:
            copy.close()
        crash_after("runner.backup")
        if [tuple(row) for row in check] != [("ok",)] or source != copied:
            raise SchemaError("ledger backup %s failed verification (integrity %r, rows %r vs %r); not migrating"
                              % (target.name, [tuple(r) for r in check][:3], source, copied))
        # the proven bytes' digest (PR 258 v5): a restore publishes a copy only if it has exactly these bytes
        try:
            self.verified[target.name] = fs.digest_file(self.paths.root, target, RESTORE_MAX_BYTES)
        except OSError as error:
            raise SchemaError("ledger backup %s could not be read back for its digest (%s: %s); not migrating"
                              % (target.name, type(error).__name__, error)) from None
        return target

    def restore(self, copy):
        """Put the verified backup back after a failed migration: the live database and its sidecars are moved
        aside together under one suffix (never deleted), and a copy holding exactly the backup's proven bytes is
        published. Returns the moved names. The connection is reopened on the restored file. RestoreAbandoned (a
        SchemaError) when the copy failed before anything moved: the live database is left in place."""
        self.db.close()
        sha256 = self.verified.get(Path(copy).name)
        if sha256 is None:
            raise SchemaError("backup %s was not proven by this process; not restoring (the live database is left "
                              "in place)" % Path(copy).name)
        suffix = ".failed-%d" % time.time_ns()
        # A durable intent first: a crash between the move-aside and the publish leaves no live file, and the next
        # open would otherwise create an empty ledger over it (AC-18 found this). Ledger.__init__ finishes it. The
        # record carries the backup's digest, so a resume needs nothing but the files and this record.
        crash_before("runner.restore_intent")
        fs.write_file(self.paths.root, self._intent_path(),
                      json.dumps({"backup": Path(copy).name, "sha256": sha256, "suffix": suffix},
                                 sort_keys=True) + "\n")
        crash_after("runner.restore_intent")
        moved = self._finish_restore(copy, suffix, sha256)
        self.db = connect_nofollow(self.paths.root, self.path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        return moved

    def _intent_path(self):
        return Path(str(self.path) + ".restore-intent")

    def _finish_restore(self, copy, suffix, sha256):
        """Finish the restore named by (copy, suffix, sha256) from whatever state the files are in. Restore and
        resume both run it, and every step reads the files first, so a crash at any point followed by any number of
        restarts converges (PR 258 v4 F1, v5 F1). L below is "the live file exists"; the suffix is unique to this
        restore, so only this restore's own move (or a foreign file) can take a name <ledger><suffix>*.
          1. Unpublished temps of an earlier attempt are removed (names only).
          2. L, and the live file is byte-identical to the verified backup: an earlier attempt published it and
             died before dropping the intent. The intent is dropped and nothing is moved again (moving it aside
             would replace the moved-aside failed database, PR 258 v4 residual).
          3. Any move target is taken while its source is in place (_aside_pairs). With L that means the ledger was
             already moved aside and the file now at its name is neither the original nor the restored copy.
             Refuse, keeping the intent; nothing changes and nothing is copied. So past this step, L means the
             live file was never moved.
          4. Stream the backup into a temp; its bytes must hash to sha256 (ahc_fs.Mismatch otherwise). On failure:
             - L (never moved, by step 3): abandon. Drop the intent, leave the live database untouched, raise
               RestoreAbandoned. The next open uses that database, and a retried migration takes a fresh
               verified backup first.
             - not L: refuse, keeping the intent. No ledger is created, and every start refuses until the
               backup is back or an operator decides.
          5. Move the live file and every SQLite sidecar still in place aside under the suffix (every target is
             checked again before the first rename, so nothing is half-moved). Publish the fsynced, digest-checked
             copy. Drop the intent.
        Memory does not grow with the ledger: the copy and both digests stream in ahc_fs.COPY_CHUNK pieces."""
        fs.remove_temps(self.paths.root, self.path)                 # an earlier attempt's unpublished copy
        if os.path.lexists(str(self.path)) and self._is_backup_copy(self.path, sha256):
            self._drop_intent()
            return []
        self._aside_pairs(suffix)           # a taken target refuses now, before a copy that could not be published
        crash_before("runner.restore_copy")
        try:
            staged = fs.copy_to_temp(self.paths.root, copy, self.path, RESTORE_MAX_BYTES, expect_sha256=sha256,
                                     progress=_restore_progress)
        except OSError as error:
            reason = "%s: %s" % (type(error).__name__, error)
            if os.path.lexists(str(self.path)):                     # never moved (step 3 passed)
                self._abandon_restore()
                raise RestoreAbandoned("could not copy the backup %s back (%s); the live database is left in "
                                       "place, unchanged" % (Path(copy).name, reason)) from None
            raise SchemaError("could not copy the backup %s back (%s); the live database is absent; the restore "
                              "intent is kept, so every start refuses until the backup can be copied"
                              % (Path(copy).name, reason)) from None
        crash_after("runner.restore_copy")
        moved = self._move_aside(suffix)
        self._publish_restored(staged)
        self._drop_intent()
        return moved

    def _is_backup_copy(self, path, sha256):
        """Whether the regular file `path` holds exactly the verified backup's bytes."""
        try:
            return fs.digest_file(self.paths.root, path, RESTORE_MAX_BYTES) == sha256
        except OSError:
            return False

    def _aside_pairs(self, suffix):
        """(source, target) for the live database and each SQLite sidecar still in place, target being
        <name><suffix><sidecar>. SchemaError (intent kept, nothing changed) if any target name is already taken
        while its source is still in place: renaming would replace that file."""
        pairs = []
        for extra in ("",) + SQLITE_SIDECARS:
            source = Path(str(self.path) + extra)
            if not os.path.lexists(str(source)):
                continue
            target = Path(str(self.path) + suffix + extra)
            if os.path.lexists(str(target)):
                raise SchemaError("interrupted restore: %s and %s both exist; refusing to replace either (the "
                                  "restore intent is kept)" % (source.name, target.name))
            pairs.append((source, target))
        return pairs

    def _move_aside(self, suffix):
        """Rename the live database and each of its SQLite sidecars still in place to <name><suffix><sidecar>, as
        names (never followed, never deleted). A sidecar is never left beside the restored copy, where SQLite would
        apply a stale -wal or -journal to it. Every target is checked before the first rename (_aside_pairs)."""
        moved = []
        crash_before("runner.restore_move")
        for source, target in self._aside_pairs(suffix):
            fs.rename(self.paths.root, source, target)              # moves a name; never follows it
            moved.append(target.name)
        crash_after("runner.restore_move")
        return moved

    def _publish_restored(self, staged):
        """AC-11: published by link then unlink, never by a replacing rename. An old process that connected while
        the ledger path was absent created a stray file there; it is never replaced: the intent, the stray file,
        the staged copy and the moved-aside files are kept, and the refusal names the stray file for main."""
        crash_before("runner.restore_publish")
        try:
            fs.link_exclusive(self.paths.root, staged, self.path)   # the complete, fsynced, digest-checked copy
        except FileExistsError:
            raise ahc_migrate.StrayLedger(
                "incident: a stray ledger file %s appeared while the path was absent during the restore (an old "
                "process created it); it was not replaced. The restore intent, the staged copy %s and the moved-"
                "aside files are kept for main" % (self.path, Path(staged).name)) from None
        fs.unlink(self.paths.root, staged)
        crash_after("runner.restore_publish")

    def _drop_intent(self):
        crash_before("runner.restore_done")
        fs.unlink(self.paths.root, self._intent_path())
        crash_after("runner.restore_done")

    def _abandon_restore(self):
        crash_before("runner.restore_abandon")
        fs.unlink(self.paths.root, self._intent_path(), missing_ok=True)
        crash_after("runner.restore_abandon")

    def _resume_restore(self):
        """At open (ahc-core only): an intent left by a crash inside restore is finished before anything else
        touches the file. Only the RECORD is validated here: a plain backup name beside the ledger, a .failed-<n>
        suffix and a 64-hex sha256. An invalid record refuses (fail closed, nothing created). Whether the backup is
        still there is not checked here (PR 258 v5 F1: checking it first stranded an intact live ledger). The files
        decide in _finish_restore. An abandoned restore (the backup cannot be copied and the live database was
        never moved) is logged, and the open goes on with that database."""
        intent = self._intent_path()
        if not intent.exists():
            return
        try:
            record = json.loads(intent.read_text())
            name, suffix = record["backup"], record["suffix"]
            sha256 = record.get("sha256", _NO_DIGEST)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise SchemaError("unreadable interrupted-restore record %s (%s); refusing to open the ledger"
                              % (intent.name, type(error).__name__))
        plain = isinstance(name, str) and isinstance(suffix, str) and \
            name not in (".", "..") and re.fullmatch(r"[A-Za-z0-9._-]+", name) and \
            re.fullmatch(r"\.failed-[0-9]+", suffix) and \
            (sha256 is _NO_DIGEST or isinstance(sha256, str) and re.fullmatch(r"[0-9a-f]{64}", sha256))
        if not plain:
            raise SchemaError("interrupted-restore record %s does not name a backup beside the ledger, a .failed-<n> "
                              "suffix and a sha256; refusing to open" % intent.name)
        log = logging.getLogger("ahc")
        if sha256 is _NO_DIGEST:
            self._resume_undigested(name, suffix, log)
            return
        log.warning("completing an interrupted ledger restore from %s", name)
        try:
            self._finish_restore(self.path.with_name(name), suffix, sha256)
        except RestoreAbandoned as abandoned:
            log.warning("abandoned the interrupted ledger restore: %s; opening that database", abandoned)

    def _resume_undigested(self, name, suffix, log):
        """An intent with no sha256, as an ahc before PR 258 v5 wrote it (that ahc moved the live files aside
        before copying). The backup's bytes cannot be checked, so they are never published here:
          * the live ledger is in place and was never moved aside under the suffix: it is kept. The intent is
            dropped and the start goes on; a failed migration is retried with a fresh, digested backup;
          * the live file is byte-identical to the backup (that ahc published it and died before dropping the
            intent): the intent is dropped, nothing is moved again;
          * otherwise (moved and not published, or absent): refuse with the intent kept, for an operator."""
        fs.remove_temps(self.paths.root, self.path)
        backup = self.path.with_name(name)
        if os.path.lexists(str(self.path)) and not os.path.lexists(str(self.path) + suffix):
            self._abandon_restore()
            log.warning("abandoned the interrupted ledger restore: its record (from an earlier ahc) has no sha256 "
                        "for %s, and the live database was never moved; opening that database", name)
            return
        if os.path.lexists(str(self.path)):
            try:
                published = fs.digest_file(self.paths.root, backup, RESTORE_MAX_BYTES)
            except OSError:
                published = None
            if published is not None and self._is_backup_copy(self.path, published):
                self._drop_intent()
                log.warning("completed the interrupted ledger restore from %s: it had been published", name)
                return
        raise SchemaError("interrupted-restore record %s (from an earlier ahc) has no sha256, so %s cannot be "
                          "verified, and the live database was already moved aside or is absent; refusing to open "
                          "(the restore intent is kept for an operator)" % (self._intent_path().name, name))

    def close(self):
        try:
            self.db.close()
        finally:
            if self._maint is not None:
                self._maint.close()
                self._maint = None

    def tx(self):
        return _Tx(self.db)

    def item(self, iid):
        return self.db.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()

    def ensure_item(self, iid, config=None, now=None):
        """The admitted row, or None. Admission happens only in `admit` (ahc submit), inside one ledger
        transaction (spec v4 F2); a queue file never admits work."""
        return self.item(iid)

    def event(self, iid, event, at, **data):
        self.db.execute("INSERT INTO events(item, event, at, data) VALUES (?,?,?,?)",
                        (iid, event, at, json.dumps(data, sort_keys=True, default=str)))

    def head_budget(self, lineage, head):
        """The v6e retry budget of one (lineage, head): `reviewed` (item ids that reached reviewing, at most
        HEAD_REVIEW_LIMIT), one use each of transient / invalid / freshness, and `first_deferred_at` (T8). Stored in
        lineage.attempts["heads"] (a v3 migration moves it to typed columns)."""
        row = self.db.execute("SELECT attempts FROM lineage WHERE lineage=?", (lineage,)).fetchone()
        data = json.loads(row["attempts"]) if row else {}
        budget = dict(HEAD_BUDGET_DEFAULT)
        budget.update(data.get("heads", {}).get(head, {}))
        budget["reviewed"] = list(budget.get("reviewed") or [])
        return budget

    def save_head_budget(self, lineage, head, budget):
        """Call inside a transaction: the check and the update must commit together (v6e admission rule)."""
        row = self.db.execute("SELECT attempts FROM lineage WHERE lineage=?", (lineage,)).fetchone()
        data = json.loads(row["attempts"]) if row else {}
        data.setdefault("heads", {})[head] = budget
        self.db.execute("INSERT INTO lineage(lineage, attempts) VALUES (?, ?) ON CONFLICT(lineage) DO UPDATE SET "
                        "attempts=excluded.attempts", (lineage, json.dumps(data, sort_keys=True)))

    def next_token(self):
        row = self.db.execute("SELECT v FROM meta WHERE k='fence'").fetchone()
        token = int(row["v"]) + 1 if row else 1
        self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('fence', ?)", (str(token),))
        return token


def _statements(script):
    return [part.strip() for part in script.split(";") if part.strip()]


class _Tx:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, kind, value, tb):
        if kind is None:
            crash_before("runner.commit")
            self.db.execute("COMMIT")
            crash_after("runner.commit")
        else:
            self.db.execute("ROLLBACK")
        return False


class Journal:
    """Facade over the ledger for one item: `state()`, `append(event, **data)`, and `path`, a human-readable JSONL
    mirror of the item's events (audit only; state is never read from it, so a torn line cannot change state)."""

    def __init__(self, paths, iid):
        self.paths, self.iid = paths, iid
        self.path = paths.items / (iid + ".jsonl")

    def state(self):
        ledger = Ledger(self.paths, migrate=False)
        try:
            row = ledger.item(self.iid)
            return row["state"] if row else None
        finally:
            ledger.close()

    def append(self, event, **data):
        ledger = Ledger(self.paths, migrate=False)
        try:
            if ledger.ensure_item(self.iid, load_config(self.paths)) is None:
                raise KeyError("no such item: " + self.iid)
            now = time.time()
            with ledger.tx():
                if event in TERMINAL or event in NON_TERMINAL:
                    row = ledger.item(self.iid)
                    merged = dict(json.loads(row["data"]), **data)
                    ledger.db.execute("UPDATE items SET entered_at=CASE WHEN state=? THEN entered_at ELSE ? END,"
                                      " state=?, data=?, updated=? WHERE id=?",
                                      (event, now, event, json.dumps(merged, sort_keys=True), now, self.iid))
                ledger.event(self.iid, event, now, **data)
            _mirror(self.paths, self.iid, event, now, data)
        finally:
            ledger.close()


def _mirror(paths, iid, event, at, data):
    try:
        _append_private(paths.root, paths.items / (iid + ".jsonl"),
                        json.dumps({"event": event, "at": at, **data}, sort_keys=True, default=str) + "\n")
    except OSError:
        log.warning("journal mirror write failed for %s", iid)


ROLES = ("core", "review", "all")
_HELD_ROLES = {}      # (root, role) -> the open lock handle this process holds (the v5 migrator skips those)
LOCKED_OUT_EXIT = 75   # another instance holds this role's lock; the unit does not restart on it


def acquire_lock(paths, role="all"):
    """Single instance per role: an exclusive non-blocking flock on ahc-<role>.lock ("all" takes both, so a manual
    all-in-one run never overlaps a unit). Returns an object to keep open, or None when another holds a lock."""
    paths.ensure()
    if role == "all":
        held = []
        for one in ("core", "review"):
            handle = acquire_lock(paths, one)
            if handle is None:
                for other in held:
                    other.close()
                return None
            held.append(handle)
        return held
    lock_flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    handle = os.fdopen(fs.open_file(paths.root, paths.root / ("ahc-%s.lock" % role), lock_flags), "a")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    _HELD_ROLES[(str(paths.root), role)] = handle
    return handle


# ---------------------------------------------------------------- item processing

class Worker:
    def __init__(self, paths, config, deps, ledger):
        self.paths, self.config, self.deps, self.led = paths, config, deps, ledger

    def now(self):
        return float(self.deps.clock())

    # --- leases and settlement (I3)
    def lease(self, iid):
        now = self.now()
        with self.led.tx():
            token = self.led.next_token()
            self.led.db.execute("UPDATE items SET lease_token=?, lease_until=? WHERE id=?",
                                (token, now + LEASE_SECONDS, iid))
        return token

    def settle(self, iid, token, state, next_action_at=None, event=None, notice=None, **data):
        """Change the item's state under its lease. `notice` (dict: state, audience, reason or body, requires_ack)
        is inserted with its effects in the SAME transaction, so a crash can never leave a settled item without
        its notice (code-inspection r1 F1)."""
        if state in NON_TERMINAL and next_action_at is None:
            raise ValueError("non-terminal state %s needs next_action_at (I2)" % state)
        now = self.now()
        with self.led.tx():
            row = self.led.item(iid)
            merged = dict(json.loads(row["data"]), **data)
            cause = data.get("cause")   # v3: kept while the state stays; cleared when it changes without one
            cur = self.led.db.execute(
                "UPDATE items SET entered_at=CASE WHEN state=? THEN COALESCE(entered_at, ?) ELSE ? END,"
                " cause=CASE WHEN ? IS NOT NULL THEN ? WHEN state=? THEN cause ELSE NULL END, state=?,"
                " next_action_at=?, data=?, updated=? WHERE id=? AND lease_token=?",
                (state, now, now, cause, cause, state, state, next_action_at if state in NON_TERMINAL else None,
                 json.dumps(merged, sort_keys=True, default=str), now, iid, token))
            if cur.rowcount != 1:
                raise Fenced(iid)
            if row["state"] in D20_STATES and state != row["state"]:
                self._clear_criticals(iid, now)  # left the covered state (terminal, superseded, merged, closed)
            self.led.event(iid, event or state, now, **data)
            if notice is not None:
                req = json.loads(row["request"])
                body = notice.get("body")
                if body is None:
                    body = _owner_body(iid, req, merged, notice["state"], notice.get("reason", ""))
                self._insert_notice(iid, req, notice["state"], notice["audience"], body, notice["requires_ack"],
                                    now)
        _mirror(self.paths, iid, event or state, now, data)
        if STOP_AFTER == state and state != "reviewing":  # "reviewing" stops after the review returns (review())
            raise _Stop(state)

    def bump(self, iid, failure_class):
        """Count a failure on the item and its lineage (I5); return the item count for this class."""
        with self.led.tx():
            row = self.led.item(iid)
            attempts = json.loads(row["attempts"])
            attempts[failure_class] = attempts.get(failure_class, 0) + 1
            self.led.db.execute("UPDATE items SET attempts=? WHERE id=?", (json.dumps(attempts), iid))
            lin = self.led.db.execute("SELECT attempts FROM lineage WHERE lineage=?", (row["lineage"],)).fetchone()
            lattempts = json.loads(lin["attempts"]) if lin else {}   # keeps the "heads" budget map as read
            lattempts[failure_class] = lattempts.get(failure_class, 0) + 1
            self.led.db.execute("INSERT OR REPLACE INTO lineage(lineage, attempts, block_rounds) VALUES (?, ?, "
                                "COALESCE((SELECT block_rounds FROM lineage WHERE lineage=?), 0))",
                                (row["lineage"], json.dumps(lattempts), row["lineage"]))
        return attempts[failure_class]

    def fail(self, iid, token, failure_class, reason, retry_at=None, effects=(), **data):
        """Settle a failure through retry_policy. The three budgeted classes draw on the head's one retry each
        (v6e, first-come, shared by every packet revision on the head); quota, auth and contention consume none
        (T15). A deferral anchors the head's 24 h deadline at its first one (v6f T8). `effects` (key, kind, payload)
        are inserted with the budget update, before the item settles."""
        count = self.bump(iid, failure_class) if failure_class != "contention" else 0  # waiting is not an attempt
        row = self.led.item(iid)
        req = json.loads(row["request"])
        now = self.now()
        with self.led.tx():
            budget = self.led.head_budget(row["lineage"], req["head"])
            slot = BUDGET_CLASSES.get(failure_class)
            if slot is not None:
                count = 2 if budget[slot] else 1
            state, next_at = retry_policy(failure_class, count, now, retry_at, first_at=budget["first_deferred_at"],
                                          config=self.config)
            if slot is not None and count == 1 and state in ("deferred", "queued"):
                budget[slot] = 1   # the retry is granted, so it is spent
            if state == "deferred" and budget["first_deferred_at"] is None:
                budget["first_deferred_at"] = now
            self.led.save_head_budget(row["lineage"], req["head"], budget)
            if state in ("deferred", "queued"):
                for key, kind, payload in effects:
                    self._insert_effect(key, iid, kind, payload, now)
        if effects and state in ("deferred", "queued"):
            data["d24_notes"] = [key for key, _kind, _payload in effects]
        notice = _owner_notice(state, reason) if state in OWNER_NOTICE_STATES else None
        self.settle(iid, token, state, next_at, event="%s:%s" % (state, failure_class), reason=reason,
                    failure_class=failure_class, notice=notice, **data)
        return state

    # --- the pipeline
    def process(self, row):
        iid = row["id"]
        req = json.loads(row["request"])
        token = self.lease(iid)
        state = row["state"]
        if state == "routed-to-main":
            return self.recheck_pass(iid, token, req)
        refusal = self.guard_refusal(req)
        if refusal:  # T33 from queued or deferred
            return self.settle(iid, token, "blocked", event="blocked:guard", reason=refusal,
                               notice=_owner_notice("blocked", refusal))
        if state == "deferred":
            budget = self.led.head_budget(row["lineage"], req["head"])
            first = budget["first_deferred_at"]
            if first is not None and self.now() - first >= bounds(self.config)["quota_auth_deadline_seconds"]:
                reason = ("deferred for 24 h since this head's first deferral (quota, auth, contention or a retry "
                          "that never ran); no further automatic attempt")
                return self.settle(iid, token, "review-error", event="review-error:deferred-deadline", reason=reason,
                                   notice=_owner_notice("review-error", reason))   # T8
            notes = json.loads(row["data"]).get("d24_notes") or []
            if notes and self.led.db.execute(
                    "SELECT COUNT(*) AS n FROM effects WHERE key IN (%s) AND status='done'" % ",".join("?" * len(notes)),
                    notes).fetchone()["n"] < len(notes):
                # D24: the re-run waits until every freshness note is posted, so the split roles can never spend the
                # head's one freshness re-run on a STALE the note would have cleared
                return self.settle(iid, token, "deferred", self.now() + 60, event="d24-note-wait")
        if self.circuit_open():
            return self.settle(iid, token, state, self.now() + 1800, event="circuit-open-wait")
        # 1. packet integrity: the bytes reviewed must be the bytes submitted
        real_packet = os.path.realpath(req["packet"])   # r4 F1: the path checked is the path opened
        if not core._inside(real_packet, self.config.get("work_roots", [])):
            return self.refuse(iid, token, "the packet path is no longer inside a work root")
        try:
            text = core.read_regular_resolved(real_packet, core.PACKET_MAX_BYTES)
        except core.Unreadable as error:
            return self.refuse(iid, token, "the submitted packet can no longer be read safely (%s)" % error)
        if hashlib.sha256(text).hexdigest() != req["packet_sha256"]:
            return self.refuse(iid, token, "the packet changed after submit; submit again with the final packet")
        # 2. lint and the deterministic move-only fix (never an LLM, NEG-33)
        try:
            decoded = text.decode("utf-8")
        except UnicodeDecodeError:
            return self.refuse(iid, token, "the packet is not UTF-8")
        fix = ahc_packet.fix_packet(decoded, req["head"], source_path=req["packet"])
        if fix["status"] == "unfixable":
            body = "Packet lint failed; no provider was launched.\n" + "\n".join("- " + p for p in fix["problems"])
            self.settle(iid, token, "lint-failed", event="lint-failed", reason=body,
                        notice=_owner_notice("lint-failed", body))
            return "lint-failed"
        # 3. live PR facts (never trust the request)
        try:
            facts = core.resolve(req, self.deps.gh)
        except core.Stale as error:
            return self.fail(iid, token, "stale", str(error))
        except core.Refused as error:
            return self.refuse(iid, token, str(error))
        except core.Retry as error:
            return self.fail(iid, token, "gh-transient", str(error))
        # 4. daemon-owned clone, merge-base, changed paths
        try:
            clone = self.deps.clone(req["repo"], facts["head"], facts["base"])
            merge_base = self.deps.merge_base(clone, facts["head"], facts["base"])
        except Exception as error:  # noqa: BLE001 - every clone failure is a counted pre-provider defect
            return self.fail(iid, token, "pre-provider", "clone failed: " + _short(error))
        if not core.HEAD_RE.fullmatch(str(merge_base or "")):
            return self.fail(iid, token, "pre-provider", "no merge-base between head and base")
        try:
            changed = list(self.deps.changed_paths(clone, merge_base, facts["head"]))
            protected = sorted(p for p in changed if _is_protected(p))
            protected_note = ("protected-path: main merge only (" + ", ".join(protected[:8]) + ")") if protected else ""
        except Exception as error:  # noqa: BLE001 - fail closed: unknown diff counts as protected
            protected_note = "protected-path: unknown (diff failed: %s); main merge only" % _short(error)
        fixed_path = self.paths.reports / (iid + ".packet.md")
        _write_private(self.paths.root, fixed_path, fix["text"])
        return self.review(iid, token, req, facts, clone, merge_base, fixed_path, fix, protected_note)

    def review(self, iid, token, req, facts, clone, merge_base, fixed_path, fix, protected_note):
        attempt = self.led.db.execute("SELECT COUNT(*) AS n FROM effects WHERE item=? AND kind='review'",
                                      (iid,)).fetchone()["n"] + 1
        row = self.led.item(iid)
        prior = json.loads(row["data"]).get("repeat_reason")
        relaunch_ok = json.loads(row["data"]).get("relaunch_ok")
        if attempt > 1 and not (prior or relaunch_ok):
            # one attempt per item unless retry_policy deferred it with a declared repeat reason (D7)
            reason = "a review attempt already exists for this item"
            return self.settle(iid, token, "needs-attention", event="relaunch-refused", reason=reason,
                               notice=_owner_notice("needs-attention", reason))
        if attempt == 1:
            with self.led.tx():
                budget = self.led.head_budget(row["lineage"], req["head"])
                if iid not in budget["reviewed"]:
                    if len(budget["reviewed"]) >= HEAD_REVIEW_LIMIT:
                        refused = True
                    else:
                        refused = False
                        budget["reviewed"].append(iid)
                        self.led.save_head_budget(row["lineage"], req["head"], budget)
                else:
                    refused = False
            if refused:  # admission refuses a 4th revision (N-T4); this guards revisions admitted before any ran
                reason = "review budget exhausted for this head: push a new head or ask main"
                return self.settle(iid, token, "needs-attention", event="needs-attention:head-budget", reason=reason,
                                   notice=_owner_notice("needs-attention", reason))
        # PR 258 v3: the review child (peer_review) writes its report itself, so ahc cannot hand it an open file.
        # peer_review refuses an existing report path, and it writes with an O_EXCL temp file plus link through
        # its own directory descriptor. ahc therefore creates a private directory for this one attempt,
        # exclusively, at 0700, and records the directory's (dev, ino). After the child exits, ahc reads the report
        # only through a descriptor for that same directory, checked by inode (Worker._read_report). A name planted
        # in reports/ cannot become the report.
        report_dir = self.paths.reports / ("%s-a%d" % (iid, attempt))
        report = report_dir / REPORT_NAME
        try:
            report_dir_id = list(fs.make_fresh_dir(self.paths.root, report_dir, reuse_empty=True))
        except (FileExistsError, fs.UnsafePath) as error:
            reason = "report path already exists or is not private; refusing to overwrite a receipt (%s)" % (
                type(error).__name__)
            return self.settle(iid, token, "needs-attention", event="report-path-taken", reason=reason,
                               notice=_owner_notice("needs-attention", reason))
        argv = [sys.executable, str(self.config.get("peer_review", Path.home() / ".claude/hooks/peer_review.py")),
                "pr", "--repo", clone, "--packet", str(fixed_path), "--output", str(report),
                "--expected-head", facts["head"], "--snapshot-base", merge_base, "--base", merge_base,
                "--timeout", str(REVIEW_TIMEOUT), "--owner", "ahc",
                # M-1 (goodqa#16049, superseding P0 AC-5 "unbound"): bound to the exact PR so the FINAL carries the
                # typed repo/pr binding pr_pass_evidence needs, and unstamped so it can never take or burn main's
                # review-auth stamp. No --author-harness: peer_review derives it from the commit trailers.
                "--github-repo", req["repo"], "--pr", str(req["pr"]), "--no-main-stamp"]
        if attempt > 1 and prior:
            argv += ["--repeat-reason", prior]
        refusal = unstamped_argv_problem(argv)
        if refusal:  # NEG-7: refused before launch, never sent
            return self.settle(iid, token, "needs-attention", event="review-argv-refused", reason=refusal,
                               notice=_owner_notice("needs-attention", refusal))
        key = "review:%s:%d" % (iid, attempt)
        now = self.now()
        with self.led.tx():  # I4: intent before dispatch
            self.led.db.execute("INSERT INTO effects(key, item, kind, status, attempts, next_action_at, payload,"
                                " updated) VALUES (?,?,?,?,?,?,?,?)",
                                (key, iid, "review", "intent", 1, None, json.dumps({"argv": argv}), now))
        self.settle(iid, token, "reviewing", now + REVIEW_WALL, report=str(report), report_dir_id=report_dir_id,
                    packet=str(fixed_path),
                    review_key=key, clone=clone, merge_base=merge_base, base_note=facts.get("base_repaired_from", ""),
                    fix_actions=fix["actions"], protected=protected_note, attempt=attempt,
                    repeat_reason=None, relaunch_ok=None)  # a declared repeat is spent by this launch
        result = self.deps.review(argv, REVIEW_WALL)
        rc, stderr = (result if isinstance(result, tuple) else (result, ""))
        with self.led.tx():  # readback recorded before the verdict is acted on
            self.led.db.execute("UPDATE effects SET status='done', result=?, updated=? WHERE key=?",
                                (json.dumps({"rc": rc, "stderr": redact.redact(str(stderr))[-2000:]}),
                                 self.now(), key))
        if STOP_AFTER == "reviewing":
            raise _Stop("reviewing")
        return self.conclude(iid, token, req, key)

    def guard_refusal(self, req):
        """Why a guard or policy refuses further daemon work on this request now, or None. P0 guard: the repo was
        removed from the coordinator allowlist after admission."""
        if str(req.get("repo", "")).lower() not in {str(r).lower() for r in self.config.get("repos", [])}:
            return "the repo is no longer on the coordinator allowlist"
        return None

    def _read_report(self, data):
        """(bytes or None, problem or None). The report is read only through a descriptor for the attempt
        directory ahc created for it, and that directory must have the (dev, ino) recorded at creation. The report
        must be the directory's only entry (peer_review unlinks its own temp file before exiting) and a regular
        file owned by this uid with one link, within REPORT_MAX_BYTES. None bytes with no problem means no report
        was written. Any problem is INVALID, and conclude() quarantines the attempt directory."""
        want = data.get("report_dir_id")
        report = Path(str(data.get("report")))
        if not want:
            return None, "no report directory identity was recorded for this attempt"
        try:
            with fs.directory(self.paths.root, report.parent) as dfd:
                info = os.fstat(dfd)
                if [info.st_dev, info.st_ino] != list(want):
                    return None, "the report directory was replaced after the review was launched"
                names = sorted(os.listdir(dfd))
                if not names:
                    return None, None
                if names != [report.name]:
                    return None, "the report directory holds entries other than %s (%d entries)" % (
                        report.name, len(names))
                entry = os.stat(report.name, dir_fd=dfd, follow_symlinks=False)
                if not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.geteuid():
                    return None, "the report is not a regular file owned by ahc"
                if entry.st_nlink != 1:
                    return None, "the report has %d hard links; only one is allowed" % entry.st_nlink
                if entry.st_size > core.REPORT_MAX_BYTES:
                    return None, "the report is larger than %d bytes" % core.REPORT_MAX_BYTES
                try:
                    return core.read_regular(report.name, core.REPORT_MAX_BYTES, dir_fd=dfd), None
                except core.Unreadable as error:
                    return None, None if error.kind == "absent" else "report unreadable: %s" % error
        except FileNotFoundError:
            return None, None
        except fs.UnsafePath as error:
            return None, "the report directory is not private: %s" % error

    def conclude(self, iid, token, req, key):
        row = self.led.item(iid)
        data = json.loads(row["data"])
        refusal = self.guard_refusal(req)
        if refusal:
            # T33 while reviewing (rescue ruling: hold the child kill): the child has already settled and its
            # result stays recorded on the effect row; the item becomes blocked, routed to the decision-maker
            reason = "guard refusal after the review finished: %s" % refusal
            return self.settle(iid, token, "blocked", event="blocked:guard", reason=reason,
                               notice=_owner_notice("blocked", reason))
        effect = self.led.db.execute("SELECT * FROM effects WHERE key=?", (key,)).fetchone()
        result = json.loads(effect["result"])
        stale = stale_tickets(result.get("stderr", ""), result["rc"])
        if stale:
            return self.freshness(iid, token, req, data, stale)
        report_bytes, problem = self._read_report(data)
        if problem:
            verdict = {"verdict": "INVALID", "reason": problem}
            moved = _quarantine_report_dir(self.paths, Path(str(data.get("report"))).parent, problem)
            if moved:
                verdict["reason"] += "; attempt directory quarantined as rejected/%s" % moved
        else:
            verdict = core.verify_receipt(result["rc"], data["report"], req["head"], data["packet"],
                                          report_bytes=report_bytes)
        name = verdict["verdict"]
        if name == "PASS" or name == "PASS-WITH-TICKETS":
            reason = "pass-gate1" + ("; " + data["protected"] if data.get("protected") else "")
            self.settle(iid, token, "routed-to-main", self.now() + PASS_RECHECK, event="pass", verdict=name,
                        routed_at=self.now(), routed_reason=reason,
                        notice={"state": "pass", "audience": "main", "body": _pass_body(iid, req, data, name),
                                "requires_ack": False})
            return "routed-to-main"
        if name == "BLOCK":
            with self.led.tx():
                self.led.db.execute("UPDATE lineage SET block_rounds=block_rounds+1 WHERE lineage=?",
                                    (row["lineage"],))
            self.settle(iid, token, "block-delivered", event="block-delivered", verdict="BLOCK",
                        notice=_owner_notice("block-delivered", _report_body(data["report"], report_bytes)))
            return "block-delivered"
        if name == "ADVISORY":
            return self.fail(iid, token, "advisory", "peer_review returned an advisory opinion, not a signoff")
        if name == "INVALID":
            return self.fail(iid, token, "invalid-output", "receipt failed verification: " + verdict["reason"],
                             repeat_reason="RECEIPT_INVALID: " + verdict["reason"])
        if result["rc"] in (core.EXIT_PASS, core.EXIT_BLOCK):
            return self.fail(iid, token, "inconsistent", "receipt contradicts its exit status: " + verdict["reason"])
        failure_class, code = classify_review_failure(result.get("stderr", ""), result["rc"])
        if failure_class == "auth":
            with self.led.tx():
                self.led.db.execute("INSERT OR REPLACE INTO circuits(provider, opened, reason) VALUES (?,?,?)",
                                    ("review", self.now(), code))
        if failure_class == "unknown-outcome":
            reason = ("review outcome unknown (%s, exit %s). Reconcile the run with usage_guard (python3 "
                      "~/.claude/hooks/usage_guard.py inspect/reconcile) before any retry; ahc will not relaunch it."
                      % (code, result["rc"]))
            return self.fail(iid, token, failure_class, reason)
        if failure_class == "contention":
            return self.fail(iid, token, failure_class, "reviewer pool busy (%s); waiting" % code, relaunch_ok=True)
        repeat = "%s: ahc deferred retry after %s" % (code, verdict["reason"])
        state = self.fail(iid, token, failure_class, "review error (%s): %s" % (code, verdict["reason"]),
                          retry_at=_reset_time(result.get("stderr", "")), repeat_reason=repeat)
        return state

    def freshness(self, iid, token, req, data, tickets):
        """D24 (minimal): a receipt refused only for ticket-freshness STALE gets one factual note per (ticket, head)
        on the STALE tickets, then the head's one re-run (T13); a second STALE goes to needs-attention (T16). The
        refusal is pre-launch (peer_review.py commit_policy_gate), so it spends no provider budget."""
        try:
            commits = list(self.deps.commits(data.get("clone"), data.get("merge_base"), req["head"]))
        except Exception as error:  # noqa: BLE001 - no commit list, no note: the owner gets it (D20)
            reason = "ticket freshness STALE and the PR's commits could not be read: %s" % _short(error)
            return self.settle(iid, token, "needs-attention", event="needs-attention:freshness", reason=reason,
                               notice=_owner_notice("needs-attention", reason))
        effects = []
        for ticket in tickets:
            digest = hashlib.sha256(("%s|%s" % (ticket, req["head"])).encode()).hexdigest()[:16]
            effects.append(("ticket:d24:" + digest, "ticket", {
                "ticket": ticket, "key": "ahc-d24-" + digest, "body": d24_note(req, commits)}))
        reason = "ticket freshness STALE (%s); %d bookkeeping note(s), then one re-run" % (", ".join(tickets),
                                                                                          len(effects))
        return self.fail(iid, token, "freshness", reason, effects=effects,
                         repeat_reason="D24_FRESHNESS: bookkeeping notes posted to %s" % ", ".join(tickets))

    def refuse(self, iid, token, reason):
        self.settle(iid, token, "refused", event="refused", reason=reason, notice=_owner_notice("refused", reason))
        return "refused"

    def recover(self, row):
        """An item left in `reviewing` by a previous process (I4): read back, never relaunch blindly."""
        iid = row["id"]
        req = json.loads(row["request"])
        data = json.loads(row["data"])
        token = self.lease(iid)
        key = data.get("review_key")
        effect = self.led.db.execute("SELECT * FROM effects WHERE key=?", (key,)).fetchone() if key else None
        if effect is not None and effect["status"] == "done":
            return self.conclude(iid, token, req, key)
        reason = ("the previous daemon stopped during the review; its outcome is unknown. Reconcile the run with "
                  "usage_guard (python3 ~/.claude/hooks/usage_guard.py inspect/reconcile) before any retry.")
        self.settle(iid, token, UNKNOWN_OUTCOME, event="review-outcome-unknown", reason=reason,
                    notice=_owner_notice(UNKNOWN_OUTCOME, reason))
        return UNKNOWN_OUTCOME

    def recheck_pass(self, iid, token, req):
        row = self.led.item(iid)
        data = json.loads(row["data"])
        rc, out, _err = self.deps.gh(["gh", "pr", "view", str(req["pr"]), "-R", req["repo"], "--json",
                                      "state,headRefOid,mergeCommit"], core.GH_TIMEOUT)
        try:
            pr = json.loads(out) if rc == 0 else None
        except ValueError:
            pr = None
        now = self.now()
        if not isinstance(pr, dict):
            return self.settle(iid, token, "routed-to-main", now + PASS_RECHECK, event="recheck-unreadable")
        if pr.get("state") == "MERGED":
            return self.settle(iid, token, "merged", event="merged-by-main",
                               merge_commit=(pr.get("mergeCommit") or {}).get("oid"))
        if pr.get("state") == "CLOSED":
            return self.settle(iid, token, "closed", event="closed")
        if pr.get("headRefOid") != req["head"]:
            return self.settle(iid, token, "stale-head", event="head-moved-after-pass")
        # D20 escalation is not here: it runs in escalate_overdue() from the ledger alone, so a GitHub outage (the
        # recheck-unreadable return above) can never suppress it
        return self.settle(iid, token, "routed-to-main", now + PASS_RECHECK, event="recheck")


    def circuit_open(self):
        return self.led.db.execute("SELECT 1 FROM circuits WHERE provider='review'").fetchone() is not None

    # --- notices and effects
    def _insert_notice(self, iid, req, state, audience, body, requires_ack, now, esc_n=None):
        """Insert one notice and its effects; the caller holds the transaction. One notice per (item, state)
        (NEG-34); returns False when it already existed. Effects: ticket comment always; owner inbox for owner
        notices; for a user-audience escalation (esc_n given) a CRITICAL alert keyed ahc:<item>:<n>, the only
        severity ops-watch mails through the deadman route (D19); a HIGH alert (dashboard and ticket, no mail) for
        terminal-unsuccessful states; the digest as a courtesy copy for main. Audience "record" is ticket and
        digest only (a disposition)."""
        nkey = "%s:%s" % (iid, state)
        body = redact.redact(body)
        cur = self.led.db.execute(
            "INSERT OR IGNORE INTO notices(key, item, state, audience, requires_ack, deadline, created)"
            " VALUES (?,?,?,?,?,?,?)",
            (nkey, iid, state, audience, int(requires_ack),
             now + bounds(self.config)["block_ack_seconds"] if requires_ack else None, now))
        if cur.rowcount != 1:
            return False
        mail = audience == "user" and esc_n is not None and self.email_ready()
        if audience == "user" and esc_n is not None and not mail:
            body += ("\nEmail route unavailable (%s): this escalation is NOT handed to the mail command; it is on the "
                     "dashboard and this ticket only." % (self._meta("email_route_reason") or "not checked"))
        effects = [("ticket", {"ticket": req["ticket"], "body": body, "key": "ahc-" + nkey.replace(":", "-")})]
        if audience == "owner":
            # lexical only: filesystem state (a planted symlink) must never make the state-change transaction raise
            name = "%s-%s.md" % (iid, state)
            effects.append(("inbox", {"path": str(core.inbox_path(self.paths, req["owner"], name, resolve=False)),
                                      "body": body}))
        if audience == "user" and esc_n is not None:
            effects.append(("alert", _alert_payload(iid, req, state, body, esc_n=esc_n)))
        elif audience != "record" and (audience == "user" or state in ALERT_STATES):
            effects.append(("alert", _alert_payload(iid, req, state, body)))
        effects.append(("digest", {"line": _digest_line(iid, req, state, body), "key": nkey}))
        if mail:
            effects.append(("mail", {"alert_key": "ahc:%s:%d" % (iid, esc_n), "n": esc_n}))
        for kind, payload in effects:
            self.led.db.execute(
                "INSERT OR IGNORE INTO effects(key, item, kind, status, attempts, next_action_at, payload, updated)"
                " VALUES (?,?,?,?,?,?,?,?)",
                ("%s:%s" % (kind, nkey), iid, kind, "pending", 0, now, json.dumps(payload), now))
        return True

    def escalate_item(self, iid, req, notice_state, body, now, d20=False):
        """The one escalation path past main (no-ack and D20): the caller holds the transaction. The item's
        escalation number <n> is bumped in the same transaction as the notice and its critical alert
        ahc:<item>:<n>, and only when the notice is new, so a retried delivery never counts (D19)."""
        row = self.led.item(iid)
        n = int(row["esc_n"] or 0) + 1
        if not self._insert_notice(iid, req, notice_state, "user", body, False, now, esc_n=n):
            return False
        self.led.db.execute("UPDATE items SET esc_n=?, esc_at=CASE WHEN ? THEN ? ELSE esc_at END WHERE id=?",
                            (n, int(bool(d20)), now, iid))
        self.led.event(iid, "escalated", now, n=n, notice=notice_state, d20=bool(d20))
        return True

    def _clear_criticals(self, iid, now):
        """Queue a clear for every critical alert this item raised (ahc:<item>:<n>) that has no clear yet, and cancel
        any such raise not yet sent, so the dashboard does not keep them standing. The caller holds the
        transaction. Called when the item leaves a D20 state, on disposition, on a D20 stop, and on an owner ack
        that leaves no live D20 obligation."""
        self.led.db.execute("UPDATE effects SET status='cancelled', next_action_at=NULL, updated=? WHERE item=? AND "
                            "kind='mail' AND status='pending'", (now, iid))
        for effect in self.led.db.execute("SELECT key, status, payload FROM effects WHERE item=? AND kind='alert'",
                                          (iid,)).fetchall():
            payload = json.loads(effect["payload"])
            if payload.get("severity") != "critical" and not payload.get("alert_key", "").startswith(UNDELIVERED_PREFIX):
                continue
            if effect["status"] == "pending":
                self.led.db.execute("UPDATE effects SET status='cancelled', next_action_at=NULL, updated=? "
                                    "WHERE key=?", (now, effect["key"]))
            self.led.db.execute(
                "INSERT OR IGNORE INTO effects(key, item, kind, status, attempts, next_action_at, payload, updated)"
                " VALUES (?,?,?,?,?,?,?,?)",
                ("clear:" + payload["alert_key"], iid, "clear", "pending", 0, now,
                 json.dumps({"alert_key": payload["alert_key"], "key": "ahc-clear-" + payload["alert_key"]}), now))

    def prune_packets(self):
        """v6c: a packet staged by `ahc submit --packet -` is kept while any item that names it is non-terminal and
        for PACKET_RETENTION_SECONDS after the last such item turned terminal; then the core removes it (the receipt
        and the ledger keep its SHA-256). A staged file no item names (its submit was refused) goes after the same
        period from its own mtime. Only regular `<sha>.md` files directly in the staging root are touched; a
        symlink or anything else there is left alone. Returns the removed names."""
        root = self.paths.packets
        try:
            entries = sorted(root.iterdir())
        except OSError:
            return []
        now = self.now()
        real_root = os.path.realpath(str(root))   # submit records the packet's resolved path
        keep_until = {}
        for row in self.led.db.execute("SELECT state, entered_at, updated, request FROM items"):
            try:
                path = str(json.loads(row["request"]).get("packet") or "")
            except ValueError:
                continue
            if not path or os.path.dirname(os.path.realpath(path)) != real_root:
                continue
            name = os.path.basename(path)
            if row["state"] in NON_TERMINAL:
                keep_until[name] = float("inf")
            else:
                ended = float(row["entered_at"] or row["updated"] or now)
                keep_until[name] = max(keep_until.get(name, 0.0), ended + PACKET_RETENTION_SECONDS)
        removed = []
        for entry in entries:
            if not STAGED_NAME.match(entry.name):
                continue
            try:
                info = os.lstat(str(entry))
                if not stat.S_ISREG(info.st_mode):
                    continue
                until = keep_until.get(entry.name, info.st_mtime + PACKET_RETENTION_SECONDS)
                if now < until:
                    continue
                crash_before("runner.prune")
                fs.unlink(self.paths.root, entry)
                crash_after("runner.prune")
                removed.append(entry.name)
            except OSError:
                continue  # retried next pass
        return removed

    def escalate_overdue(self):
        """D20: every item in a covered state escalates past main 4 h after entering it, then every 24 h, until a
        disposition, a newer submission for the same PR, or the PR merging or closing. Reads only the ledger, plus
        one PR read at escalation time; an unreadable PR is never read as merged or closed (I9)."""
        now = self.now()
        marks = ",".join("?" * len(D20_STATES))
        rows = self.led.db.execute("SELECT * FROM items WHERE state IN (%s) AND disposed_at IS NULL ORDER BY id"
                                   % marks, sorted(D20_STATES)).fetchall()
        for row in rows:
            start = row["entered_at"] if row["entered_at"] is not None else row["updated"]
            last = row["esc_at"]
            due = (now >= last + D20_REPEAT) if (last is not None and last >= start) else (now >= start + D20_FIRST)
            if not due:
                continue
            req = json.loads(row["request"])
            stop = self._d20_stop(row, req)
            with self.led.tx():
                current = self.led.item(row["id"])
                if current["state"] != row["state"] or current["disposed_at"] is not None:
                    continue
                if stop:
                    self.led.db.execute("UPDATE items SET disposed_at=? WHERE id=?", (now, row["id"]))
                    self.led.event(row["id"], "d20-stopped", now, reason=stop)
                    self._clear_criticals(row["id"], now)
                    continue
                n = int(current["esc_n"] or 0) + 1
                data = json.loads(current["data"])
                hours = int((now - start) // 3600)
                body = ("D20 escalation %d: %s#%s at %s has waited %d h in `%s` for %s.\nReason: %s\nReceipt: %s\n"
                        "Main runs: %s\nTo stop this escalation, act on the PR, or record a disposition: python3 "
                        "~/.claude/hooks/ahc_runner.py ack %s --owner %s --disposition \"<reason>\""
                        % (n, req["repo"], req["pr"], req["head"], hours, row["state"],
                           STATE_TABLE[row["state"]]["waits_on"], data.get("routed_reason") or data.get("reason")
                           or "-", data.get("report") or "-", merge_command(req), row["id"],
                           " or ".join(STATE_TABLE[row["state"]].get("dispose", ("main",)))))
                self.escalate_item(row["id"], req, "d20-%s-%d" % (row["state"], n), body, now, d20=True)

    def newer_head(self, row):
        """The id of the newest later submission for the same PR at a DIFFERENT head, or None. Only a new head is the
        owner's repair (v6e M1): a packet-only resubmit on the same head never stops an obligation."""
        head = json.loads(row["request"]).get("head")
        for later in self.led.db.execute("SELECT id, request FROM items WHERE lineage=? AND submitted > ? AND id != ?"
                                         " ORDER BY submitted DESC, id", (row["lineage"], row["submitted"],
                                                                          row["id"])):
            later_req = json.loads(later["request"])
            if later_req.get("head") != head and not later_req.get("discovered"):   # discovery is not a submission
                return later["id"]
        return None

    def supersede_by_head(self):
        """v6e T25: a delivered or acknowledged BLOCK closes as `superseded` (reason superseded-by-head), linked to
        the new item, once a submission for the same PR at a new head is admitted. Core-owned (review never leases
        these states). The full T25 (gh head readback, every non-terminal state) lands with the v6e table."""
        closed = []
        for row in self.led.db.execute("SELECT * FROM items WHERE state IN ('block-delivered', 'acknowledged') "
                                       "ORDER BY id").fetchall():
            newer = self.newer_head(row)
            if newer is None:
                continue
            token = self.lease(row["id"])
            self.settle(row["id"], token, "superseded", event="superseded-by-head", by=newer,
                        reason="superseded-by-head")
            closed.append((row["id"], newer))
        closed += self.head_readback()
        # an `unsubmitted` head is answered by a submission at that head (T1b, reason resubmitted)
        for row in self.led.db.execute("SELECT * FROM items WHERE state='unsubmitted' ORDER BY id").fetchall():
            head = json.loads(row["request"]).get("head")
            for later in self.led.db.execute("SELECT id, request FROM items WHERE lineage=? AND id != ? "
                                             "ORDER BY submitted, id", (row["lineage"], row["id"])).fetchall():
                if json.loads(later["request"]).get("head") == head and not json.loads(later["request"]).get(
                        "discovered"):
                    token = self.lease(row["id"])
                    self.settle(row["id"], token, "superseded", event="superseded", by=later["id"],
                                reason="resubmitted")
                    closed.append((row["id"], later["id"]))
                    break
        return closed

    HEAD_READBACK_SECONDS = 600

    def head_readback(self):
        """v6e T25 + T2 for a delivered or acknowledged BLOCK: read the PR's live head (at most every 10 min per
        item). If it moved and nothing was submitted for the new head, the BLOCK closes as superseded
        (superseded-by-head) linked to a new `unsubmitted` item for the new head, which carries its own D20 clock,
        so the obligation never disappears. An unreadable PR changes nothing (I9)."""
        now, out = self.now(), []
        for row in self.led.db.execute("SELECT * FROM items WHERE state IN ('block-delivered', 'acknowledged') "
                                       "ORDER BY id").fetchall():
            data = json.loads(row["data"])
            if now - float(data.get("head_checked_at") or 0) < self.HEAD_READBACK_SECONDS:
                continue
            req = json.loads(row["request"])
            try:
                rc, text, _err = self.deps.gh(["gh", "pr", "view", str(req["pr"]), "-R", req["repo"], "--json",
                                               "number,state,headRefOid"], core.GH_TIMEOUT)
                pr = json.loads(text) if rc == 0 else None
            except (ValueError, OSError, subprocess.SubprocessError):
                pr = None
            with self.led.tx():
                self.led.db.execute("UPDATE items SET data=? WHERE id=? AND state=?",
                                    (json.dumps(dict(data, head_checked_at=now), sort_keys=True), row["id"],
                                     row["state"]))
            head = pr.get("headRefOid") if isinstance(pr, dict) and pr.get("number") == req["pr"] else None
            if not core.HEAD_RE.fullmatch(str(head or "")) or head == req["head"] or pr.get("state") != "OPEN":
                continue
            new = dict(req, head=head, packet="", packet_sha256="", discovered=True, submitted=now)
            new["id"] = core.item_id(new, "")
            with self.led.tx():
                self.led.db.execute(
                    "INSERT OR IGNORE INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, "
                    "request, updated, entered_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (new["id"], row["lineage"], req["owner"], req["ticket"], "unsubmitted", None, now,
                     json.dumps(new, sort_keys=True), now, now))
                self.led.event(new["id"], "unsubmitted", now, discovered_from=row["id"])
                self._insert_notice(new["id"], new, "unsubmitted", "owner",
                                    _owner_body(new["id"], new, {}, "unsubmitted",
                                                "PR head moved to %s after a BLOCK; nothing was submitted for it"
                                                % head), True, now)
            token = self.lease(row["id"])
            self.settle(row["id"], token, "superseded", event="superseded-by-head", by=new["id"],
                        reason="superseded-by-head")
            out.append((row["id"], new["id"]))
        return out

    def _d20_stop(self, row, req):
        """Why D20 (and an unacked notice's escalation) stops for this item without a disposition, or None: a newer submission for the same PR, or the
        PR read as MERGED or CLOSED. A failed or unreadable read is None (keep escalating)."""
        newer = self.newer_head(row)
        if newer is not None:
            return "superseded by %s" % newer
        try:
            rc, out, _err = self.deps.gh(["gh", "pr", "view", str(req["pr"]), "-R", req["repo"], "--json", "state"],
                                         core.GH_TIMEOUT)
            pr = json.loads(out) if rc == 0 else None
        except (ValueError, OSError, subprocess.SubprocessError):
            pr = None
        if isinstance(pr, dict) and pr.get("state") in ("MERGED", "CLOSED"):
            return "PR %s" % pr["state"].lower()
        return None

    def dispatch_effects(self):
        now = self.now()
        rows = self.led.db.execute(
            "SELECT * FROM effects WHERE kind != 'review' AND status IN ('pending', 'intent', 'outcome-unknown') AND "
            "next_action_at <= ? ORDER BY next_action_at, key", (now,)).fetchall()
        for row in rows:
            payload = json.loads(row["payload"])
            if row["kind"] == "mail":
                self.check_mail(row, payload, now)
                continue
            if row["status"] == "intent":
                # v6f: a dispatcher stopped between intent and result. Only this effect row becomes
                # outcome-unknown; its item keeps its state. It is read back before any redispatch (a ticket,
                # alert or clear is re-sent under the same idempotency key, which ah applies once).
                with self.led.tx():
                    self.led.db.execute("UPDATE effects SET status='outcome-unknown', updated=? WHERE key=?",
                                        (now, row["key"]))
                    self.led.event(row["item"], "effect-outcome-unknown", now, effect=row["key"], kind=row["kind"])
            if row["kind"] == "alert" and payload.get("severity") == "critical":
                self._note_raise(row["key"], now)
            if row["status"] in ("intent", "outcome-unknown") and self.readback(row["kind"], payload):
                self._effect_done(row["key"], "readback")
                continue
            with self.led.tx():
                self.led.db.execute("UPDATE effects SET status='intent', attempts=attempts+1, updated=? WHERE key=?",
                                    (now, row["key"]))
            ok, detail = self.send(row["kind"], payload)
            if ok:
                self._effect_done(row["key"], detail)
            else:
                _state, next_at = retry_policy("delivery", row["attempts"] + 1, now, config=self.config)
                with self.led.tx():
                    self.led.db.execute("UPDATE effects SET status='pending', next_action_at=?, result=?, updated=?"
                                        " WHERE key=?", (next_at, detail, now, row["key"]))

    def _note_raise(self, alert_key_row, now):
        """Record, before the ah call, the first time this critical alert was raised: a receipt counts only at or
        after it (D19)."""
        mail_key = "mail:" + alert_key_row.split(":", 1)[1]
        with self.led.tx():
            row = self.led.db.execute("SELECT payload FROM effects WHERE key=?", (mail_key,)).fetchone()
            if row is None:
                return
            payload = json.loads(row["payload"])
            if payload.get("raised_at") is None:
                payload["raised_at"] = now
                self.led.db.execute("UPDATE effects SET payload=? WHERE key=?", (json.dumps(payload), mail_key))

    def _insert_effect(self, key, iid, kind, payload, now):
        self.led.db.execute(
            "INSERT OR IGNORE INTO effects(key, item, kind, status, attempts, next_action_at, payload, updated)"
            " VALUES (?,?,?,?,?,?,?,?)", (key, iid, kind, "pending", 0, now, json.dumps(payload), now))

    def check_mail(self, row, payload, now):
        """One escalation's mail receipt (D19). Done only when `ops_watch.py delivered` returns a time at or after
        the raise: "handed to mail command", never "emailed". Until then it stays pending and is re-read each tick;
        30 min after the raise without a receipt it fires email-undelivered once (ticket + high alert), which is
        cleared if the receipt arrives later. Alert creation, a queued mail or an unreadable answer is never a
        receipt."""
        row = self.led.db.execute("SELECT * FROM effects WHERE key=?", (row["key"],)).fetchone()
        payload = json.loads(row["payload"])  # current: _note_raise may have stamped raised_at in this same pass
        nkey = row["key"].split(":", 1)[1]
        iid, n = row["item"], payload.get("n")
        alert = self.led.db.execute("SELECT status, updated FROM effects WHERE key=?", ("alert:" + nkey,)).fetchone()
        tick = bounds(self.config)["tick_seconds"]
        if alert is None or alert["status"] == "cancelled":
            with self.led.tx():
                self.led.db.execute("UPDATE effects SET status='cancelled', next_action_at=NULL, updated=? WHERE key=?",
                                    (now, row["key"]))
            return
        raised_at = payload.get("raised_at")
        if alert["status"] != "done" or raised_at is None:
            with self.led.tx():
                self.led.db.execute("UPDATE effects SET next_action_at=?, updated=? WHERE key=?",
                                    (now + tick, now, row["key"]))
            return
        got = self.delivered_at(payload["alert_key"])
        if got is not None and got >= float(raised_at):
            with self.led.tx():
                self.led.db.execute("UPDATE effects SET status='done', next_action_at=NULL, result=?, updated=? "
                                    "WHERE key=?", ("handed to mail command at %.0f" % got, now, row["key"]))
                self.led.event(iid, "email-handed", now, n=n, alert_key=payload["alert_key"], delivered_at=got)
                if payload.get("undelivered_key"):
                    # adv-4 F3: a failed send stays queued in ops-watch and may land late; the undelivered alert is
                    # cleared and the ticket gets one note saying so
                    self._insert_effect("clear:" + payload["undelivered_key"], iid, "clear",
                                        {"alert_key": payload["undelivered_key"],
                                         "key": "ahc-clear-" + payload["undelivered_key"]}, now)
                    item = self.led.item(iid)
                    if item is not None:
                        body = ("Escalation %s (critical alert %s) was handed to the mail command late, %d min after "
                                "it was raised; the email-undelivered alert is cleared." % (
                                    n, payload["alert_key"], int((got - float(raised_at)) // 60)))
                        self._insert_notice(iid, json.loads(item["request"]), "email-late-%s" % n, "record", body,
                                            False, now)
            return
        waited = now - float(raised_at)
        with self.led.tx():
            if waited >= EMAIL_UNDELIVERED_SECONDS and not payload.get("undelivered_key"):
                item = self.led.item(iid)
                req = json.loads(item["request"]) if item is not None else None
                ukey = "%s%s:%s" % (UNDELIVERED_PREFIX, iid, n)
                payload["undelivered_key"] = ukey
                if req is not None:
                    body = ("Escalation %s (critical alert %s) has no mail receipt %d min after it was raised: it was NOT "
                            "handed to the mail command. Check `python3 ~/.claude/hooks/ops_watch.py status` and the "
                            "deadman sink on this host." % (n, payload["alert_key"], int(waited // 60)))
                    self._insert_notice(iid, req, "email-undelivered-%s" % n, "record", body, False, now)
                    self._insert_effect("alert:" + ukey, iid, "alert", {
                        "alert_key": ukey, "key": "ahc-" + ukey.replace(":", "-"), "severity": "high",
                        "message": "ahc email-undelivered: %s (no mail receipt after %d min)" % (
                            payload["alert_key"], int(waited // 60))}, now)
                self.led.event(iid, "email-undelivered", now, n=n, alert_key=payload["alert_key"])
            expired = waited > MAIL_CHECK_MAX
            self.led.db.execute("UPDATE effects SET status=?, next_action_at=?, payload=?, result=?, updated=? "
                                "WHERE key=?", ("expired" if expired else "pending", None if expired else now + tick,
                                                json.dumps(payload), "no receipt" if got is None else
                                                "receipt predates the raise", now, row["key"]))

    def delivered_at(self, alert_key):
        """The receipt time from `ops_watch.py delivered --key K --json`, or None: any failure, timeout, malformed
        or mismatched answer is "not delivered" (I9)."""
        child = getattr(self.deps, "ops_watch", None)
        if child is None:
            return None
        try:
            rc, out, _err = child(["delivered", "--key", alert_key, "--json"], OPS_WATCH_TIMEOUT)
            answer = json.loads(out) if rc == 0 else None
        except Exception:  # noqa: BLE001 - an unreadable answer is never a receipt
            return None
        if not isinstance(answer, dict) or answer.get("key") != alert_key:
            return None
        value = answer.get("delivered_at")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    def _meta(self, key):
        row = self.led.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else None

    def email_ready(self):
        return self._meta("email_route") == "ready"

    def email_route(self):
        """D19 readiness, at start and every tick: ops-watch must list both capabilities and have a non-empty
        `sinks.deadman`. The config output holds the mail argv, so only its emptiness is used; it is never logged,
        stored or quoted. A change to unavailable opens a new episode: one high alert ahc:email-route:<episode> and
        one comment on `ops_ticket` (alert only, with a log line, when no ops ticket is configured); a change back
        to ready clears that episode's alert. Returns True when ready."""
        reason = self._email_reason()
        now = self.now()
        previous = self._meta("email_route")
        state = "ready" if reason is None else "unavailable"
        with self.led.tx():
            episode = int(self._meta("email_episode") or 0)
            self.led.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('email_route', ?)", (state,))
            self.led.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('email_route_reason', ?)", (reason or "",))
            if state == "unavailable" and previous != "unavailable":
                episode += 1
                self.led.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('email_episode', ?)", (str(episode),))
                key = "ahc:email-route:%d" % episode
                message = ("ahc email-route: unavailable (%s). Escalations are NOT handed to the mail command until "
                           "this clears; they still reach the dashboard and the ticket." % reason)
                self._insert_effect("alert:" + key, SYSTEM_ITEM, "alert", {
                    "alert_key": key, "key": "ahc-email-route-%d" % episode, "severity": "high",
                    "message": message}, now)
                ticket = self.config.get("ops_ticket")
                if ticket:
                    self._insert_effect("ticket:email-route:%d" % episode, SYSTEM_ITEM, "ticket", {
                        "ticket": ticket, "body": message, "key": "ahc-email-route-%d" % episode}, now)
                else:
                    log.warning("email-route unavailable (%s); no ops ticket configured, alert only", reason)
                self.led.event(SYSTEM_ITEM, "email-route-unavailable", now, reason=reason, episode=episode)
            elif state == "ready" and previous == "unavailable" and episode:
                key = "ahc:email-route:%d" % episode
                self._insert_effect("clear:" + key, SYSTEM_ITEM, "clear", {"alert_key": key,
                                                                           "key": "ahc-clear-" + key}, now)
                self.led.event(SYSTEM_ITEM, "email-route-ready", now, episode=episode)
        return state == "ready"

    def _email_reason(self):
        child = getattr(self.deps, "ops_watch", None)
        if child is None:
            return "no ops-watch child"
        try:
            rc, out, _err = child(["capabilities"], OPS_WATCH_TIMEOUT)
            caps = set(out.split()) if rc == 0 else None
            rc2, raw, _err2 = child(["config"], OPS_WATCH_TIMEOUT)
            cfg = json.loads(raw) if rc2 == 0 else None
        except Exception:  # noqa: BLE001 - unreadable is unavailable, never ready
            return "ops-watch unreadable"
        if caps is None or not isinstance(cfg, dict):
            return "ops-watch unreadable"
        for cap in EMAIL_CAPABILITIES:
            if cap not in caps:
                return "missing capability %s" % cap
        sinks = cfg.get("sinks")
        deadman = sinks.get("deadman") if isinstance(sinks, dict) else None
        if not isinstance(deadman, list) or not [c for c in deadman if c]:
            return "sinks.deadman is empty"
        return None

    def _effect_done(self, key, detail):
        with self.led.tx():
            self.led.db.execute("UPDATE effects SET status='done', next_action_at=NULL, result=?, updated=? "
                                "WHERE key=?", (str(detail)[:500], self.now(), key))

    def readback(self, kind, payload):
        if kind == "inbox":
            path = Path(payload["path"])
            return path.parent.parent == self.paths.inbox and _inbox_delivered(
                self.paths.inbox, path.parent.name, path.name, payload["body"])
        if kind == "digest":
            return _digest_has(self.paths.digest, payload["key"])
        return False  # ticket: ah applies an idempotency key once, so resending with the same key is the readback

    def send(self, kind, payload):
        try:
            if kind == "ticket":
                rc, _out, err = self.deps.ah(["ah", "ticket", "comment", payload["ticket"], "--body", payload["body"],
                                              "--key", payload["key"]], 60)
                return rc == 0, "rc=%s %s" % (rc, _short(err))
            if kind == "inbox":
                path = Path(payload["path"])
                try:
                    core.inbox_path(self.paths, path.parent.name, path.name)
                except core.Refused as error:
                    return False, "refused: %s" % error
                if path.parent.parent != self.paths.inbox:
                    return False, "refused: inbox path escapes the inbox directory"
                try:
                    _write_inbox(self.paths.inbox, path.parent.name, path.name, payload["body"])
                except _InboxRefused as error:
                    return False, "refused: %s" % error
                return True, "written"
            if kind == "digest":
                if not self.readback("digest", payload):
                    _append_private(self.paths.root, self.paths.digest, payload["line"])
                return True, "appended"
            if kind == "alert":
                rc, _out, err = self.deps.ah(["ah", "alert", "raise", "--severity", payload.get("severity", "high"),
                                              "--alert-key", payload["alert_key"], "--source", "ahc", "--key",
                                              payload["key"], "--message", payload["message"]], 60)
                return rc == 0, "rc=%s %s" % (rc, _short(err))
            if kind == "clear":
                rc, _out, err = self.deps.ah(["ah", "alert", "clear", "--alert-key", payload["alert_key"], "--source",
                                              "ahc", "--key", payload["key"]], 60)
                return rc == 0, "rc=%s %s" % (rc, _short(err))
        except (OSError, subprocess.SubprocessError) as error:
            return False, _short(error)
        return False, "unknown effect kind"  # includes "mail": a receipt is read back, never sent

    def escalate(self):
        """Owner notices not acknowledged by their deadline go to the ticket and the user channel, once (AC-19)."""
        now = self.now()
        rows = self.led.db.execute(
            "SELECT * FROM notices WHERE requires_ack=1 AND acked_at IS NULL AND escalated_at IS NULL"
            " AND deadline <= ?", (now,)).fetchall()
        for notice in rows:
            row = self.led.item(notice["item"])
            req = json.loads(row["request"])
            body = ("Owner %s has not acknowledged the %s notice for %s#%s (item %s) within %d min. Escalating to "
                    "the ticket and the user channel. Acknowledge with: python3 ~/.claude/hooks/ahc_runner.py ack %s "
                    "--owner %s" % (req["owner"], notice["state"], req["repo"], req["pr"], notice["item"],
                                    bounds(self.config)["block_ack_seconds"] // 60, notice["item"], req["owner"]))
            stop = self._d20_stop(row, req)
            with self.led.tx():
                self.led.db.execute("UPDATE notices SET escalated_at=? WHERE key=?", (now, notice["key"]))
                if stop:  # the owner already responded (newer submission) or the PR is merged or closed
                    self.led.event(notice["item"], "ack-escalation-skipped", now, notice=notice["state"],
                                   reason=stop)
                    continue
                # under a live D20 obligation this escalation is also the D20 one (sets esc_at), so the two clocks
                # (both 4 h by default) never raise two criticals for the same wait
                live_d20 = row["state"] in D20_STATES and row["disposed_at"] is None
                self.escalate_item(notice["item"], req, "%s-escalated" % notice["state"], body, now, d20=live_d20)

# ---------------------------------------------------------------- tick

def ingest(ledger, paths, config, now=None):
    """Accept queue files into the ledger. A file that fails validation, or whose ingestion raises anything, is moved
    to `rejected/` with a reason file and reported; it never stops the other items (r2 F5). Returns the rejections as
    (file name, reason)."""
    try:
        files = sorted(paths.queue.glob("ahc-*.json"))
    except OSError:
        files = []
    rejected = []
    for qfile in files:
        # spec v4 F2: only `ahc submit` admits work, inside the ledger transaction; a file placed in the queue
        # directory admits nothing, whatever it contains, and is quarantined with an alert
        reason = "a queue file admits nothing; submit with `ahc submit` (the file was not read)"
        moved = _quarantine(paths, qfile, reason)
        # an unmovable file is skipped and reported again next tick under the same deterministic alert key
        rejected.append((moved or qfile.name, reason if moved else reason + "; quarantine move failed"))
    return rejected


def _quarantine(paths, qfile, reason):
    """Atomically rename the queue entry itself (a symlink is moved, never followed) into rejected/, with a reason
    file. Returns the quarantined name, which keys the one alert for it, or None if it could not be moved."""
    target_dir = paths.root / "rejected"
    try:
        fs.make_dirs(paths.root, target_dir)
        target = target_dir / qfile.name
        if os.path.lexists(str(target)):
            target = target_dir / ("%s.%d.json" % (qfile.stem, time.time_ns()))
        # the reason first (AC-18): a crash after the rename must still leave the reason beside the quarantined
        # file, because the alert below is best effort and the queue entry is gone after the rename
        _write_private(paths.root, target.with_name(target.name + ".reason"), redact.redact(reason) + "\n")
        crash_before("runner.quarantine")
        fs.rename(paths.root, qfile, target)  # atomic; renames the link, never its referent
        crash_after("runner.quarantine")
        return target.name
    except OSError as error:
        log.warning("could not quarantine %s: %s", qfile.name, type(error).__name__)
        return None


def file_transport_refused(paths):
    """True when `paths` is the production root, under the real home directory of this uid. Tests always build
    Paths on a temporary home, so only they can turn the local file transport on."""
    try:
        return Path(paths.home).resolve() == Path(os.path.expanduser("~")).resolve()
    except (OSError, RuntimeError):
        return True


def _quarantine_report_dir(paths, report_dir, reason):
    """Move a review attempt's directory that failed _read_report into rejected/ as a name (a link or a swapped
    directory is moved, never followed), with a reason file beside it. Its contents are never read again, and the
    next attempt gets a fresh directory. Returns the quarantined name, or None if nothing could be moved."""
    report_dir = Path(report_dir)
    if report_dir.parent != paths.reports or not os.path.lexists(str(report_dir)):
        return None
    target = paths.root / "rejected" / ("report-%s" % report_dir.name)
    try:
        fs.make_dirs(paths.root, target.parent)
        if os.path.lexists(str(target)):
            target = target.with_name("%s.%d" % (target.name, time.time_ns()))
        _write_private(paths.root, target.with_name(target.name + ".reason"), redact.redact(reason) + "\n")
        crash_before("runner.quarantine_report")
        fs.rename(paths.root, report_dir, target)
        crash_after("runner.quarantine_report")
        return target.name
    except OSError as error:
        log.warning("could not quarantine report dir %s: %s", report_dir.name, type(error).__name__)
        return None


def supersede(worker):
    """NEG-15: for one PR only the newest submission proceeds; older queued or deferred items are superseded."""
    led = worker.led
    rows = led.db.execute("SELECT id, lineage, submitted, state FROM items WHERE state IN ('queued', 'deferred') "
                          "ORDER BY lineage, submitted DESC, id").fetchall()
    newest = {}
    for row in rows:
        live = led.db.execute("SELECT id FROM items WHERE lineage=? AND state IN ('queued','deferred','reviewing',"
                              "'routed-to-main') ORDER BY submitted DESC, id LIMIT 1", (row["lineage"],)).fetchone()
        newest[row["lineage"]] = live["id"]
        if row["id"] != live["id"]:
            token = worker.lease(row["id"])
            worker.settle(row["id"], token, "superseded", event="superseded", by=live["id"])


REVIEW_STATES = ("queued", "deferred")   # the review role's states; core never leases them or `reviewing`


def tick(paths, config, deps, role="all"):
    """One reconcile pass for one role. Returns a summary dict. Raises nothing for item-level failures.

    The two units split the ledger by item state, so they never lease the same item:
      core    ingest, email-route readiness, the routed-to-main recheck, no-ack and D20 escalation, effect dispatch,
              invariant checks; it alone migrates the ledger;
      review  recovery of `reviewing` items (any found at its start is an orphan: it holds the review lock), the
              supersede pass, and one prepare-and-review of a due queued or deferred item;
    "all" (tests, a manual run) does both in that order. Each role beats its own heartbeat service."""
    if role not in ROLES:
        raise ValueError("unknown role %r" % role)
    core_role, review_role = role in ("core", "all"), role in ("review", "all")
    ledger = Ledger(paths, migrate=core_role)
    worker = Worker(paths, config, deps, ledger)
    summary = {"role": role, "processed": [], "recovered": [], "defects": [], "rejected": []}
    try:
        if core_role:
            _core_intake(worker, ledger, paths, config, deps, summary)
        if review_role:
            _review_pass(worker, ledger, summary)
        if core_role:
            _core_outbound(worker, ledger, summary)
            _shadow_pass(ledger, paths, config, deps, summary)
    except _Stop:
        summary["stopped"] = True
    finally:
        ledger.close()
    service = {"core": "ahc-core", "review": "ahc-review", "all": "ahc"}[role]
    try:
        deps.ah(["ah", "heartbeat", "beat", "--service", service], 30)
    except Exception:  # noqa: BLE001 - a heartbeat failure is visible to the observer as a stale beat
        log.warning("heartbeat failed")
    return summary


def _core_intake(worker, ledger, paths, config, deps, summary):
    summary["email_route"] = "ready" if worker.email_route() else "unavailable"
    summary["rejected"] = ingest(ledger, paths, config, worker.now())
    for name, reason in summary["rejected"]:
        message = "ahc rejected queue file %s: %s (moved to %s)" % (name, reason, paths.root / "rejected")
        try:
            rc, _out, _err = deps.ah(["ah", "alert", "raise", "--severity", "high", "--alert-key",
                                      "ahc:rejected:" + name, "--source", "ahc", "--key", "ahc-rejected-" + name,
                                      "--message", redact.redact(message)[:500]], 60)
            if rc != 0:
                log.warning("rejection alert for %s exited %s; the reason file in rejected/ remains", name, rc)
        except Exception:  # noqa: BLE001 - the file is already quarantined with its reason; the alert is best effort
            log.warning("rejection alert failed for %s; the reason file in rejected/ remains", name)
    summary["superseded_by_head"] = worker.supersede_by_head()
    now = worker.now()
    for row in ledger.db.execute("SELECT * FROM items WHERE state='routed-to-main' AND next_action_at <= ? "
                                 "ORDER BY next_action_at, submitted, id", (now,)).fetchall():
        current = ledger.item(row["id"])
        if current["state"] == row["state"]:
            summary["processed"].append((row["id"], worker.process(current)))


def _review_pass(worker, ledger, summary):
    for row in ledger.db.execute("SELECT * FROM items WHERE state='reviewing'").fetchall():
        summary["recovered"].append((row["id"], worker.recover(row)))
    supersede(worker)
    now = worker.now()
    marks = ",".join("?" * len(REVIEW_STATES))
    due = ledger.db.execute("SELECT * FROM items WHERE state IN (%s) AND next_action_at <= ? ORDER BY next_action_at,"
                            " submitted, id" % marks, list(REVIEW_STATES) + [now]).fetchall()
    for row in due:
        current = ledger.item(row["id"])
        if current["state"] != row["state"]:
            continue
        summary["processed"].append((row["id"], worker.process(current)))
        if ledger.db.execute("SELECT 1 FROM effects WHERE item=? AND kind='review'", (row["id"],)).fetchone():
            break  # one review per tick on this host (D7)


def _core_outbound(worker, ledger, summary):
    worker.escalate()
    worker.escalate_overdue()
    worker.dispatch_effects()
    summary["pruned_packets"] = worker.prune_packets()
    missing = ledger.db.execute("SELECT id FROM items WHERE state IN (%s) AND next_action_at IS NULL"
                                % ",".join("?" * len(NON_TERMINAL)), sorted(NON_TERMINAL)).fetchall()
    summary["defects"] = ["I2: %s has no next_action_at" % row["id"] for row in missing]


def _shadow_pass(ledger, paths, config, deps, summary):
    """AC-3/AC-4: the shadow WorkItem pass (AHC_SHADOW=1 only, for the repos on the shadow list), after the legacy
    pass; then AC-13's refusals, collected by the active launch policy, are raised as incidents in the outbox."""
    import ahc_guard  # noqa: PLC0415
    import ahc_shadow  # noqa: PLC0415
    c = open_contracts(ledger, paths)
    parts = getattr(deps, "shadow_parts", None)
    if ahc_shadow.shadow_on() and parts is not None and config.get("shadow_repos"):
        producer, clone, w21 = parts(c)
        stage = getattr(deps, "review_stage", None)
        t = ahc_shadow.ShadowTick(c, producer, clone, config, w21=w21,
                                  digest_append=lambda text: _append_private(paths.root, paths.root / SHADOW_DIGEST,
                                                                             text),
                                  review=stage(c, clone) if stage is not None else None,
                                  store_packet=lambda packet: store_r2_packet(paths.root, packet))
        summary["shadow"] = t.tick()
        for subject, why in summary["shadow"]["incidents"] + [("observations", w) for w in producer.incidents]:
            raise_incident(c, subject, why)
    policy = ahc_guard.active()
    if policy is not None:
        while policy.incidents:
            raise_incident(c, "launch-guard", "AC-13 refused: %s" % policy.incidents.pop(0))


def store_r2_packet(root, packet):
    """R2: the built packet at root/packets/<sha256>.md, where the R3 unit's --packet names it (written once)."""
    import ahc_fs  # noqa: PLC0415
    path = Path(root) / "packets" / ("%s.md" % packet["sha256"])
    try:
        ahc_fs.write_file(root, path, packet["text"].encode("utf-8"), exclusive=True, create_dirs=True)
    except FileExistsError:
        pass                                          # the same sha names the same bytes


def startup_reconcile(paths, policy, runner=None):
    """AC-8 / NEG-36 / NEG-49: before any new attempt can start, list the ahc-review-* units and reconcile each
    against its committed launch intent; every finding is raised as an incident. Without review isolation (no systemd
    on this host, or the units not resolved by the guard) there is no unit to reconcile. `runner` is for tests."""
    import ahc_review  # noqa: PLC0415
    if runner is None:
        if not ahc_review.SystemdRunner.available(policy):
            return {"skipped": "no review isolation on this host"}
        runner = ahc_review.SystemdRunner(policy)
    ledger = Ledger(paths)
    try:
        contracts = open_contracts(ledger, paths)
        out = ahc_review.Reconciler(contracts, policy, runner).run()
        for text in out["incidents"]:
            raise_incident(contracts, "reconcile", text)
        del policy.incidents[:]
        return out
    finally:
        ledger.close()


def raise_incident(contracts, subject, text):
    """An incident in the outbox (wi_notices, kind incident) for the daemon itself, through the AC-14 chokepoint."""
    stamp = contracts.stamp({})
    ev = "incident:" + hashlib.sha256(("%s|%s|%s|%r" % (subject, text, stamp["boot"], stamp["mono"])).encode()
                                      ).hexdigest()[:32]
    with contracts.tx():
        contracts._wi_notice(ev, {"id": SYSTEM_ITEM}, str(subject)[:80], "incident", str(text)[:1000])
    log.warning("incident (%s): %s", subject, _short(text))


MAIN_ACTOR = "main"
DISPOSITION_MAX = 500


def ack(paths, iid, owner, now=None, disposition=None, main_proven=False, config=None, deps=None):
    """Owner acknowledgement: the only way an owner notice becomes delivered (AC-19, NEG-26). It clears the item's
    critical alerts unless a D20 obligation is still live (an owner ack never silences main's obligation).

    With `disposition` (required reason text) it records a disposition that stops D20 escalation (spec Q1 ruling):
    for a state whose `dispose` lists "owner", the item's owner or main may record it; otherwise main only. `--owner
    main` counts only with `main_proven` (the CLI's caller_identity stamp, bound to main's own tool call); a sub-agent
    claiming to be main is refused and escalation continues. The disposition is an event with actor and reason, a
    ticket comment, and clears the item's critical alerts."""
    now = now if now is not None else time.time()
    ledger = Ledger(paths, migrate=False)
    try:
        row = ledger.item(iid)
        if row is None:
            raise core.Refused("no such item")
        if disposition is None:
            if row["owner"] != owner:
                raise core.Refused("only the item's owner can acknowledge it")
            with ledger.tx():
                cur = ledger.db.execute("UPDATE notices SET acked_at=? WHERE item=? AND audience='owner' AND "
                                        "acked_at IS NULL", (now, iid))
                # v6e M4 / adv-4 F2: an ack acknowledges receipt only. A delivered BLOCK becomes `acknowledged`,
                # whose D20 repair deadline runs from the ack (entered_at); the guarded UPDATE makes a repeat ack a
                # no-op that never resets that deadline. No ack is ever a disposition (M3).
                moved = ledger.db.execute(
                    "UPDATE items SET state='acknowledged', entered_at=?, updated=? WHERE id=? AND "
                    "state='block-delivered'", (now, now, iid)).rowcount
                ledger.event(iid, "acked", now, owner=owner, notices=cur.rowcount,
                             moved="block-delivered->acknowledged" if moved else None)
                row = ledger.item(iid)
                if row["state"] not in D20_STATES or row["disposed_at"] is not None:
                    Worker(paths, config or {}, deps, ledger)._clear_criticals(iid, now)
            if moved:
                _mirror(paths, iid, "acknowledged", now, {"owner": owner})
            return cur.rowcount
        reason = " ".join(str(disposition).split())
        if not reason:
            raise core.Refused("a disposition needs a reason")
        if len(reason) > DISPOSITION_MAX:
            raise core.Refused("a disposition reason is at most %d characters" % DISPOSITION_MAX)
        policy = STATE_TABLE.get(row["state"], {})
        if policy.get("cover") != "d20":
            raise core.Refused("item is %s, which is not under D20 escalation; nothing to dispose" % row["state"])
        if row["disposed_at"] is not None:
            raise core.Refused("a disposition is already recorded for this item")
        allowed = policy.get("dispose", (MAIN_ACTOR,))
        if owner == MAIN_ACTOR:
            if not main_proven:
                raise core.Refused("--owner main needs proof that the main session itself ran this command "
                                   "(caller_identity stamp); a sub-agent cannot dispose for main")
            actor = MAIN_ACTOR
        elif owner == row["owner"] and "owner" in allowed:
            actor = "owner " + owner
        else:
            raise core.Refused("only %s may dispose of a %s item" % (" or ".join(
                "main" if a == MAIN_ACTOR else "the item's owner" for a in allowed), row["state"]))
        req = json.loads(row["request"])
        body = ("Disposition recorded for %s#%s at %s (item %s, state `%s`) by %s: %s\nD20 escalation for this item "
                "stops; its critical alerts are cleared." % (req["repo"], req["pr"], req["head"], iid, row["state"],
                                                              actor, redact.redact(reason)))
        worker = Worker(paths, config or {}, deps, ledger)
        with ledger.tx():
            ledger.db.execute("UPDATE items SET disposed_at=? WHERE id=?", (now, iid))
            ledger.event(iid, "disposed", now, actor=actor, reason=redact.redact(reason))
            worker._insert_notice(iid, req, "disposed", "record", body, False, now)
            worker._clear_criticals(iid, now)
        return 1
    finally:
        ledger.close()


# ---------------------------------------------------------------- text helpers

def open_contracts(ledger, paths):
    """The WorkItem/Review/Grant/Effect transition functions over this ledger's connection, with the local
    authority log beside the ledger (a ledger.sqlite3.* name, which every ahc root check accepts)."""
    return ahc_contracts.Contracts(ledger.db, ahc_contracts.AuthorityLog(paths.root / AUTHORITY_LOG))


AUTHORITY_LOG = "ledger.sqlite3.authority.jsonl"
SHADOW_DIGEST = "ledger.sqlite3.shadow-digest.md"


def w16(paths, argv, *, main_proven, item, target, expected_version, accept=(), ticket=None, extension=0):
    """AC-6 / NEG-15: main's WorkItem disposition. Applied only from this command, only when claim_main proved
    main's one-shot stamp for exactly `argv`; the proof (bound to the item, the target, the expected version and
    the argv digest) is recorded and spent in the same transaction as the W16 move. The tick never applies W16."""
    if not main_proven:
        raise core.Refused("w16 needs main's stamp for exactly this command; an actor name is not proof")
    digest = core.dispose_stamp_parts(argv)[0]
    ledger = Ledger(paths, migrate=False)
    try:
        c = open_contracts(ledger, paths)
        proof = "w16-" + hashlib.sha256(("%s|%s|%r" % (digest, c.boot_id, c._mono())).encode()).hexdigest()[:24]
        try:
            with c.tx():
                c.record_w16_proof(proof, item, target, expected_version, digest, accepted=list(accept),
                                   ticket=ticket, extension=extension)
                return c.wi_move(item, "W16", expected_version=expected_version, event_id="w16:" + proof,
                                 actor="main", to=target, proof=proof)
        except ahc_contracts.ContractError as error:
            raise core.Refused(str(error)) from None
    finally:
        ledger.close()


def _short(value, limit=300):
    return redact.redact(str(value)).replace("\n", " ")[:limit]


def _is_protected(path):
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, pattern) for pattern in PROTECTED) or path.startswith(".claude/")


def _report_body(report_path, raw=None):
    try:
        if raw is None:
            raw = core.read_regular(report_path, core.REPORT_MAX_BYTES)
        text = raw.decode("utf-8", errors="replace")
    except core.Unreadable:
        return "(the report could not be read)"
    head, _sep, body = text.partition("\n\n")
    return body.strip()[:MAX_BODY] or text[:MAX_BODY]


def _owner_notice(state, reason):
    return {"state": state, "audience": "owner", "reason": reason, "requires_ack": True}


def _alert_payload(iid, req, state, body, esc_n=None):
    """A routine terminal-unsuccessful state raises HIGH under ahc:<item> (dashboard, no mail). A user-audience
    escalation raises CRITICAL under its own key ahc:<item>:<n>, so ops-watch's 6 h per-key mail limit never
    suppresses a later escalation of the same item (D19)."""
    message = "ahc %s: %s#%s %s | %s" % (state, req["repo"], req["pr"], req["head"][:12],
                                       " ".join(body.split())[:400])
    if esc_n is None:
        return {"alert_key": "ahc:" + iid, "key": "ahc-%s-%s" % (iid, state), "message": message, "severity": "high"}
    return {"alert_key": "ahc:%s:%d" % (iid, esc_n), "key": "ahc-%s-%s" % (iid, state), "message": message,
            "severity": "critical"}


def _owner_body(iid, req, data, state, reason):
    steps = {
        "block-delivered": "Acknowledge receipt (ahc ack <item> --owner <you>), fix the findings, push, then submit "
                           "again at the new head with a fresh packet. The ack does not close the finding: the repair "
                           "deadline keeps running until the new head, and only main can close it without one.",
        "blocked": "A guard or policy refused this step. It is routed to the decision-maker; there is no alternate "
                   "path.",
        "lint-failed": "Fix the packet layout or add the missing evidence, then submit again. The fixer never adds "
                       "an exit status or a count.",
        "stale-head": "The PR head moved. Submit again at the new head with a fresh packet.",
        "refused": "Correct the request and submit again.",
        "review-error": "No receipt was produced. Read the reason; a quota or provider outage is retried by the "
                        "daemon, anything else needs you.",
        "needs-attention": "The daemon stopped automatic work on this item. Read the reason and resubmit or ask main.",
        "unsubmitted": "The PR has a new head that superseded a BLOCK, and nothing was submitted for it. Submit the "
                       "new head with a fresh packet (ahc submit); the escalation clock runs until you do.",
        "review-invalid": "The reviewer's output was unusable twice for this head (the one declared repeat is spent). "
                          "Fix the packet if the cause is inside it, push a new head, or ask main.",
        UNKNOWN_OUTCOME: "The review's outcome is unknown and it will not be relaunched. Reconcile the run with "
                         "usage_guard, then record a disposition (ack --disposition) or resubmit.",
    }
    lines = ["ahc %s: %s#%s at %s (item %s)" % (state, req["repo"], req["pr"], req["head"], iid),
             "Report: %s" % data.get("report", "none"),
             "Next step: %s" % steps.get(state, "see the reason below"),
             "Acknowledge: python3 ~/.claude/hooks/ahc_runner.py ack %s --owner %s" % (iid, req["owner"]),
             "", str(reason)[:MAX_BODY]]
    return "\n".join(lines)


def _pass_body(iid, req, data, verdict):
    lines = ["ahc %s: %s#%s at %s (item %s)" % (verdict, req["repo"], req["pr"], req["head"], iid),
             "Receipt: %s" % data.get("report"),
             "Packet reviewed: %s" % data.get("packet")]
    if data.get("base_note"):
        lines.append("Base: %s" % data["base_note"])
    if data.get("fix_actions"):
        lines.append("Packet fixer: " + "; ".join(data["fix_actions"]))
    if data.get("protected"):
        lines.append(data["protected"])
    if verdict != "PASS":
        lines.append("PASS-WITH-TICKETS is not a pure PASS: main decides.")
    lines += ["Gate 1: main merges. Exact command (checks green):",
              "    " + merge_command(req),
              "If merge_gate reports no_ci, main first runs:",
              "    python3 ~/.claude/hooks/merge_gate.py waive --repo %s --pr %s --head %s --ticket '%s' "
              "--reason 'ahc exact-head PASS receipt %s'" % (req["repo"], req["pr"], req["head"], req["ticket"],
                                                             Path(str(data.get("report"))).name)]
    return "\n".join(lines)


def merge_command(req):
    return "gh pr merge %s -R %s --merge --match-head-commit %s" % (req["pr"], req["repo"], req["head"])


def _digest_line(iid, req, state, body):
    """One digest entry. The item id appears once, inside the readback key, so a count of the id is a count of
    entries (NEG-34)."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rest = body.splitlines()[1:] if body else []
    detail = " | ".join(line.strip() for line in rest if line.strip()).replace(iid, "<item>")[:1500]
    return "- %s %s %s#%s %s [k:%s:%s]\n  %s\n" % (stamp, state.upper(), req["repo"], req["pr"], req["head"][:12],
                                                 iid, state, detail)


class _InboxRefused(OSError):
    """The inbox directory or owner directory is not a real directory (for example a symlink swapped in)."""


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _write_inbox(inbox, owner, name, text):
    """Write an owner notice without a check-then-write gap (r2 F5 follow-up): the inbox and owner directories are
    opened with O_NOFOLLOW|O_DIRECTORY and the file is created relative to the owner directory's fd with
    O_EXCL|O_NOFOLLOW, then renamed within that directory. A symlink swapped in after inbox_path's check makes the open
    fail; nothing is ever written through it. An existing notice is left as is (idempotent)."""
    root = Path(inbox).parent                # paths.inbox is always <ahc root>/inbox
    notice = Path(inbox) / owner / name
    try:
        with fs.directory(root, notice.parent, create=True) as owner_fd:
            present = _notice_state(owner_fd, name, text)
    except fs.UnsafePath as error:
        raise _InboxRefused("owner inbox is not a private directory: %s" % error) from None
    if present == "match":
        return  # already delivered with exactly this content
    if present != "absent":
        raise _InboxRefused("notice name is occupied by a %s entry" % present)
    crash_before("runner.inbox")
    try:
        fs.write_file(root, notice, text, exclusive=True)   # first writer wins; a name planted since is kept
    except FileExistsError:
        raise _InboxRefused("notice name was taken while it was being written") from None
    except fs.UnsafePath as error:
        raise _InboxRefused("owner inbox is not a private directory: %s" % error) from None
    crash_after("runner.inbox")


def _notice_state(owner_fd, name, text):
    """'absent', 'match', or why the entry at `name` (relative to owner_fd, never followed) is not our notice:
    'symlink', 'non-regular' or 'mismatched'."""
    want = text.encode("utf-8")
    try:
        have = core.read_regular(name, len(want), dir_fd=owner_fd)
    except core.Unreadable as error:
        if error.kind in ("absent", "symlink", "non-regular"):
            return error.kind
        return "mismatched"   # oversize (a different notice) or unreadable: never counted as delivered
    return "match" if have == want else "mismatched"


def _inbox_delivered(inbox, owner, name, text):
    """Readback for an inbox effect: delivered only if the notice is a regular file, reached without following any
    symlink, whose bytes equal what was written. A symlink or any mismatch is not delivered (r2 F5 follow-up)."""
    try:
        root_fd = os.open(str(inbox), _DIR_FLAGS)
    except OSError:
        return False
    try:
        try:
            owner_fd = os.open(owner, _DIR_FLAGS, dir_fd=root_fd)
        except OSError:
            return False
        try:
            return _notice_state(owner_fd, name, text) == "match"
        finally:
            os.close(owner_fd)
    finally:
        os.close(root_fd)


DIGEST_TAIL_BYTES = 1_000_000


def _open_private(path, flags, mode=0o600):
    """Open a coordinator-private file without following a symlink and without blocking on a FIFO (a write open of a
    FIFO with no reader fails with ENXIO instead of waiting), then require a regular file on the opened descriptor
    (r4 F2). Returns the fd; raises OSError."""
    fd = os.open(str(path), flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), mode)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file: %s" % Path(path).name)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _digest_has(path, key):
    """Digest readback: look for the line's key in the last DIGEST_TAIL_BYTES only (the digest only grows). The line
    being checked was appended moments before a crash, so it is always inside the tail. Unreadable is not found."""
    try:
        fd = _open_private(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        size = os.fstat(fd).st_size
        os.lseek(fd, max(0, size - DIGEST_TAIL_BYTES), os.SEEK_SET)
        tail = os.read(fd, DIGEST_TAIL_BYTES)
    except OSError:
        return False
    finally:
        os.close(fd)
    return ("[k:%s]" % key).encode("utf-8") in tail


def _write_private(root, path, text):
    """Replace `path` under the ahc root whole: an unpredictable O_EXCL temp file, then rename by descriptor."""
    crash_before("runner.write_private")
    fs.write_file(root, Path(path), text, create_dirs=True)
    crash_after("runner.write_private")


def _append_private(root, path, text):
    """Append to `path` under the ahc root through checked directory descriptors (O_NOFOLLOW, regular, our uid)."""
    crash_before("runner.append_private")
    fs.append_file(root, Path(path), text, create_dirs=True)
    crash_after("runner.append_private")


# ---------------------------------------------------------------- live dependencies

class LiveDeps:
    """The production children. Every call is an argv list with a timeout; nothing goes through a shell."""

    def __init__(self, paths, config, policy=None):
        import ahc_guard  # noqa: PLC0415
        self.paths, self.config = paths, config
        # AC-13: every child is launched in its form (resolved absolute path, minimal env, cwd the root). The
        # daemon entry installs an enforcing policy; elsewhere (CLI, tests) the same forms run unenforced.
        self.policy = policy or ahc_guard.active() or ahc_guard.Policy(
            paths.root, repos=config.get("repos", []), home=getattr(paths, "home", None))

    def clock(self):
        return time.time()

    def _refused(self, error):
        log.error("launch refused: %s", error)
        return 126, "", "LaunchRefused: %s" % error

    def gh(self, argv, timeout):
        import ahc_guard  # noqa: PLC0415
        try:
            return ahc_guard.run(self.policy, "gh", list(argv[1:]), min(timeout, core.TIMEOUTS["gh"]))
        except ahc_guard.LaunchRefused as error:
            return self._refused(error)

    def _helper(self, name, default, args, timeout):
        import ahc_guard  # noqa: PLC0415
        script = str(self.config.get(name, default))
        try:
            return ahc_guard.run_helper(self.policy, name, list(args), timeout, script=script)
        except ahc_guard.LaunchRefused as error:
            return self._refused(error)

    def ah(self, argv, timeout):
        return self._helper("ah", Path.home() / ".claude/hooks/ah.py", argv[1:], min(timeout, core.TIMEOUTS["ah"]))

    def review(self, argv, timeout):
        """The legacy review helper: argv is [python, peer_review script, ...] as the runner built it."""
        import ahc_guard  # noqa: PLC0415
        try:
            rc, _out, err = ahc_guard.run_helper(self.policy, "peer_review", list(argv[2:]), timeout,
                                                 script=argv[1])
        except ahc_guard.LaunchRefused as error:
            rc, _out, err = self._refused(error)
        return rc, err

    def commits(self, clone, merge_base, head):
        """[(full sha, subject)] of merge_base..head in the daemon clone (D24 note)."""
        # AC-13: the legacy call (no SAFE, inherited env) moves onto the git form
        rc, out, err = ahc_clone_git(["-C", str(clone), "log", "--format=%H%x09%s", "%s..%s" % (merge_base, head)],
                                     60, cwd=str(clone))
        if rc != 0:
            raise RuntimeError("git log failed: %s" % _short(err))
        return [tuple(line.split("\t", 1)) for line in out.splitlines() if "\t" in line]

    def ops_watch(self, argv, timeout):
        """Read-only ops-watch queries only: capabilities, config (emptiness of sinks.deadman), delivered."""
        if not argv or argv[0] not in ("capabilities", "config", "delivered"):
            raise ValueError("ops_watch: only read-only queries")
        return self._helper("ops_watch", Path.home() / ".claude/hooks/ops_watch.py", argv,
                            min(timeout, OPS_WATCH_TIMEOUT))

    def clone(self, repo, head, base):
        import ahc_clone
        # https only. config.json can opt into local file remotes for tests, and that opt-in is refused for the
        # production root (under the real home), so a stray key can never widen the transports of the live daemon.
        allow_file = self.config.get("clone_file_transport") is True
        if allow_file and file_transport_refused(self.paths):
            raise ahc_clone.CloneError("clone_file_transport is for test roots only; refused for %s" % self.paths.root)
        floor = int(self.config.get("disk_floor_bytes", 20 * 1024 ** 3))
        if shutil.disk_usage(str(self.paths.clones)).free < floor:
            raise RuntimeError("disk floor: less than %d GiB free for clones" % (floor // 1024 ** 3))
        url = self.config.get("clone_urls", {}).get(repo, "https://github.com/%s.git" % repo)
        return ahc_clone.prepare(self.paths.clones, repo, url, head, base, allow_file=allow_file)

    def shadow_parts(self, contracts):
        """AC-3: the shadow tick's parts: the production observation producer (AC-1, gh and git through the AC-13
        forms), the daemon clone, and the W21 sender (None until AC-7 is armed by its flag).

        ASSUMPTION (goodqa#16049, open for main): no production GoodQA reader exists at this slice, so the reader
        returns nothing and every shadow observation is refused (fail closed: nothing is admitted or moved live).
        The local reader takes the repo's policy record from config `shadow_policy[repo]`; the kill switch, CAS and
        canary are unknown (None), so ELIG's e6 and e9 fail closed."""
        import ahc_observe  # noqa: PLC0415
        shadow_policy = self.config.get("shadow_policy") if isinstance(self.config.get("shadow_policy"), dict) else {}

        def local(repo):
            record = shadow_policy.get(repo)
            return {"policy": dict(record) if isinstance(record, dict) else {}, "kill_switch": None,
                    "kill_epoch": contracts.authority_epoch(), "chk_cas": None, "canary": None}

        def goodqa(repo, pr, item):
            return None
        producer = ahc_observe.Producer.for_live(contracts, self.policy, goodqa, local)
        return producer, (lambda repo, head, base: self.clone(repo, head, base)), None

    def review_stage(self, contracts, clone):
        """AC-8: the shadow tick's review step: the production R3 Launcher (no runner, so infra-wait, unless systemd
        and the completion wrapper are both present) and core's completion inbox, kept for the daemon's life."""
        import ahc_review  # noqa: PLC0415
        launcher = ahc_review.Launcher(contracts, self.policy, Path.home() / ".claude/hooks/peer_review.py",
                                       self.paths.root, clone)
        if launcher.runner is None:
            return ahc_review.ReviewStage(contracts, launcher, None)
        if getattr(self, "_inbox", None) is None:
            self._inbox = ahc_review.FinalInbox(self.paths.root)
        return ahc_review.ReviewStage(contracts, launcher, self._inbox)

    def merge_base(self, clone, head, base):
        import ahc_clone
        return ahc_clone._git(["merge-base", head, base], cwd=clone).stdout.strip()

    def changed_paths(self, clone, merge_base, head):
        import ahc_clone
        out = ahc_clone._git(["diff", "--name-only", "--no-renames", "-z", merge_base, head], cwd=clone).stdout
        return [p for p in out.split("\0") if p]


def ahc_clone_git(args, timeout, cwd=None):
    """(rc, stdout, stderr) of one git child in the AC-13 git form, never raising on a nonzero exit."""
    import ahc_clone  # noqa: PLC0415
    r = ahc_clone._git(list(args), cwd=cwd, timeout=timeout, check=False)
    return r.returncode, r.stdout, r.stderr


# ---------------------------------------------------------------- CLI

def load_config(paths):
    path = paths.root / "config.json"
    try:
        config = json.loads(core.read_regular(path, core.CONFIG_MAX_BYTES).decode("utf-8"))
        if not isinstance(config, dict):
            config = {}
    except (core.Unreadable, ValueError):
        config = {}
    config.setdefault("repos", ["ericmacdougall/bugtracker", "ericmacdougall/Android-security",
                                "ericmacdougall/agent-harness", "ericmacdougall/agent-fabric"])
    config.setdefault("work_roots", [str(paths.home / ".agent-harness" / "work")])
    if str(paths.packets) not in config["work_roots"]:
        config["work_roots"] = list(config["work_roots"]) + [str(paths.packets)]  # staged stdin packets (adv-3 F2)
    return config


REPO_HOURLY_LIMIT = 6        # NEG-52: submissions admitted per repo per rolling hour
PACKET_RETENTION_SECONDS = 7 * 86400   # v6c: staged packets outlive their item's terminal state by 7 days
STAGED_NAME = re.compile(r"^[0-9a-f]{64}\.md$")


def admit(paths, config, norm, now=None):
    """Admit one validated request (spec v4 F2): in ONE `BEGIN IMMEDIATE` transaction, a duplicate id returns the
    existing item; otherwise the queue cap (non-terminal items) and the per-repo limit (items admitted for the repo in
    the last hour) are checked and the row, its lineage and the `accepted` event are inserted. Concurrent submits
    serialize on the write lock, so N racers against k free slots admit exactly k. Returns {"id", "duplicate"}."""
    now = float(now if now is not None else norm.get("submitted") or time.time())
    capacity = int(bounds(config)["queue_capacity"])
    ledger = Ledger(paths, migrate=False)
    try:
        import ahc_shadow  # noqa: PLC0415
        if ahc_shadow.pipeline_of(ledger.db, norm["repo"], config) == "shadow":
            # AC-3: a shadow repo is wholly in the WorkItem pipeline; its request never enters the legacy items
            key = ahc_shadow.queue_request(open_contracts(ledger, paths), norm)
            return {"id": key, "duplicate": False, "pipeline": "shadow"}
        with ledger.tx():
            if ledger.item(norm["id"]) is not None:
                return {"id": norm["id"], "duplicate": True}
            depth = ledger.db.execute("SELECT COUNT(*) FROM items WHERE state IN (%s)" % ",".join(
                "?" * len(NON_TERMINAL)), sorted(NON_TERMINAL)).fetchone()[0]
            if depth >= capacity:  # NEG-38
                raise core.Refused("the ahc queue is full: %d items waiting (capacity %d); try again later or ask "
                                   "main" % (depth, capacity))
            prefix = norm["repo"] + "|"
            recent = ledger.db.execute("SELECT COUNT(*) FROM items WHERE substr(lineage, 1, ?) = ? AND submitted > ?",
                                       (len(prefix), prefix, now - 3600)).fetchone()[0]
            lineage = "%s|%s" % (norm["repo"], norm["pr"])
            if len(ledger.head_budget(lineage, norm["head"])["reviewed"]) >= HEAD_REVIEW_LIMIT:  # N-T4
                raise core.Refused("review budget exhausted for this head: push a new head or ask main")
            if recent >= REPO_HOURLY_LIMIT:  # NEG-52
                raise core.Refused("%s already has %d submissions in the last hour (limit %d); try again later"
                                   % (norm["repo"], recent, REPO_HOURLY_LIMIT))
            ledger.db.execute(
                "INSERT INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, request, updated,"
                " entered_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (norm["id"], "%s|%s" % (norm["repo"], norm["pr"]), norm["owner"], norm["ticket"], "queued",
                 norm["submitted"], norm["submitted"], json.dumps(norm, sort_keys=True), now, norm["submitted"]))
            ledger.db.execute("INSERT OR IGNORE INTO lineage(lineage) VALUES (?)",
                              ("%s|%s" % (norm["repo"], norm["pr"]),))
            ledger.event(norm["id"], "accepted", now)
        _mirror(paths, norm["id"], "accepted", now, {})
        return {"id": norm["id"], "duplicate": False}
    finally:
        ledger.close()


def stage_packet(paths, stream, expect_sha=None):
    """`ahc submit --packet -` (adv-3 F2): read at most the packet cap from the stream, refuse anything larger or a
    SHA-256 that differs from --expect-sha, and write the bytes once to the private staging root as <sha>.md (0600,
    no-follow, never overwritten). Returns (path, sha)."""
    data = stream.read(core.PACKET_MAX_BYTES + 1)
    if len(data) > core.PACKET_MAX_BYTES:
        raise core.Refused("the packet on stdin is larger than %d bytes" % core.PACKET_MAX_BYTES)
    if not data:
        raise core.Refused("no packet bytes on stdin")
    sha = hashlib.sha256(data).hexdigest()
    if expect_sha is not None and expect_sha.strip().lower() != sha:
        raise core.Refused("the packet received has SHA-256 %s, not the expected %s; nothing was queued"
                           % (sha, expect_sha.strip()))
    paths.ensure()                       # ahc's own root first (marker); a foreign root refuses before any write
    target = paths.packets / (sha + ".md")
    crash_before("runner.stage_packet")
    try:
        fs.write_file(paths.root, target, data, exclusive=True, create_dirs=True)
    except FileExistsError:
        if core.read_regular(target, core.PACKET_MAX_BYTES) != data:
            raise core.Refused("a different staged packet already has this name; refusing") from None
        fs.touch(paths.root, target)  # restart the orphan clock so prune_packets cannot remove it before admission
        return target, sha
    crash_after("runner.stage_packet")
    return target, sha


def submit_with_lint(paths, config, req):
    """`ahc submit`: validate, lint synchronously (AC-25) and enqueue. Rejects with the lint tool's exact text."""
    norm = core.validate(config, req)
    raw = core.read_regular(norm["packet"], core.PACKET_MAX_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise core.Refused("the packet is not UTF-8") from None
    fix = ahc_packet.fix_packet(text, norm["head"], source_path=norm["packet"])
    if fix["status"] == "unfixable":
        import review_diagnostics
        raise core.Refused(review_diagnostics.render_lint(fix["problems"], "pr"))
    # r4 F3: the linted bytes are the hashed bytes; admission (cap, hourly limit, dedupe) is one transaction
    result = core.submit(paths, config, req, data=raw)
    result["packet_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def _setup_logging(paths):
    logdir = paths.home / ".agent-harness" / "logs"
    logdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = logging.handlers.RotatingFileHandler(str(logdir / "ahc.log"), maxBytes=8 * 1024 * 1024,
                                                   backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def build_parser():
    """The P0 CLI. It has no merge or `authority enable` subcommand (AC-31); those arrive only with P1/Gate 2."""
    parser = argparse.ArgumentParser(description="ahc coordinator (Gate 1: receipts only, never merges)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("submit", help="queue an exact-head PR receipt request")
    for name in ("--repo", "--head", "--base", "--packet", "--ticket", "--owner"):
        s.add_argument(name, required=True)
    s.add_argument("--pr", type=int, required=True)
    s.add_argument("--expect-sha", help="with --packet -: refuse unless the stdin bytes have this SHA-256")
    a = sub.add_parser("ack", help="owner acknowledges an item's notice, or records a D20 disposition")
    a.add_argument("item")
    a.add_argument("--owner", required=True)
    a.add_argument("--disposition", help="reason text: stop D20 escalation for this item (owner or verified main, "
                                         "per the state's rule)")
    w = sub.add_parser("w16", help="main only (stamped): move a WorkItem from waiting-ask, exhausted or "
                                    "waiting-dep back to pr-gate, or cancel it (AC-6)")
    w.add_argument("item")
    w.add_argument("--target", choices=("pr-gate", "cancelled"), required=True)
    w.add_argument("--expected-version", type=int, required=True)
    w.add_argument("--accept", default="", help="comma-separated finding ids accepted into --ticket")
    w.add_argument("--ticket")
    w.add_argument("--extension", type=int, default=0, help="extra B7 review rounds (pr-gate only)")
    sub.add_parser("status", help="item states, pending effects, the email route and the units")
    for name, text in (("install", "write and start the systemd user units ahc-core and ahc-review (t2-dev)"),
                       ("uninstall", "stop and remove the units; keep the ledger, clones and inbox")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--apply", action="store_true", help="make the changes (default: print what would change)")
    r = sub.add_parser("run", help="run ticks (the daemon loop; one systemd user unit per role)")
    r.add_argument("--role", choices=ROLES, default="all")
    r.add_argument("--once", action="store_true")
    r.add_argument("--interval", type=int, default=60)
    return parser


def claim_main(argv):
    """Take main's one-shot stamp for exactly this argument list, before anything parses it (so a failing or --help
    run still consumes it). True only for a disposition command that main's own hook stamped."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not core.is_dispose_argv(argv):
        return False
    try:
        import caller_identity  # noqa: PLC0415
        return caller_identity.take_stamp(core.DISPOSE_STAMP, core.dispose_stamp_parts(argv), bound=True,
                                          ttl=core.DISPOSE_STAMP_TTL,
                                          home=os.environ.get("AH_HOME") or None) is not None  # = mission_gate home
    except Exception:  # noqa: BLE001 - no proof is "not main", never an error that lets the claim through
        return False


def main(argv=None):
    main_proven = claim_main(argv)
    args = build_parser().parse_args(argv)
    paths = core.Paths()
    try:
        paths.claim_root()        # before reading anything under the root, for every subcommand
    except core.ForeignRoot as error:
        # Exit 3 is in the units' RestartPreventExitStatus, so a foreign root stops the unit instead of looping.
        # No `ah alert` here: the deps need ahc's own config, which a foreign root does not hold; the failed unit
        # and this line are what the operator sees.
        print("ahc: %s" % error, file=sys.stderr)
        return ROOT_EXIT
    config = load_config(paths)
    if args.cmd == "submit":
        req = {"repo": args.repo, "pr": args.pr, "head": args.head, "base": args.base, "packet": args.packet,
               "ticket": args.ticket, "owner": args.owner}
        try:
            if args.packet == "-":
                staged, _sha = stage_packet(paths, sys.stdin.buffer, args.expect_sha)
                req["packet"] = str(staged)
            elif args.expect_sha is not None:
                raise core.Refused("--expect-sha applies only to --packet -")
            print(json.dumps(submit_with_lint(paths, config, req)))
        except core.Refused as error:
            print("refused: %s" % error, file=sys.stderr)
            return 2
        return 0
    if args.cmd == "ack":
        try:
            count = ack(paths, args.item, args.owner, disposition=args.disposition, main_proven=main_proven,
                        config=config)
            print("disposition recorded" if args.disposition is not None else "acknowledged %d notice(s)" % count)
        except core.Refused as error:
            print("refused: %s" % error, file=sys.stderr)
            return 2
        return 0
    if args.cmd == "w16":
        try:
            row = w16(paths, list(sys.argv[1:] if argv is None else argv), main_proven=main_proven, item=args.item,
                      target=args.target, expected_version=args.expected_version,
                      accept=[a for a in args.accept.split(",") if a], ticket=args.ticket, extension=args.extension)
            print("%s %s version %d" % (row["id"], row["state"], row["version"]))
        except core.Refused as error:
            print("refused: %s" % error, file=sys.stderr)
            return 2
        return 0
    if args.cmd in ("install", "uninstall"):
        import ahc_install  # noqa: PLC0415
        action = ahc_install.install if args.cmd == "install" else ahc_install.uninstall
        return action(paths, paths.home, args.apply)
    if args.cmd == "status":
        import ahc_install  # noqa: PLC0415
        for unit, state in ahc_install.unit_states().items():
            print("unit %s: %s" % (unit, state))
        ledger = Ledger(paths, migrate=False)
        try:
            for row in ledger.db.execute("SELECT id, state, next_action_at, request FROM items ORDER BY submitted"):
                req = json.loads(row["request"])
                print("%s %-18s %s#%s %s next=%s" % (row["id"], row["state"], req["repo"], req["pr"], req["head"][:12],
                                                    row["next_action_at"]))
            pending = ledger.db.execute("SELECT COUNT(*) AS n FROM effects WHERE status IN ('pending', 'intent')"
                                        ).fetchone()["n"]
            print("pending effects: %d" % pending)
            import ahc_shadow  # noqa: PLC0415
            for line in ahc_shadow.status_lines(open_contracts(ledger, paths)):
                print(line)
            route = ledger.db.execute("SELECT k, v FROM meta WHERE k IN ('email_route', 'email_route_reason')")
            route = {row["k"]: row["v"] for row in route}
            print("email route: %s%s" % (route.get("email_route", "not checked"),
                                         " (%s)" % route["email_route_reason"] if route.get("email_route_reason")
                                         else ""))
            for row in ledger.db.execute("SELECT item, status, result, payload FROM effects WHERE kind='mail' AND "
                                         "status != 'cancelled' ORDER BY updated DESC LIMIT 20"):
                print("mail %s %s %s: %s" % (row["item"], json.loads(row["payload"]).get("alert_key"), row["status"],
                                             row["result"] or "awaiting receipt"))
        finally:
            ledger.close()
        return 0
    lock = acquire_lock(paths, args.role)
    if lock is None:
        print("ahc: another instance holds the %s lock; exiting" % args.role, file=sys.stderr)
        return LOCKED_OUT_EXIT
    _setup_logging(paths)
    import ahc_guard  # noqa: PLC0415
    # AC-13: the daemon process enforces its launch, socket and import policy from here on
    # gh authenticates from its own config under HOME; the unit sets no gh credential variable, so the gh
    # form carries none (ASSUMPTION)
    policy = ahc_guard.install(ahc_guard.Policy(paths.root, repos=config.get("repos", []), home=paths.home))
    log.info("startup reconciliation %s", json.dumps(startup_reconcile(paths, policy), default=str))
    deps = LiveDeps(paths, config)
    while True:
        try:
            summary = tick(paths, config, deps, role=args.role)
        except SchemaError as error:
            log.error("schema refusal: %s", error)
            print("ahc: %s" % error, file=sys.stderr)
            deps.ah(["ah", "alert", "raise", "--alert-key", "ahc-schema", "--source", "ahc", "--severity", "high",
                     "--message", "ahc refused to start: " + _short(error)], 60)
            return SCHEMA_EXIT  # the unit does not restart on it (RestartPreventExitStatus), so no backup loop
        log.info("tick %s", json.dumps(summary, default=str))
        if args.once:
            print(json.dumps(summary, default=str))
            return 0
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    sys.exit(main())
