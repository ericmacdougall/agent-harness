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
      `intent` is never relaunched: it goes to needs-attention for usage_guard reconciliation;
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
import ahc_packet  # noqa: E402
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
                        "dispose": ("owner", "main")},
    "refused": {"settled": True, "waits_on": "owner", "cover": "ack", "alert": True, "notice": True},
    "lint-failed": {"settled": True, "waits_on": "owner", "cover": "ack", "alert": True, "notice": True},
    "review-error": {"settled": True, "waits_on": "owner", "cover": "ack", "alert": True, "notice": True},
    "stale-head": {"settled": True, "waits_on": "owner", "cover": "ack", "notice": True},
    "blocked": {"settled": True, "waits_on": "owner", "cover": "ack", "notice": True},
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


def retry_policy(failure_class, attempts, now, retry_at=None, first_at=None, config=None):
    """(state, next_action_at) for a failure. `attempts` counts this class's failures so far, this one included;
    `first_at` is when this class first failed for the item (for the 24 h quota deadline). Bounds come from D19.

    gh-transient        live PR read failed: capped exponential backoff, then needs-attention after 8
    pre-provider        clone or other deterministic repair: at most pre_provider_runs (2), then needs-attention
    provider-transient  peer_review already used its primary and fallback: one deferred retry, then review-error
    invalid-output      reviewer output unusable for a reason outside the packet: one declared repeat when
                        invalid_output_repeat is on, then the owner; never a second repeat
    quota               durable retry_at from the reset time (default 1 h), no probing; needs-attention once the
                        quota deadline (24 h from the first quota failure) passes
    auth                opens the provider circuit; never retried on a timer
    contention          pool busy (REVIEW_NOT_STARTED on a held pool): wait; waiting is not an attempt
    unknown-outcome     launch or supervision outcome unknown: needs-attention until usage_guard reconciliation
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
        return ("deferred", now + 900) if attempts <= 1 else ("review-error", None)
    if failure_class == "invalid-output":
        if limits["invalid_output_repeat"] and attempts <= 1:
            return "deferred", now + 60
        return "review-error", None
    if failure_class == "quota":
        if first_at is not None and now - first_at >= limits["quota_auth_deadline_seconds"]:
            return "needs-attention", None
        return "deferred", max(now + 60, retry_at or now + 3600)
    if failure_class == "auth":
        return "needs-attention", None
    if failure_class == "contention":
        return "deferred", now + 120
    if failure_class in ("advisory", "inconsistent"):
        return "review-error", None
    if failure_class in ("unknown-outcome", "environment"):
        return "needs-attention", None
    if failure_class == "block":
        return "blocked", None
    if failure_class == "stale":
        return "stale-head", None
    if failure_class == "delivery":
        return "pending", now + min(60 * 2 ** max(attempts - 1, 0), limits["delivery_backoff_cap_seconds"])
    raise ValueError("unknown failure class: " + str(failure_class))


TRANSIENT_CODES = {"PROVIDER_UNAVAILABLE", "PROVIDER_TIMEOUT", "BUDGET_EXHAUSTED", "REVIEW_NOT_STARTED",
                   "SNAPSHOT_TIMEOUT", "SNAPSHOT_SOURCE_CHANGED", "SNAPSHOT_GIT_FAILED"}
UNKNOWN_CODES = {"REVIEW_LAUNCH_UNCONFIRMED", "PROVIDER_IO_UNKNOWN", "ISOLATION_FAILED"}
CONTENTION = re.compile(r"\b(?:pool|reservation|reserved|cooldown|held by)\b", re.I)


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
  entered_at REAL, esc_n INTEGER NOT NULL DEFAULT 0, esc_at REAL, disposed_at REAL);
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


SCHEMA_VERSION = 2
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
MIGRATIONS = {1: [], 2: [_migrate_v2]}


class SchemaError(RuntimeError):
    """The ledger's schema is unknown or newer than this code; the daemon must not start."""


class Ledger:
    def __init__(self, paths):
        paths.ensure()
        self.paths = paths
        self.path = paths.root / "ledger.sqlite3"
        fresh = not self.path.exists()
        self.db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self._schema(fresh)
        except Exception:
            self.db.close()
            raise
        os.chmod(self.path, 0o600)

    def _version(self):
        has_meta = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
        if not has_meta:
            has_items = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'").fetchone()
            return 0 if has_items else None
        row = self.db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        if row is None:
            return 0
        try:
            return int(row["v"])
        except (TypeError, ValueError):
            raise SchemaError("unreadable schema_version %r in %s" % (row["v"], self.path)) from None

    def _schema(self, fresh):
        version = None if fresh else self._version()
        if version is None:
            with self.tx():
                for statement in _statements(SCHEMA):
                    self.db.execute(statement)
                self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)",
                                (str(SCHEMA_VERSION),))
            return
        if version > SCHEMA_VERSION or version < 0:
            raise SchemaError("ledger schema_version %d is not supported by this ahc (knows %d); refusing to start"
                              % (version, SCHEMA_VERSION))
        if version == SCHEMA_VERSION:
            return
        copy = self.backup("pre-v%d" % SCHEMA_VERSION)
        try:
            with self.tx():
                for step in range(version + 1, SCHEMA_VERSION + 1):
                    if step == 1:
                        for statement in _statements(SCHEMA):
                            self.db.execute(statement)
                    for statement in MIGRATIONS[step]:
                        statement(self.db) if callable(statement) else self.db.execute(statement)
                self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)",
                                (str(SCHEMA_VERSION),))
        except Exception as error:
            aside = self.restore(copy)
            raise SchemaError("ledger migration v%d->v%d failed (%s); restored the verified backup %s and moved the "
                              "failed database files aside as %s" % (version, SCHEMA_VERSION, type(error).__name__,
                                                                      copy.name, ", ".join(aside))) from error

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
        copy = sqlite3.connect(str(target))
        try:
            self.db.backup(copy)
            check = copy.execute("PRAGMA integrity_check").fetchall()
            source, copied = self._counts(self.db), self._counts(copy)
        finally:
            copy.close()
        os.chmod(target, 0o600)
        if [tuple(row) for row in check] != [("ok",)] or source != copied:
            raise SchemaError("ledger backup %s failed verification (integrity %r, rows %r vs %r); not migrating"
                              % (target.name, [tuple(r) for r in check][:3], source, copied))
        return target

    def restore(self, copy):
        """Put the verified backup back after a failed migration. The live database, -wal and -shm files are moved
        aside together under one suffix (never deleted), then the backup is copied into place. Returns the moved
        names. The connection is reopened on the restored file."""
        self.db.close()
        suffix = ".failed-%d" % time.time_ns()
        moved = []
        for extra in ("", "-wal", "-shm"):
            source = Path(str(self.path) + extra)
            if os.path.lexists(str(source)):
                target = Path(str(self.path) + suffix + extra)
                os.rename(str(source), str(target))
                moved.append(target.name)
        shutil.copyfile(str(copy), str(self.path))
        os.chmod(self.path, 0o600)
        self.db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        return moved

    def close(self):
        self.db.close()

    def tx(self):
        return _Tx(self.db)

    def item(self, iid):
        return self.db.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()

    def ensure_item(self, iid, config, now=None):
        """Accept the queued request into the ledger (I1) after re-validating it (r2 F5). Returns the row, None if
        no request file exists, or raises core.Refused for a record that must be quarantined."""
        row = self.item(iid)
        if row is not None:
            return row
        qfile = self.paths.queue / (iid + ".json")
        try:
            text = core.read_regular(qfile, core.PACKET_MAX_BYTES).decode("utf-8")
        except core.Unreadable as error:
            if error.kind == "absent":
                return None
            raise core.Refused("queue file unreadable: %s" % error) from None
        except UnicodeDecodeError:
            raise core.Refused("queue file is not UTF-8") from None
        try:
            raw = json.loads(text)
        except ValueError:
            raise core.Refused("queue file is not valid JSON") from None
        req = core.validate_queued(config, raw, now if now is not None else time.time())
        if req["id"] != iid:
            raise core.Refused("queue file name does not match its id")
        with self.tx():
            self.db.execute(
                "INSERT OR IGNORE INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, request,"
                " updated, entered_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (iid, "%s|%s" % (req["repo"], req["pr"]), req["owner"], req["ticket"], "queued",
                 req["submitted"], req["submitted"], json.dumps(req, sort_keys=True), time.time(), req["submitted"]))
            self.db.execute("INSERT OR IGNORE INTO lineage(lineage) VALUES (?)", ("%s|%s" % (req["repo"], req["pr"]),))
            self.db.execute("INSERT INTO events(item, event, at, data) VALUES (?,?,?,?)",
                            (iid, "accepted", time.time(), "{}"))
        return self.item(iid)

    def event(self, iid, event, at, **data):
        self.db.execute("INSERT INTO events(item, event, at, data) VALUES (?,?,?,?)",
                        (iid, event, at, json.dumps(data, sort_keys=True, default=str)))

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
        self.db.execute("COMMIT" if kind is None else "ROLLBACK")
        return False


class Journal:
    """Facade over the ledger for one item: `state()`, `append(event, **data)`, and `path`, a human-readable JSONL
    mirror of the item's events (audit only; state is never read from it, so a torn line cannot change state)."""

    def __init__(self, paths, iid):
        self.paths, self.iid = paths, iid
        self.path = paths.items / (iid + ".jsonl")

    def state(self):
        ledger = Ledger(self.paths)
        try:
            row = ledger.item(self.iid)
            return row["state"] if row else None
        finally:
            ledger.close()

    def append(self, event, **data):
        ledger = Ledger(self.paths)
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
        _append_private(paths.items / (iid + ".jsonl"),
                        json.dumps({"event": event, "at": at, **data}, sort_keys=True, default=str) + "\n")
    except OSError:
        log.warning("journal mirror write failed for %s", iid)


def acquire_lock(paths):
    """Single instance: an exclusive non-blocking flock. Returns the open handle, or None when another holds it."""
    paths.ensure()
    handle = os.fdopen(_open_private(paths.root / "ahc.lock", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
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
            cur = self.led.db.execute(
                "UPDATE items SET entered_at=CASE WHEN state=? THEN COALESCE(entered_at, ?) ELSE ? END, state=?,"
                " next_action_at=?, data=?, updated=? WHERE id=? AND lease_token=?",
                (state, now, now, state, next_action_at if state in NON_TERMINAL else None,
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
            lattempts = json.loads(lin["attempts"]) if lin else {}
            lattempts[failure_class] = lattempts.get(failure_class, 0) + 1
            self.led.db.execute("INSERT OR REPLACE INTO lineage(lineage, attempts, block_rounds) VALUES (?, ?, "
                                "COALESCE((SELECT block_rounds FROM lineage WHERE lineage=?), 0))",
                                (row["lineage"], json.dumps(lattempts), row["lineage"]))
        return attempts[failure_class]

    def fail(self, iid, token, failure_class, reason, retry_at=None, **data):
        count = self.bump(iid, failure_class) if failure_class != "contention" else 0  # waiting is not an attempt
        first_key = "first_" + failure_class.replace("-", "_") + "_at"
        first_at = json.loads(self.led.item(iid)["data"]).get(first_key, self.now())
        data.setdefault(first_key, first_at)
        state, next_at = retry_policy(failure_class, count, self.now(), retry_at, first_at=first_at,
                                      config=self.config)
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
        _write_private(fixed_path, fix["text"])
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
        report = self.paths.reports / ("%s-a%d.md" % (iid, attempt))
        if os.path.lexists(str(report)):
            reason = "report path already exists; refusing to overwrite a receipt"
            return self.settle(iid, token, "needs-attention", event="report-path-taken", reason=reason,
                               notice=_owner_notice("needs-attention", reason))
        argv = [sys.executable, str(self.config.get("peer_review", Path.home() / ".claude/hooks/peer_review.py")),
                "pr", "--repo", clone, "--packet", str(fixed_path), "--output", str(report),
                "--expected-head", facts["head"], "--snapshot-base", merge_base, "--base", merge_base,
                "--timeout", str(REVIEW_TIMEOUT), "--owner", "ahc"]
        if attempt > 1 and prior:
            argv += ["--repeat-reason", prior]
        key = "review:%s:%d" % (iid, attempt)
        now = self.now()
        with self.led.tx():  # I4: intent before dispatch
            self.led.db.execute("INSERT INTO effects(key, item, kind, status, attempts, next_action_at, payload,"
                                " updated) VALUES (?,?,?,?,?,?,?,?)",
                                (key, iid, "review", "intent", 1, None, json.dumps({"argv": argv}), now))
        self.settle(iid, token, "reviewing", now + REVIEW_WALL, report=str(report), packet=str(fixed_path),
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

    def conclude(self, iid, token, req, key):
        row = self.led.item(iid)
        data = json.loads(row["data"])
        effect = self.led.db.execute("SELECT * FROM effects WHERE key=?", (key,)).fetchone()
        result = json.loads(effect["result"])
        verdict = core.verify_receipt(result["rc"], data["report"], req["head"], data["packet"])
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
            self.settle(iid, token, "blocked", event="blocked", verdict="BLOCK",
                        notice=_owner_notice("blocked", _report_body(data["report"])))
            return "blocked"
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
        self.settle(iid, token, "needs-attention", event="review-outcome-unknown", reason=reason,
                    notice=_owner_notice("needs-attention", reason))
        return "needs-attention"

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

    def _d20_stop(self, row, req):
        """Why D20 (and an unacked notice's escalation) stops for this item without a disposition, or None: a newer submission for the same PR, or the
        PR read as MERGED or CLOSED. A failed or unreadable read is None (keep escalating)."""
        newer = self.led.db.execute("SELECT id FROM items WHERE lineage=? AND submitted > ? AND id != ? "
                                    "ORDER BY submitted DESC LIMIT 1",
                                    (row["lineage"], row["submitted"], row["id"])).fetchone()
        if newer is not None:
            return "superseded by %s" % newer["id"]
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
            "SELECT * FROM effects WHERE kind != 'review' AND status IN ('pending', 'intent') AND next_action_at <= ?"
            " ORDER BY next_action_at, key", (now,)).fetchall()
        for row in rows:
            payload = json.loads(row["payload"])
            if row["kind"] == "mail":
                self.check_mail(row, payload, now)
                continue
            if row["kind"] == "alert" and payload.get("severity") == "critical":
                self._note_raise(row["key"], now)
            if row["status"] == "intent" and self.readback(row["kind"], payload):
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
                    self._insert_effect("clear:" + payload["undelivered_key"], iid, "clear",
                                        {"alert_key": payload["undelivered_key"],
                                         "key": "ahc-clear-" + payload["undelivered_key"]}, now)
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
                    _append_private(self.paths.digest, payload["line"])
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
        try:
            ledger.ensure_item(qfile.stem, config, now)
        except Exception as error:  # noqa: BLE001 - any per-file failure is quarantined, never fatal to the tick
            reason = str(error) if isinstance(error, core.Refused) else "ingest error: %s" % type(error).__name__
            try:
                if ledger.db.in_transaction:
                    ledger.db.rollback()
            except Exception:  # noqa: BLE001
                pass
            moved = _quarantine(paths, qfile, reason)
            # an unmovable file is skipped and reported again next tick under the same deterministic alert key
            rejected.append((moved or qfile.name, reason if moved else reason + "; quarantine move failed"))
    return rejected


def _quarantine(paths, qfile, reason):
    """Atomically rename the queue entry itself (a symlink is moved, never followed) into rejected/, with a reason
    file. Returns the quarantined name, which keys the one alert for it, or None if it could not be moved."""
    target_dir = paths.root / "rejected"
    try:
        target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = target_dir / qfile.name
        if os.path.lexists(str(target)):
            target = target_dir / ("%s.%d.json" % (qfile.stem, time.time_ns()))
        os.rename(str(qfile), str(target))  # same filesystem: atomic; renames the link, not its referent
        _write_private(target.with_name(target.name + ".reason"), redact.redact(reason) + "\n")
        return target.name
    except OSError as error:
        log.warning("could not quarantine %s: %s", qfile.name, type(error).__name__)
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


def tick(paths, config, deps):
    """One reconcile pass. Returns a summary dict. Raises nothing for item-level failures."""
    ledger = Ledger(paths)
    worker = Worker(paths, config, deps, ledger)
    summary = {"processed": [], "recovered": [], "defects": [], "rejected": []}
    try:
        summary["email_route"] = "ready" if worker.email_route() else "unavailable"
        summary["rejected"] = ingest(ledger, paths, config, worker.now())
        for name, reason in summary["rejected"]:
            message = "ahc rejected queue file %s: %s (moved to coordinator/rejected/)" % (name, reason)
            try:
                rc, _out, _err = deps.ah(["ah", "alert", "raise", "--severity", "high", "--alert-key",
                                          "ahc:rejected:" + name, "--source", "ahc", "--key", "ahc-rejected-" + name,
                                          "--message", redact.redact(message)[:500]], 60)
                if rc != 0:
                    log.warning("rejection alert for %s exited %s; the reason file in rejected/ remains", name, rc)
            except Exception:  # noqa: BLE001 - the file is already quarantined with its reason; the alert is best effort
                log.warning("rejection alert failed for %s; the reason file in rejected/ remains", name)
        for row in ledger.db.execute("SELECT * FROM items WHERE state='reviewing'").fetchall():
            summary["recovered"].append((row["id"], worker.recover(row)))
        supersede(worker)
        now = worker.now()
        due = ledger.db.execute("SELECT * FROM items WHERE state IN ('queued', 'deferred', 'routed-to-main') "
                                "AND next_action_at <= ? ORDER BY next_action_at, submitted, id", (now,)).fetchall()
        reviewed = False
        for row in due:
            if row["state"] != "routed-to-main" and reviewed:
                continue  # one review per tick on this host (D7)
            current = ledger.item(row["id"])
            if current["state"] != row["state"]:
                continue
            outcome = worker.process(current)
            summary["processed"].append((row["id"], outcome))
            if row["state"] != "routed-to-main" and ledger.db.execute(
                    "SELECT 1 FROM effects WHERE item=? AND kind='review'", (row["id"],)).fetchone():
                reviewed = True
        worker.escalate()
        worker.escalate_overdue()
        worker.dispatch_effects()
        missing = ledger.db.execute("SELECT id FROM items WHERE state IN ('queued','deferred','reviewing',"
                                    "'routed-to-main') AND next_action_at IS NULL").fetchall()
        summary["defects"] = ["I2: %s has no next_action_at" % row["id"] for row in missing]
    except _Stop:
        summary["stopped"] = True
    finally:
        ledger.close()
    try:
        deps.ah(["ah", "heartbeat", "beat", "--service", "ahc"], 30)
    except Exception:  # noqa: BLE001 - a heartbeat failure is visible to the observer as a stale beat
        log.warning("heartbeat failed")
    return summary


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
    ledger = Ledger(paths)
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
                ledger.event(iid, "acked", now, owner=owner, notices=cur.rowcount)
                if row["state"] not in D20_STATES or row["disposed_at"] is not None:
                    Worker(paths, config or {}, deps, ledger)._clear_criticals(iid, now)
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

def _short(value, limit=300):
    return redact.redact(str(value)).replace("\n", " ")[:limit]


def _is_protected(path):
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, pattern) for pattern in PROTECTED) or path.startswith(".claude/")


def _report_body(report_path):
    try:
        text = core.read_regular(report_path, core.REPORT_MAX_BYTES).decode("utf-8", errors="replace")
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
        "blocked": "Fix the findings, push, then submit again at the new head with a fresh packet.",
        "lint-failed": "Fix the packet layout or add the missing evidence, then submit again. The fixer never adds "
                       "an exit status or a count.",
        "stale-head": "The PR head moved. Submit again at the new head with a fresh packet.",
        "refused": "Correct the request and submit again.",
        "review-error": "No receipt was produced. Read the reason; a quota or provider outage is retried by the "
                        "daemon, anything else needs you.",
        "needs-attention": "The daemon stopped automatic work on this item. Read the reason and resubmit or ask main.",
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
    try:
        root_fd = os.open(str(inbox), _DIR_FLAGS)
    except OSError as error:
        raise _InboxRefused("inbox directory is not a real directory: %s" % type(error).__name__) from None
    try:
        try:
            os.mkdir(owner, 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        try:
            owner_fd = os.open(owner, _DIR_FLAGS, dir_fd=root_fd)
        except OSError as error:
            raise _InboxRefused("owner inbox is not a real directory: %s" % type(error).__name__) from None
        try:
            present = _notice_state(owner_fd, name, text)
            if present == "match":
                return  # already delivered with exactly this content
            if present != "absent":
                raise _InboxRefused("notice name is occupied by a %s entry" % present)
            tmp = "." + name + ".tmp"
            try:
                os.unlink(tmp, dir_fd=owner_fd)
            except FileNotFoundError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
                         dir_fd=owner_fd)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(tmp, name, src_dir_fd=owner_fd, dst_dir_fd=owner_fd)
        finally:
            os.close(owner_fd)
    finally:
        os.close(root_fd)


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


def _write_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + ".tmp")
    fd = _open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _append_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = _open_private(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


# ---------------------------------------------------------------- live dependencies

class LiveDeps:
    """The production children. Every call is an argv list with a timeout; nothing goes through a shell."""

    def __init__(self, paths, config):
        self.paths, self.config = paths, config

    def clock(self):
        return time.time()

    def _run(self, argv, timeout):
        return core.run_argv(argv, timeout)

    def gh(self, argv, timeout):
        return self._run(argv, min(timeout, core.TIMEOUTS["gh"]))

    def ah(self, argv, timeout):
        script = str(self.config.get("ah", Path.home() / ".claude/hooks/ah.py"))
        return self._run([sys.executable, script] + list(argv[1:]), min(timeout, core.TIMEOUTS["ah"]))

    def review(self, argv, timeout):
        rc, _out, err = self._run(argv, timeout)
        return rc, err

    def ops_watch(self, argv, timeout):
        """Read-only ops-watch queries only: capabilities, config (emptiness of sinks.deadman), delivered."""
        if not argv or argv[0] not in ("capabilities", "config", "delivered"):
            raise ValueError("ops_watch: only read-only queries")
        script = str(self.config.get("ops_watch", Path.home() / ".claude/hooks/ops_watch.py"))
        return self._run([sys.executable, script] + list(argv), min(timeout, OPS_WATCH_TIMEOUT))

    def clone(self, repo, head, base):
        import ahc_clone
        floor = int(self.config.get("disk_floor_bytes", 20 * 1024 ** 3))
        if shutil.disk_usage(str(self.paths.clones)).free < floor:
            raise RuntimeError("disk floor: less than %d GiB free for clones" % (floor // 1024 ** 3))
        url = self.config.get("clone_urls", {}).get(repo, "https://github.com/%s.git" % repo)
        return ahc_clone.prepare(self.paths.clones, repo, url, head, base)

    def merge_base(self, clone, head, base):
        import ahc_clone
        return ahc_clone._git(["merge-base", head, base], cwd=clone).stdout.strip()

    def changed_paths(self, clone, merge_base, head):
        import ahc_clone
        out = ahc_clone._git(["diff", "--name-only", "--no-renames", "-z", merge_base, head], cwd=clone).stdout
        return [p for p in out.split("\0") if p]


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
    return config


def submit_with_lint(paths, config, req):
    """`ahc submit`: validate, lint synchronously (AC-25) and enqueue. Rejects with the lint tool's exact text."""
    norm = core.validate(config, req)
    capacity = int(bounds(config)["queue_capacity"])
    ledger = Ledger(paths)
    try:
        ingest(ledger, paths, config)
        raw = core.read_regular(norm["packet"], core.PACKET_MAX_BYTES)
        existing = ledger.item(core.item_id(norm, hashlib.sha256(raw).hexdigest()))
        depth = ledger.db.execute("SELECT COUNT(*) AS n FROM items WHERE state IN (%s)" % ",".join(
            "?" * len(NON_TERMINAL)), sorted(NON_TERMINAL)).fetchone()["n"]
    finally:
        ledger.close()
    if existing is None and depth >= capacity:  # NEG-38; a duplicate resubmit stays a no-op
        raise core.Refused("the ahc queue is full: %d items waiting (capacity %d); try again later or ask main"
                           % (depth, capacity))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise core.Refused("the packet is not UTF-8") from None
    fix = ahc_packet.fix_packet(text, norm["head"], source_path=norm["packet"])
    if fix["status"] == "unfixable":
        import review_diagnostics
        raise core.Refused(review_diagnostics.render_lint(fix["problems"], "pr"))
    return core.submit(paths, config, req, data=raw)   # r4 F3: the linted bytes are the hashed bytes


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
    a = sub.add_parser("ack", help="owner acknowledges an item's notice, or records a D20 disposition")
    a.add_argument("item")
    a.add_argument("--owner", required=True)
    a.add_argument("--disposition", help="reason text: stop D20 escalation for this item (owner or verified main, "
                                         "per the state's rule)")
    sub.add_parser("status", help="item states and pending effects")
    r = sub.add_parser("run", help="run ticks (the daemon loop under launchd)")
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
    config = load_config(paths)
    if args.cmd == "submit":
        req = {"repo": args.repo, "pr": args.pr, "head": args.head, "base": args.base, "packet": args.packet,
               "ticket": args.ticket, "owner": args.owner}
        try:
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
    if args.cmd == "status":
        ledger = Ledger(paths)
        try:
            for row in ledger.db.execute("SELECT id, state, next_action_at, request FROM items ORDER BY submitted"):
                req = json.loads(row["request"])
                print("%s %-18s %s#%s %s next=%s" % (row["id"], row["state"], req["repo"], req["pr"], req["head"][:12],
                                                    row["next_action_at"]))
            pending = ledger.db.execute("SELECT COUNT(*) AS n FROM effects WHERE status IN ('pending', 'intent')"
                                        ).fetchone()["n"]
            print("pending effects: %d" % pending)
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
    lock = acquire_lock(paths)
    if lock is None:
        print("ahc: another instance holds the lock; exiting")
        return 0
    _setup_logging(paths)
    deps = LiveDeps(paths, config)
    while True:
        try:
            summary = tick(paths, config, deps)
        except SchemaError as error:
            log.error("schema refusal: %s", error)
            print("ahc: %s" % error, file=sys.stderr)
            deps.ah(["ah", "alert", "raise", "--alert-key", "ahc-schema", "--source", "ahc", "--severity", "high",
                     "--message", "ahc refused to start: " + _short(error)], 60)
            return 3
        log.info("tick %s", json.dumps(summary, default=str))
        if args.once:
            print(json.dumps(summary, default=str))
            return 0
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    sys.exit(main())
