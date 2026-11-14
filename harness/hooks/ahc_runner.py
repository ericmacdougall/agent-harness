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

TERMINAL = {"refused", "lint-failed", "stale-head", "superseded", "review-error", "needs-attention", "blocked",
            "merged", "closed"}
NON_TERMINAL = {"queued", "deferred", "reviewing", "routed-to-main"}
ALERT_STATES = {"refused", "lint-failed", "review-error", "needs-attention"}  # terminal-unsuccessful (D14)
OWNER_NOTICE_STATES = {"refused", "lint-failed", "stale-head", "review-error", "needs-attention", "blocked"}
REVIEW_TIMEOUT = 720                     # per provider, peer_review's cap
REVIEW_WALL = core.TIMEOUTS["review"]    # primary plus one fallback (D21)
LEASE_SECONDS = REVIEW_WALL + 60         # lease = timeout + 60 s; a reclaim mints a new fencing token
PASS_RECHECK = 3600             # routed-to-main: re-read the PR this often
ROUTED_FIRST = 4 * 3600         # D20: ticket escalation 4 h after routing to main ...
ROUTED_REPEAT = 24 * 3600       # ... then every 24 h while it still waits
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
    return "environment", code   # EXEC_*, other SNAPSHOT_*, PYTHON_UNSUPPORTED: a local defect, not a retry


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
  attempts TEXT NOT NULL DEFAULT '{}', request TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', updated REAL);
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


SCHEMA_VERSION = 1
# Forward-only migrations: MIGRATIONS[n] takes a database at version n-1 to version n. Version 0 is a ledger written
# before schema_version existed (same tables). Each runs inside one transaction after a file copy (spec v14, NEG-37).
MIGRATIONS = {1: []}


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
        self.backup("pre-v%d" % SCHEMA_VERSION)
        with self.tx():
            for step in range(version + 1, SCHEMA_VERSION + 1):
                if step == 1:
                    for statement in _statements(SCHEMA):
                        self.db.execute(statement)
                for statement in MIGRATIONS[step]:
                    self.db.execute(statement)
            self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)",
                            (str(SCHEMA_VERSION),))

    def backup(self, label):
        """Copy the whole database (SQLite online backup) before a migration; returns the copy path."""
        target = self.path.with_name("%s.%s.%d.bak" % (self.path.name, label, int(time.time())))
        copy = sqlite3.connect(str(target))
        try:
            self.db.backup(copy)
        finally:
            copy.close()
        os.chmod(target, 0o600)
        return target

    def close(self):
        self.db.close()

    def tx(self):
        return _Tx(self.db)

    def item(self, iid):
        return self.db.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()

    def ensure_item(self, iid):
        """Accept the queued request into the ledger (I1). Returns the row, or None if no request exists."""
        row = self.item(iid)
        if row is not None:
            return row
        qfile = self.paths.queue / (iid + ".json")
        try:
            req = json.loads(qfile.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(req, dict) or req.get("id") != iid:
            return None
        with self.tx():
            self.db.execute(
                "INSERT OR IGNORE INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, request,"
                " updated) VALUES (?,?,?,?,?,?,?,?,?)",
                (iid, "%s|%s" % (req["repo"], req["pr"]), req["owner"], req["ticket"], "queued",
                 float(req.get("submitted") or 0), float(req.get("submitted") or 0), json.dumps(req, sort_keys=True),
                 time.time()))
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
            if ledger.ensure_item(self.iid) is None:
                raise KeyError("no such item: " + self.iid)
            now = time.time()
            with ledger.tx():
                if event in TERMINAL or event in NON_TERMINAL:
                    row = ledger.item(self.iid)
                    merged = dict(json.loads(row["data"]), **data)
                    ledger.db.execute("UPDATE items SET state=?, data=?, updated=? WHERE id=?",
                                      (event, json.dumps(merged, sort_keys=True), now, self.iid))
                ledger.event(self.iid, event, now, **data)
            _mirror(self.paths, self.iid, event, now, data)
        finally:
            ledger.close()


def _mirror(paths, iid, event, at, data):
    try:
        paths.items.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(paths.items / (iid + ".jsonl"), "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"event": event, "at": at, **data}, sort_keys=True, default=str) + "\n")
    except OSError:
        log.warning("journal mirror write failed for %s", iid)


def acquire_lock(paths):
    """Single instance: an exclusive non-blocking flock. Returns the open handle, or None when another holds it."""
    paths.ensure()
    handle = open(paths.root / "ahc.lock", "a")
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
                "UPDATE items SET state=?, next_action_at=?, data=?, updated=? WHERE id=? AND lease_token=?",
                (state, next_action_at if state in NON_TERMINAL else None, json.dumps(merged, sort_keys=True,
                                                                                       default=str), now, iid, token))
            if cur.rowcount != 1:
                raise Fenced(iid)
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
        try:
            text = Path(req["packet"]).read_bytes()
        except OSError:
            return self.refuse(iid, token, "the submitted packet can no longer be read")
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
        if report.exists():
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
        routed_at = float(data.get("routed_at", now))
        last = data.get("routed_escalated_at")
        due = (now - routed_at >= ROUTED_FIRST) if last is None else (now - float(last) >= ROUTED_REPEAT)
        if due:
            count = int(data.get("routed_escalations", 0)) + 1
            notice_state = "routed-overdue-%d" % count
            body = ("Routed to main (%s) for %s#%s at %s; still waiting after %d h.\nReceipt: %s\nMain runs: %s"
                    % (data.get("routed_reason", "pass-gate1"), req["repo"], req["pr"], req["head"],
                       int((now - routed_at) // 3600), data.get("report"), merge_command(req)))
            self.settle(iid, token, "routed-to-main", now + PASS_RECHECK, event="routed-escalated",
                        routed_escalated_at=now, routed_escalations=count,
                        notice={"state": notice_state, "audience": "user", "body": body, "requires_ack": False})
            return "routed-to-main"
        return self.settle(iid, token, "routed-to-main", now + PASS_RECHECK, event="recheck")


    def circuit_open(self):
        return self.led.db.execute("SELECT 1 FROM circuits WHERE provider='review'").fetchone() is not None

    # --- notices and effects
    def _insert_notice(self, iid, req, state, audience, body, requires_ack, now):
        """Insert one notice and its effects; the caller holds the transaction. One notice per (item, state)
        (NEG-34). Effects: ticket comment always; owner inbox for owner notices; a high alert (v15 sink: dashboard,
        and email through the GoodQA deadman route) for user-audience notices and terminal-unsuccessful states;
        the digest as a courtesy copy for main."""
        nkey = "%s:%s" % (iid, state)
        body = redact.redact(body)
        cur = self.led.db.execute(
            "INSERT OR IGNORE INTO notices(key, item, state, audience, requires_ack, deadline, created)"
            " VALUES (?,?,?,?,?,?,?)",
            (nkey, iid, state, audience, int(requires_ack),
             now + bounds(self.config)["block_ack_seconds"] if requires_ack else None, now))
        if cur.rowcount != 1:
            return
        effects = [("ticket", {"ticket": req["ticket"], "body": body, "key": "ahc-" + nkey.replace(":", "-")})]
        if audience == "owner":
            effects.append(("inbox", {"path": str(self.paths.inbox / req["owner"] / ("%s-%s.md" % (iid, state))),
                                      "body": body}))
        if audience == "user" or state in ALERT_STATES:
            effects.append(("alert", _alert_payload(iid, req, state, body)))
        effects.append(("digest", {"line": _digest_line(iid, req, state, body), "key": nkey}))
        for kind, payload in effects:
            self.led.db.execute(
                "INSERT OR IGNORE INTO effects(key, item, kind, status, attempts, next_action_at, payload, updated)"
                " VALUES (?,?,?,?,?,?,?,?)",
                ("%s:%s" % (kind, nkey), iid, kind, "pending", 0, now, json.dumps(payload), now))

    def dispatch_effects(self):
        now = self.now()
        rows = self.led.db.execute(
            "SELECT * FROM effects WHERE kind != 'review' AND status IN ('pending', 'intent') AND next_action_at <= ?"
            " ORDER BY next_action_at, key", (now,)).fetchall()
        for row in rows:
            payload = json.loads(row["payload"])
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

    def _effect_done(self, key, detail):
        with self.led.tx():
            self.led.db.execute("UPDATE effects SET status='done', next_action_at=NULL, result=?, updated=? "
                                "WHERE key=?", (str(detail)[:500], self.now(), key))

    def readback(self, kind, payload):
        if kind == "inbox":
            return Path(payload["path"]).exists()
        if kind == "digest":
            try:
                return ("[k:%s]" % payload["key"]) in self.paths.digest.read_text(encoding="utf-8")
            except OSError:
                return False
        return False  # ticket: ah applies an idempotency key once, so resending with the same key is the readback

    def send(self, kind, payload):
        try:
            if kind == "ticket":
                rc, _out, err = self.deps.ah(["ah", "ticket", "comment", payload["ticket"], "--body", payload["body"],
                                              "--key", payload["key"]], 60)
                return rc == 0, "rc=%s %s" % (rc, _short(err))
            if kind == "inbox":
                path = Path(payload["path"])
                if not path.exists():
                    _write_private(path, payload["body"])
                return True, "written"
            if kind == "digest":
                if not self.readback("digest", payload):
                    _append_private(self.paths.digest, payload["line"])
                return True, "appended"
            if kind == "alert":
                rc, _out, err = self.deps.ah(["ah", "alert", "raise", "--severity", "high", "--alert-key",
                                              payload["alert_key"], "--source", "ahc", "--key", payload["key"],
                                              "--message", payload["message"]], 60)
                return rc == 0, "rc=%s %s" % (rc, _short(err))
        except (OSError, subprocess.SubprocessError) as error:
            return False, _short(error)
        return False, "unknown effect kind"

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
            with self.led.tx():
                self.led.db.execute("UPDATE notices SET escalated_at=? WHERE key=?", (now, notice["key"]))
                self._insert_notice(notice["item"], req, "%s-escalated" % notice["state"], "user", body, False, now)

# ---------------------------------------------------------------- tick

def ingest(ledger, paths):
    try:
        files = sorted(paths.queue.glob("ahc-*.json"))
    except OSError:
        files = []
    for qfile in files:
        ledger.ensure_item(qfile.stem)


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
    summary = {"processed": [], "recovered": [], "defects": []}
    try:
        ingest(ledger, paths)
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


def ack(paths, iid, owner, now=None):
    """Owner acknowledgement: the only way an owner notice becomes delivered (AC-19, NEG-26)."""
    ledger = Ledger(paths)
    try:
        row = ledger.item(iid)
        if row is None:
            raise core.Refused("no such item")
        if row["owner"] != owner:
            raise core.Refused("only the item's owner can acknowledge it")
        with ledger.tx():
            cur = ledger.db.execute("UPDATE notices SET acked_at=? WHERE item=? AND audience='owner' AND acked_at "
                                    "IS NULL", (now or time.time(), iid))
            ledger.event(iid, "acked", now or time.time(), owner=owner, notices=cur.rowcount)
        return cur.rowcount
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
        text = Path(report_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(the report could not be read)"
    head, _sep, body = text.partition("\n\n")
    return body.strip()[:MAX_BODY] or text[:MAX_BODY]


def _owner_notice(state, reason):
    return {"state": state, "audience": "owner", "reason": reason, "requires_ack": True}


def _alert_payload(iid, req, state, body):
    message = "ahc %s: %s#%s %s | %s" % (state, req["repo"], req["pr"], req["head"][:12],
                                       " ".join(body.split())[:400])
    return {"alert_key": "ahc:" + iid, "key": "ahc-%s-%s" % (iid, state), "message": message}


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


def _write_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _append_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
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
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
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
        ingest(ledger, paths)
        existing = ledger.item(core.item_id(norm, hashlib.sha256(Path(norm["packet"]).read_bytes()).hexdigest()))
        depth = ledger.db.execute("SELECT COUNT(*) AS n FROM items WHERE state IN (%s)" % ",".join(
            "?" * len(NON_TERMINAL)), sorted(NON_TERMINAL)).fetchone()["n"]
    finally:
        ledger.close()
    if existing is None and depth >= capacity:  # NEG-38; a duplicate resubmit stays a no-op
        raise core.Refused("the ahc queue is full: %d items waiting (capacity %d); try again later or ask main"
                           % (depth, capacity))
    text = Path(norm["packet"]).read_text(encoding="utf-8")
    fix = ahc_packet.fix_packet(text, norm["head"], source_path=norm["packet"])
    if fix["status"] == "unfixable":
        import review_diagnostics
        raise core.Refused(review_diagnostics.render_lint(fix["problems"], "pr"))
    return core.submit(paths, config, req)


def _setup_logging(paths):
    logdir = paths.home / ".agent-harness" / "logs"
    logdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = logging.handlers.RotatingFileHandler(str(logdir / "ahc.log"), maxBytes=8 * 1024 * 1024,
                                                   backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def main(argv=None):
    parser = argparse.ArgumentParser(description="ahc coordinator (Gate 1: receipts only, never merges)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("submit", help="queue an exact-head PR receipt request")
    for name in ("--repo", "--head", "--base", "--packet", "--ticket", "--owner"):
        s.add_argument(name, required=True)
    s.add_argument("--pr", type=int, required=True)
    a = sub.add_parser("ack", help="owner acknowledges an item's notice")
    a.add_argument("item")
    a.add_argument("--owner", required=True)
    sub.add_parser("status", help="item states and pending effects")
    r = sub.add_parser("run", help="run ticks (the daemon loop under launchd)")
    r.add_argument("--once", action="store_true")
    r.add_argument("--interval", type=int, default=60)
    args = parser.parse_args(argv)
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
            print("acknowledged %d notice(s)" % ack(paths, args.item, args.owner))
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
            pending = ledger.db.execute("SELECT COUNT(*) AS n FROM effects WHERE status != 'done'").fetchone()["n"]
            print("pending effects: %d" % pending)
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
