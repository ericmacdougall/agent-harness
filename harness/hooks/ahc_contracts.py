"""ahc Review, Grant and Operation (Effect) rows with the design v3 transition contracts (3.3, 3.9, 3.9a, 2.5).

Slice M-1 of goodqa#16049. Pure ledger logic over one sqlite3 connection: no subprocess, no network, no model. A
transition that is not listed here does not exist. Every transition checks the common guard G0 (expected version,
new event id, an actor allowed for that entity and transition) and writes the common action A0 (a transition record
and the new version) in the same transaction as its own actions.

Not built here, and stated so nobody assumes it: recovery epochs (G0's epoch check is the single-epoch case), an
off-host authority record (AuthorityLog is a local, fsynced, append-only file labelled not-off-host; the merge path
adds a GoodQA comment readback on top, in the runner), and the Attempt entity.
"""
import contextlib
import hashlib
import json
import os
import time

# Bounds from design v3 1.1 (the only numbers here)
B10_DISPATCHES = 3            # physical dispatches per operation key, in total, the first included
B37_PROBE_SECONDS = 60        # readback rate per unknown outcome
B37_PROBES = 20               # automatic readbacks per episode before held
B42_INCIDENT_SECONDS = 1800   # unknown-effect age that raises an incident
B47_GRANT_SECONDS = 86400     # grant lifetime
B48_RETENTION_SECONDS = 30 * 86400   # operation record retention after settlement; then a tombstone, kept forever
B54_LATE_SECONDS = 86400      # late-request horizon for "absent by quiescence"
B55_REQUEST_SECONDS = 120     # one effect, readback or probe request

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL,
  packet_sha256 TEXT NOT NULL, policy_revision TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL,
  receipt TEXT, successor TEXT, producer_unit TEXT, producer_uid INTEGER, data TEXT NOT NULL DEFAULT '{}',
  created REAL NOT NULL, updated REAL NOT NULL,
  UNIQUE(kind, repo, pr, head, packet_sha256, policy_revision));
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, principal TEXT NOT NULL,
  repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL, base TEXT NOT NULL, merge_sha TEXT NOT NULL,
  policy_revision TEXT NOT NULL, uses INTEGER NOT NULL, expires_at REAL NOT NULL, state TEXT NOT NULL,
  operation TEXT, authority_epoch INTEGER NOT NULL, kill_epoch INTEGER NOT NULL, cap_day INTEGER NOT NULL,
  cap_held INTEGER NOT NULL, authority_seq INTEGER, version INTEGER NOT NULL, created REAL NOT NULL,
  updated REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS grants_one_live_per_scope ON grants(kind, repo, pr, merge_sha)
  WHERE state IN ('validated', 'active', 'reserved');
CREATE TABLE IF NOT EXISTS operations (
  key TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, repo TEXT NOT NULL, pr INTEGER NOT NULL,
  head TEXT NOT NULL, base TEXT NOT NULL, merge_sha TEXT NOT NULL, policy_revision TEXT NOT NULL,
  generation INTEGER NOT NULL, params TEXT, params_sha256 TEXT NOT NULL, grant_id TEXT,
  state TEXT NOT NULL, dispatch_count INTEGER NOT NULL DEFAULT 0, proven_absent INTEGER NOT NULL DEFAULT 0,
  dispatched_at REAL, request_id TEXT, refusal TEXT, probe_at REAL, escalate_at REAL,
  readbacks INTEGER NOT NULL DEFAULT 0, proof TEXT, evidence TEXT, incident INTEGER NOT NULL DEFAULT 0,
  pr_unmarked INTEGER NOT NULL DEFAULT 0, settled_at REAL, tombstone INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS contract_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
INSERT OR IGNORE INTO contract_meta(k, v) VALUES ('authority_epoch', '1');
CREATE TABLE IF NOT EXISTS repo_flags (
  repo TEXT PRIMARY KEY, merging_off INTEGER NOT NULL, cause TEXT, actor TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS transitions (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT NOT NULL, id TEXT NOT NULL, from_state TEXT,
  to_state TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE, actor TEXT NOT NULL, at REAL NOT NULL, data TEXT);
"""


class ContractError(ValueError):
    """A transition that the contract does not allow, or whose guard is false. Nothing was written."""


class VersionConflict(ContractError):
    """G0: the row changed since the caller read it."""


class OperationConflict(ContractError):
    """2.5: the same operation key with different parameters. Surfaced to the scheduler; never a new row."""


class AuthorityError(ContractError):
    """The authority record could not be written first; the transition did not happen."""


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha(value):
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def apply_schema(db):
    for statement in [s.strip() for s in SCHEMA.split(";") if s.strip()]:
        db.execute(statement)


# ------------------------------------------------------------------ authority record

class AuthorityLog:
    """Append-only, fsynced JSON-lines record of grant changes, written BEFORE the ledger change it describes.
    LOCAL, NOT OFF-HOST (a stated deviation from 3.9). Idempotent per event id: a retried transition reuses the
    sequence it already has. A write failure raises AuthorityError and the caller's transaction rolls back."""

    label = "local-not-off-host"

    def __init__(self, path):
        self.path = str(path)

    def records(self):
        try:
            with open(self.path, encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as error:
            raise AuthorityError("authority record unreadable: %s" % type(error).__name__) from None

    def append(self, record):
        rows = self.records()
        for row in rows:
            if row.get("event_id") == record["event_id"]:
                if {k: row.get(k) for k in record} != record:
                    raise AuthorityError("authority record event id reused with other content")
                return row["seq"]
        entry = dict(record, seq=len(rows) + 1, label=self.label)
        try:
            os.makedirs(os.path.dirname(self.path) or ".", mode=0o700, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(fd, (_canon(entry) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as error:
            raise AuthorityError("authority record not written: %s" % type(error).__name__) from None
        return entry["seq"]


# ------------------------------------------------------------------ common guard and action

class Contracts:
    """Transitions over one connection. `now` is injectable for tests; `authority` is an AuthorityLog."""

    def __init__(self, db, authority, now=None):
        self.db = db
        self.authority = authority
        self._now = now or time.time

    def now(self):
        return float(self._now())

    @contextlib.contextmanager
    def tx(self):
        if self.db.in_transaction:
            yield
            return
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def _row(self, table, column, value):
        cur = self.db.execute("SELECT * FROM %s WHERE %s=?" % (table, column), (value,))
        row = cur.fetchone()
        if row is None:
            return None
        return dict(zip([d[0] for d in cur.description], row))

    def _g0(self, entity, row, expected_version, event_id, actor, allowed, frm, to):
        if (frm, to) not in allowed:
            raise ContractError("%s: no transition %s -> %s" % (entity, frm, to))
        actors = allowed[(frm, to)]
        if actor not in actors:
            raise ContractError("%s %s -> %s: actor %r may not make this transition" % (entity, frm, to, actor))
        if row is not None and (expected_version is None or row["version"] != expected_version):
            raise VersionConflict("%s version is %s, caller expected %s" % (entity, row["version"], expected_version))
        if not isinstance(event_id, str) or not event_id:
            raise ContractError("an event id is required")
        if self.db.execute("SELECT 1 FROM transitions WHERE event_id=?", (event_id,)).fetchone():
            raise ContractError("event id %s was already applied" % event_id)

    def _a0(self, entity, ident, frm, to, event_id, actor, **data):
        self.db.execute("INSERT INTO transitions(entity, id, from_state, to_state, event_id, actor, at, data) "
                        "VALUES (?,?,?,?,?,?,?,?)", (entity, ident, frm, to, event_id, actor, self.now(),
                                                     _canon(data) if data else None))

    # -------------------------------------------------------------- Review (3.3)

    # M-1 spec (ahc-m1-v1, Review table R1-R13): kinds adversarial and spec, plus red-team where the class requires
    # it. `cancelling` is added per the spec owner's ruling (running -> cancelling -> superseded: the attempt unit is
    # stopped before its row is terminal). There is no waiver path in M-1.
    REVIEW_KINDS = ("adversarial", "spec", "red-team")
    ATTEMPT_KINDS = ("adversarial", "red-team")      # produced by a review attempt unit: producer is verified
    REVIEW_TERMINAL = ("passed", "findings", "superseded")
    D, P = ("ahc-core",), ("ahc-core", "ahc-review")
    REVIEW = {
        ("required", "queued"): D,            # R2 packet built, linted, hashed
        ("required", "passed"): D,            # R11 spec kind: attach record current
        ("required", "infra-wait"): D,        # R13 spec kind: no attach record for 4 h; packet build failed
        ("required", "superseded"): D,        # R12
        ("queued", "running"): P,             # R3 isolated attempt unit allocated
        ("queued", "infra-wait"): D,          # NEG-12 review-isolation unavailable at allocation (proposed for R6)
        ("queued", "superseded"): D,          # R12
        ("running", "passed"): P,             # R4
        ("running", "findings"): P,           # R5
        ("running", "infra-wait"): P,         # R6
        ("running", "outcome-unknown"): D,    # R7
        ("running", "cancelling"): D,         # R12 via cancelling (ruling 2)
        ("cancelling", "superseded"): D,
        ("outcome-unknown", "passed"): D,     # R8
        ("outcome-unknown", "findings"): D,   # R8
        ("outcome-unknown", "queued"): D,     # R9
        ("outcome-unknown", "superseded"): D,  # R12: a receipt arriving later authorizes nothing
        ("infra-wait", "queued"): D,          # R10
        ("infra-wait", "superseded"): D,      # R12
    }

    def require_review(self, kind, repo, pr, head, packet_sha256, policy_revision, item=None, event_id=None,
                       actor="ahc-core"):
        """none -> required, or the existing row for this exact binding (idempotent)."""
        if kind not in self.REVIEW_KINDS:
            raise ContractError("unknown review kind %r" % kind)
        if actor not in self.D:
            raise ContractError("review rows are created by ahc-core")
        binding = {"kind": kind, "repo": str(repo).lower(), "pr": int(pr), "head": head,
                   "packet_sha256": packet_sha256, "policy_revision": policy_revision}
        rid = "rv-" + _sha(binding)[:24]
        with self.tx():
            existing = self._row("reviews", "id", rid)
            if existing:
                return existing
            now = self.now()
            self.db.execute("INSERT INTO reviews(id, kind, item, repo, pr, head, packet_sha256, policy_revision, "
                            "state, version, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                            (rid, kind, item, binding["repo"], binding["pr"], head, packet_sha256, policy_revision,
                             "required", 1, now, now))
            self._a0("review", rid, None, "required", event_id or "ev-" + rid + "-required", actor)
            return self._row("reviews", "id", rid)

    def start_attempt(self, rid, unit, uid, *, expected_version, event_id, actor="ahc-review"):
        """R3 queued -> running: binds the row to the one attempt unit core started and the uid systemd allocated to
        it (read by core from the unit, never from the attempt). Only that uid's result can settle the row."""
        if not isinstance(unit, str) or not unit or type(uid) is not int or uid <= 0:
            raise ContractError("running needs the attempt's unit name and its allocated uid")
        with self.tx():
            self.review(rid, "running", expected_version=expected_version, event_id=event_id, actor=actor)
            self.db.execute("UPDATE reviews SET producer_unit=?, producer_uid=? WHERE id=?", (unit, uid, rid))
            return self._row("reviews", "id", rid)

    def review(self, rid, to, *, expected_version, event_id, actor="ahc-core", receipt=None, unit_gone=None,
               successor=None, cause=None, peer_uid=None):
        """One Review transition. A result (passed or findings) of an attempt kind needs peer_uid, the kernel peer
        credential of the socket the result arrived on, equal to the uid bound at R3; anything else is
        unverified-producer and authorizes nothing (spec H2, NEG-12)."""
        with self.tx():
            row = self._row("reviews", "id", rid)
            if row is None:
                raise ContractError("no review row %s" % rid)
            frm = row["state"]
            self._g0("review", row, expected_version, event_id, actor, self.REVIEW, frm, to)
            if to in ("passed", "findings"):
                if row["kind"] in self.ATTEMPT_KINDS and (
                        row["producer_uid"] is None or type(peer_uid) is not int or peer_uid != row["producer_uid"]):
                    raise ContractError("unverified-producer: the result did not come from the attempt unit bound "
                                        "to this row")
                if row["kind"] == "spec" and frm != "required":
                    raise ContractError("a spec row passes only from required, on its attach record (R11)")
                self._check_receipt(row, receipt, to)
            if frm == "outcome-unknown" and to == "queued" and unit_gone is not True:
                raise ContractError("outcome-unknown -> queued needs the unit confirmed gone and no bound receipt")
            if to == "superseded" and not successor and frm != "cancelling":
                raise ContractError("superseded needs the successor row id")
            self.db.execute("UPDATE reviews SET state=?, version=version+1, updated=?, receipt=COALESCE(?, receipt), "
                            "successor=COALESCE(?, successor) WHERE id=?",
                            (to, self.now(), _canon(receipt) if receipt is not None else None, successor, rid))
            self._a0("review", rid, frm, to, event_id, actor, cause=cause, peer_uid=peer_uid)
            return self._row("reviews", "id", rid)

    @staticmethod
    def _check_receipt(row, receipt, to):
        if not isinstance(receipt, dict):
            raise ContractError("%s needs a parsed receipt" % to)
        want = {"repo": row["repo"], "pr": row["pr"], "head": row["head"], "packet_sha256": row["packet_sha256"],
                "policy_revision": row["policy_revision"]}
        got = {"repo": str(receipt.get("repo", "")).lower(), "pr": receipt.get("pr"), "head": receipt.get("head"),
               "packet_sha256": receipt.get("packet_sha256"), "policy_revision": receipt.get("policy_revision")}
        if got != want:
            raise ContractError("receipt is bound to another subject: %s" % sorted(k for k in want
                                                                                   if want[k] != got[k]))
        verdict = receipt.get("verdict")
        if (to == "passed") != (verdict == "PASS"):
            raise ContractError("receipt verdict %r does not match %s" % (verdict, to))

    def supersede_reviews(self, repo, pr, head, successor_of, event_prefix, actor="ahc-core"):
        """R12, a changed head: every non-terminal row for (repo, pr) at another head is superseded; a running row
        goes to cancelling first and settles to superseded once its unit is stopped. A receipt that arrives for a
        superseded row authorizes nothing. successor_of(row id) names the new row."""
        out = []
        with self.tx():
            rows = self.db.execute("SELECT id, state, version FROM reviews WHERE repo=? AND pr=? AND head != ? "
                                   "AND state NOT IN ('passed', 'findings', 'superseded', 'cancelling')",
                                   (str(repo).lower(), int(pr), head)).fetchall()
            for rid, state, version in rows:
                to = "cancelling" if state == "running" else "superseded"
                self.review(rid, to, expected_version=version, event_id="%s-%s" % (event_prefix, rid), actor=actor,
                            successor=successor_of(rid) if to == "superseded" else None, cause="head-changed")
                out.append((rid, to))
        return out

    # -------------------------------------------------------------- Grant (spec ahc-m1-v2e G1-G9)

    GRANT_TERMINAL = ("consumed", "retired", "expired", "revoked")
    GRANT_LIVE = ("validated", "active", "reserved")
    POLICY_PRINCIPALS = ("ahc-policy",)
    CAP1_PER_DAY = 10              # spec A3: integrations per repo per UTC day, reserved at G1
    GRANT = {
        ("validated", "active"): ("ahc-core",),                        # G2
        ("active", "reserved"): ("ahc-core",),                         # G3
        ("reserved", "consumed"): ("ahc-core",),                       # G4
        ("validated", "retired"): ("ahc-core",), ("active", "retired"): ("ahc-core",),   # G5
        ("reserved", "retired"): ("ahc-core",),
        ("validated", "expired"): ("ahc-core",), ("active", "expired"): ("ahc-core",),   # G7
        ("validated", "revoked"): ("main", "ahc-core"),                # G8 (main) / G9 (kill switch, ahc-core)
        ("active", "revoked"): ("main", "ahc-core"),
        ("reserved", "revoked"): ("main", "ahc-core"),
    }
    CAP_RELEASED_BY = ("retired", "expired")      # G5, G7 release the CAP1 slot; G4 keeps it; G8/G9 keep it

    def authority_epoch(self):
        row = self.db.execute("SELECT v FROM contract_meta WHERE k='authority_epoch'").fetchone()
        return int(row[0]) if row else 1

    def utc_day(self, at=None):
        return int((self.now() if at is None else at) // 86400)

    def cap_used(self, repo, day=None):
        return self.db.execute("SELECT COUNT(*) FROM grants WHERE repo=? AND cap_day=? AND cap_held=1",
                               (str(repo).lower(), self.utc_day() if day is None else day)).fetchone()[0]

    def issue_grant(self, kind, source, principal, scope, policy_revision, *, event_id, kill_epoch,
                    lifetime=B47_GRANT_SECONDS):
        """G1: none -> validated, authority log first. The caller (ahc-policy in W7) checked ELIG on fresh
        observations. Scope (repo, pr, H, B, M); one non-terminal grant per (kind, repo, pr, M) by unique index; a
        CAP1 slot for the UTC day of G1 is reserved in the same transaction; the grant carries the current authority
        epoch and the kill epoch the caller read."""
        if principal not in self.POLICY_PRINCIPALS:
            raise ContractError("grants are issued by a policy principal, never by a model or an owner")
        if not isinstance(source, str) or not source.startswith(("user:", "answer:", "queue:")):
            raise ContractError("a grant needs the source of the user's decision")
        if not isinstance(scope, dict) or any(scope.get(k) in (None, "") for k in ("repo", "pr", "head", "base",
                                                                                     "merge_sha")):
            raise ContractError("a grant's scope names repo, pr, head, base and the candidate M")
        if type(kill_epoch) is not int:
            raise ContractError("a grant records the kill epoch it was issued under")
        repo, pr = str(scope["repo"]).lower(), int(scope["pr"])
        head, base, m = scope["head"], scope["base"], scope["merge_sha"]
        gid = "gr-" + _sha({"kind": kind, "repo": repo, "pr": pr, "m": m, "policy": policy_revision,
                            "event": event_id})[:24]
        with self.tx():
            live = self.db.execute("SELECT id FROM grants WHERE kind=? AND repo=? AND pr=? AND merge_sha=? AND "
                                   "state IN ('validated', 'active', 'reserved')", (kind, repo, pr, m)).fetchone()
            if live:
                raise ContractError("a non-terminal grant %s already covers this candidate" % live[0])
            day = self.utc_day()
            if self.cap_used(repo, day) >= self.CAP1_PER_DAY:
                raise ContractError("CAP1 reached for %s on this UTC day" % repo)
            self._g0("grant", None, None, event_id, "ahc-core", {(None, "validated"): ("ahc-core",)}, None,
                     "validated")
            now, epoch = self.now(), self.authority_epoch()
            seq = self.authority.append({"event_id": event_id, "grant": gid, "from": None, "to": "validated",
                                         "operation": None, "scope": {"repo": repo, "pr": pr, "head": head,
                                                                      "base": base, "merge_sha": m},
                                         "actor": principal, "epochs": [epoch, kill_epoch]})
            self.db.execute("INSERT INTO grants(id, kind, source, principal, repo, pr, head, base, merge_sha, "
                            "policy_revision, uses, expires_at, state, authority_epoch, kill_epoch, cap_day, "
                            "cap_held, authority_seq, version, created, updated) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (gid, kind, source, principal, repo, pr, head, base, m, policy_revision, 1,
                             now + lifetime, "validated", epoch, kill_epoch, day, 1, seq, 1, now, now))
            self._a0("grant", gid, None, "validated", event_id, "ahc-core", principal=principal)
            return self._row("grants", "id", gid)

    def _grant_move(self, gid, to, expected_version, event_id, actor, operation=None, **data):
        """Every grant move after G1 writes the authority log first (T4); a failed append aborts the transaction."""
        row = self._row("grants", "id", gid)
        if row is None:
            raise ContractError("no grant %s" % gid)
        frm = row["state"]
        self._g0("grant", row, expected_version, event_id, actor, self.GRANT, frm, to)
        op = row["operation"] if operation is None else operation
        seq = self.authority.append({"event_id": event_id, "grant": gid, "from": frm, "to": to,
                                     "operation": op or None,
                                     "scope": {k: row[k] for k in ("repo", "pr", "head", "base", "merge_sha")},
                                     "actor": actor})
        held = 0 if to in self.CAP_RELEASED_BY else row["cap_held"]
        self.db.execute("UPDATE grants SET state=?, version=version+1, updated=?, authority_seq=?, operation=?, "
                        "cap_held=? WHERE id=?", (to, self.now(), seq, op, held, gid))
        self._a0("grant", gid, frm, to, event_id, actor, **data)
        return self._row("grants", "id", gid)

    def _current_epochs(self, row, kill_epoch):
        if row["authority_epoch"] != self.authority_epoch():
            raise ContractError("grant is from an earlier authority epoch (T10)")
        if kill_epoch != row["kill_epoch"]:
            raise ContractError("the kill epoch changed since the grant was issued (T9)")

    def activate_grant(self, gid, *, expected_version, event_id):
        """G2: the G1 log line is durable (AuthorityLog.append fsyncs before returning)."""
        with self.tx():
            return self._grant_move(gid, "active", expected_version, event_id, "ahc-core")

    def reserve_grant(self, gid, op_key, *, expected_version, event_id, mirror_read_back, kill_epoch):
        """G3: the intent for exactly this scope exists and the off-host mirror comment was read back."""
        with self.tx():
            row = self._row("grants", "id", gid)
            op = self._row("operations", "key", op_key)
            if row is None or op is None:
                raise ContractError("reserve needs an existing grant and operation")
            if mirror_read_back is not True:
                raise ContractError("reserve needs the mirror comment read back from the ticket")
            self._current_epochs(row, kill_epoch)
            if row["expires_at"] <= self.now():
                raise ContractError("grant is past expiry: no new reservation")
            if row["operation"]:
                raise ContractError("grant is already reserved for %s" % row["operation"])
            if op["state"] != "intent" or any(str(op[k]).lower() != str(row[k]).lower()
                                              for k in ("repo", "pr", "head", "base", "merge_sha")):
                raise ContractError("operation is outside the grant's scope")
            if op["policy_revision"] != row["policy_revision"]:
                raise ContractError("operation is bound to another policy revision")
            if op["grant_id"]:
                raise ContractError("operation already holds grant %s" % op["grant_id"])
            self._grant_move(gid, "reserved", expected_version, event_id, "ahc-core", operation=op_key)
            self.db.execute("UPDATE operations SET grant_id=? WHERE key=?", (gid, op_key))
            return self._row("grants", "id", gid)

    def revoke_grant(self, gid, *, expected_version, event_id, by, source):
        """G8 (by="main"; the CALLER verifies main's stamp through caller_identity first: C6 obligation) or G9
        (by="kill-switch", actor ahc-core). An in-flight operation then settles only by readback (E11)."""
        if by not in ("main", "kill-switch"):
            raise ContractError("a grant is revoked by main or by the kill switch")
        if not isinstance(source, str) or not source:
            raise ContractError("a revocation records its source")
        actor = "main" if by == "main" else "ahc-core"
        with self.tx():
            return self._grant_move(gid, "revoked", expected_version, event_id, actor, source=source, by=by)

    def retire_grant(self, gid, *, expected_version, event_id, reason):
        """G5 for a validated or active grant whose W7 attempt ended before an Effect bound it."""
        with self.tx():
            return self._grant_move(gid, "retired", expected_version, event_id, "ahc-core", reason=reason)

    def expire_grants(self, event_prefix):
        """G7 sweep. A reserved grant past expiry has NO transition while its operation is unsettled."""
        out = []
        with self.tx():
            for gid, version in self.db.execute(
                    "SELECT id, version FROM grants WHERE state IN ('validated', 'active') AND expires_at <= ?",
                    (self.now(),)).fetchall():
                self._grant_move(gid, "expired", version, "%s-%s" % (event_prefix, gid), "ahc-core")
                out.append(gid)
        return out

    def _settle_grant_for(self, op, event_id):
        """The grant side of an operation reaching a terminal state: G4 when confirmed, or abandoned after a send
        whose outcome stayed unknown; G5 (retired) when abandoned with nothing sent or every send proven absent."""
        gid = op["grant_id"]
        row = self._row("grants", "id", gid) if gid else None
        if row is None or row["state"] != "reserved" or row["operation"] != op["key"]:
            return row
        if op["state"] == "confirmed" or op["proof"] == "unknown-spent":
            return self._grant_move(gid, "consumed", row["version"], event_id + "-grant", "ahc-core")
        return self._grant_move(gid, "retired", row["version"], event_id + "-grant", "ahc-core")

    # -------------------------------------------------------------- Effect / Operation (spec ahc-m1-v2e E1-E12)

    OP_TERMINAL = ("confirmed", "abandoned")
    OP_UNSETTLED = ("intent", "dispatched", "absent-proven", "outcome-unknown", "held")
    OPERATORS = ("main", "reconcile")
    PROOFS = ("p1", "p2", "p3")
    P1_KINDS = ("non-fast-forward", "ref-lock", "protected-ref")
    OBSERVATION_SECONDS = 120     # T2: an external fact in a guard is under 2 min old
    PR_MARK_SECONDS = 600         # E12: the PR does not show merged within 10 min of the dispatch
    OP = {
        ("intent", "dispatched"): ("ahc-merge",),                           # E2
        ("dispatched", "confirmed"): ("ahc-merge",),                        # E3, E12
        ("outcome-unknown", "confirmed"): ("ahc-merge",),                   # E3, E12
        ("dispatched", "absent-proven"): ("ahc-merge",),                    # E4
        ("outcome-unknown", "absent-proven"): ("ahc-merge",),               # E4
        ("dispatched", "outcome-unknown"): ("ahc-core",),                   # E5
        ("outcome-unknown", "held"): ("ahc-core",),                         # E6
        ("absent-proven", "intent"): ("ahc-core",),                         # E7
        ("absent-proven", "abandoned"): ("ahc-core",),                      # E8
        ("intent", "abandoned"): ("ahc-core",),                             # E9
        ("held", "confirmed"): OPERATORS, ("held", "abandoned"): OPERATORS,  # E10
        ("absent-proven", "held"): ("ahc-core",),                           # E11
    }

    @staticmethod
    def operation_key(repo, pr, merge_sha, policy_revision, generation):
        """E1: (repo, pr, M, policy revision, g), derived by core, never supplied by a model. M is deterministic
        from (B, H), so a base move always gives a new key."""
        if any(v in (None, "") for v in (repo, pr, merge_sha, policy_revision)) or type(generation) is not int \
                or generation < 0:
            raise ContractError("an operation key needs repo, pr, M, policy revision and generation")
        ident = {"repo": str(repo).lower(), "pr": int(pr), "m": merge_sha, "policy": policy_revision, "g": generation}
        return "op-merge-%s" % _sha(ident)[:32]

    def next_generation(self, repo, pr, merge_sha, policy_revision):
        """g rises only when the previous operation for the same M was abandoned with nothing sent or with every
        send proven absent (p1-p3). An operation with any send not proven absent never yields a new g."""
        rows = self.db.execute("SELECT generation, state, dispatch_count, proven_absent FROM operations WHERE "
                               "repo=? AND pr=? AND merge_sha=? AND policy_revision=? ORDER BY generation DESC "
                               "LIMIT 1", (str(repo).lower(), int(pr), merge_sha, policy_revision)).fetchall()
        if not rows:
            return 0
        g, state, sent, proven = rows[0]
        if state == "abandoned" and proven >= sent:
            return g + 1
        if state == "abandoned":
            raise ContractError("an operation with a send not proven absent never yields a new generation")
        return g

    def intend(self, params, *, item=None, lease_ok, event_id):
        """E1 none -> intent. params: repo, pr, head, base, merge_sha, policy_revision, method ("merge" only),
        default_branch. Same key and same parameters returns the row; same key with other parameters raises."""
        for k in ("repo", "pr", "head", "base", "merge_sha", "policy_revision", "method", "default_branch"):
            if params.get(k) in (None, ""):
                raise ContractError("operation is missing %s" % k)
        if params["method"] != "merge":
            raise ContractError("only the merge-commit method is allowed")
        with self.tx():
            g = self.next_generation(params["repo"], params["pr"], params["merge_sha"], params["policy_revision"])
            key = self.operation_key(params["repo"], params["pr"], params["merge_sha"], params["policy_revision"], g)
            params_sha = _sha(params)
            row = self._row("operations", "key", key)
            if row is not None:
                if row["tombstone"]:
                    raise ContractError("operation key %s is tombstoned; it can never be reused" % key)
                if row["params_sha256"] != params_sha:
                    raise OperationConflict("operation %s already exists with other parameters" % key)
                return row
            if lease_ok is not True:
                raise ContractError("intent needs a valid owning lease")
            self._g0("operation", None, None, event_id, "ahc-core", {(None, "intent"): ("ahc-core",)}, None,
                     "intent")
            now = self.now()
            self.db.execute("INSERT INTO operations(key, kind, item, repo, pr, head, base, merge_sha, "
                            "policy_revision, generation, params, params_sha256, state, version, created, updated) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (key, "merge", item, str(params["repo"]).lower(), int(params["pr"]), params["head"],
                             params["base"], params["merge_sha"], params["policy_revision"], g, _canon(params),
                             params_sha, "intent", 1, now, now))
            self._a0("operation", key, None, "intent", event_id, "ahc-core", generation=g)
            return self._row("operations", "key", key)

    def _op_move(self, key, to, expected_version, event_id, actor, sets=None, **data):
        row = self._row("operations", "key", key)
        if row is None:
            raise ContractError("no operation %s" % key)
        frm = row["state"]
        self._g0("operation", row, expected_version, event_id, actor, self.OP, frm, to)
        sets = dict(sets or {}, state=to, updated=self.now())
        if to in self.OP_TERMINAL:
            sets["settled_at"] = self.now()
        assignments = ", ".join("%s=?" % k for k in sets) + ", version=version+1"
        self.db.execute("UPDATE operations SET %s WHERE key=?" % assignments, list(sets.values()) + [key])
        self._a0("operation", key, frm, to, event_id, actor, **data)
        new = self._row("operations", "key", key)
        if to in self.OP_TERMINAL:
            self._settle_grant_for(new, event_id)
        return new

    def _fresh(self, obs):
        if not isinstance(obs, dict) or not isinstance(obs.get("at"), (int, float)):
            raise ContractError("the guard needs an observation row with its time (T2)")
        if self.now() - float(obs["at"]) >= self.OBSERVATION_SECONDS or float(obs["at"]) > self.now():
            raise ContractError("observation is stale (over 2 min) or from the future (T2)")

    def _row_or_raise(self, key):
        row = self._row("operations", "key", key)
        if row is None:
            raise ContractError("no operation %s" % key)
        return row

    def dispatch(self, key, obs, *, expected_version, event_id, lease_ok, mirror_read_back, request_id=None):
        """E2 intent -> dispatched. Every guard is re-read here; the count rises BEFORE the request is sent, and the
        caller sends only after this commits (T5), holding the T9 lock shared."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["dispatch_count"] >= B10_DISPATCHES:
                raise ContractError("dispatch budget B10 is spent for %s" % key)
            if lease_ok is not True:
                raise ContractError("dispatch needs a re-read valid lease")
            g = self._row("grants", "id", row["grant_id"]) if row["grant_id"] else None
            if g is None or g["state"] != "reserved" or g["operation"] != key:
                raise ContractError("dispatch needs the grant reserved for this operation")
            if mirror_read_back is not True:
                raise ContractError("dispatch needs the mirror comment read back")
            self._fresh(obs)
            self._current_epochs(g, obs.get("kill_epoch"))
            problems = []
            if obs.get("kill_switch") is not False:
                problems.append("kill switch on or unread")
            if obs.get("pr_state") != "OPEN" or obs.get("pr_head") != row["head"] or obs.get("draft") is not False:
                problems.append("PR not open at H")
            if obs.get("tip") != row["base"]:
                problems.append("default branch not at B")
            if obs.get("candidate") != row["merge_sha"]:
                problems.append("candidate ref is not M")
            if list(obs.get("parents") or []) != [row["base"], row["head"]]:
                problems.append("M's parents are not (B, H)")
            if obs.get("checks_green") is not True:
                problems.append("policy checks not green on H")
            if problems:
                raise ContractError("E2 guard false: " + "; ".join(problems))
            now = self.now()
            return self._op_move(key, "dispatched", expected_version, event_id, "ahc-merge", {
                "dispatch_count": row["dispatch_count"] + 1, "dispatched_at": now, "request_id": request_id,
                "probe_at": now + B55_REQUEST_SECONDS}, observation=obs)

    def confirm(self, key, obs, *, expected_version, event_id, actor="ahc-merge"):
        """E3: M is reachable from the current tip (compare M...tip is identical or ahead) and M's parents are
        (B, H). E12: the same, but the PR is not shown merged 10 min after the dispatch: still confirmed, flagged
        so ahc comments on the PR. E10 by main with evidence, or the reconcile under the E3 readback."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] == "held" and actor == "main":
                if not isinstance(obs, dict) or not obs:
                    raise ContractError("main settles a held operation with evidence")
                return self._op_move(key, "confirmed", expected_version, event_id, "main", {"evidence": _canon(obs)})
            if row["state"] == "held" and actor != "reconcile":
                raise ContractError("a held operation is settled only by main or the reconcile")
            self._fresh(obs)
            if obs.get("m_reachable") is not True or obs.get("compare") not in ("identical", "ahead") \
                    or list(obs.get("parents") or []) != [row["base"], row["head"]]:
                raise ContractError("readback does not show M reachable from the tip with parents (B, H)")
            unmarked = obs.get("pr_merged") is not True
            if unmarked and row["state"] != "held" and \
                    self.now() - float(row["dispatched_at"] or 0) < self.PR_MARK_SECONDS:
                raise ContractError("the PR is not shown merged yet; wait up to 10 min before E12")
            return self._op_move(key, "confirmed", expected_version, event_id, actor,
                                 {"evidence": _canon(obs), "pr_unmarked": 1 if unmarked else 0})

    def absent(self, key, proof, evidence, *, expected_version, event_id):
        """E4 -> absent-proven with an admissible proof. "Not there now" is never one.
        p1: a typed server refusal (evidence {"kind": non-fast-forward | ref-lock | protected-ref}).
        p2: an error response to a completed request AND a fresh readback taken after the dispatch showing the tip
            is no longer B and M is not reachable from it (evidence {"error": ..., "readback": {at, tip,
            m_reachable}}). An error while the tip is still B is NOT absence: the op stays dispatched or
            outcome-unknown with its grant reserved (L5).
        p3: the connection failed before the request was sent (evidence {"stage": dns | tcp | tls}).
        Each proof covers the one send in flight, so proven_absent rises by one."""
        if proof not in self.PROOFS or not isinstance(evidence, dict):
            raise ContractError("absent-proven needs proof p1, p2 or p3 with its evidence")
        with self.tx():
            row = self._row_or_raise(key)
            if proof == "p1" and evidence.get("kind") not in self.P1_KINDS:
                raise ContractError("p1 needs a typed server refusal")
            if proof == "p2":
                rb = evidence.get("readback")
                if not evidence.get("error") or not isinstance(rb, dict):
                    raise ContractError("p2 needs the error response and a readback")
                self._fresh(rb)
                if float(rb["at"]) < float(row["dispatched_at"] or 0):
                    raise ContractError("p2's readback must follow the dispatch")
                if not rb.get("tip") or rb.get("tip") == row["base"]:
                    raise ContractError("an error while the tip is still B is not an absence proof")
                if rb.get("m_reachable") is not False:
                    raise ContractError("p2 needs M not reachable from the tip")
            if proof == "p3" and evidence.get("stage") not in ("dns", "tcp", "tls"):
                raise ContractError("p3 needs a failure before the request was sent")
            return self._op_move(key, "absent-proven", expected_version, event_id, "ahc-merge",
                                 {"refusal": evidence.get("kind") or proof, "proof": proof,
                                  "proven_absent": row["proven_absent"] + 1, "evidence": _canon(evidence)})

    def unknown(self, key, *, expected_version, event_id, restart=False):
        """E5 dispatched -> outcome-unknown when B55 passed or a restart found no conclusive readback."""
        with self.tx():
            row = self._row_or_raise(key)
            if not restart and self.now() < float(row["probe_at"] or 0):
                raise ContractError("the request has not timed out yet (B55)")
            now = self.now()
            return self._op_move(key, "outcome-unknown", expected_version, event_id, "ahc-core", {
                "readbacks": 0, "probe_at": now + B37_PROBE_SECONDS, "escalate_at": now + B42_INCIDENT_SECONDS})

    def readback_missed(self, key, *, expected_version, event_id):
        """One inconclusive readback (a counter, not a transition). At 20: E6 held, one incident, the grant stays
        reserved and the record cannot expire."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None or row["state"] != "outcome-unknown":
                raise ContractError("readback applies to an outcome-unknown operation")
            if row["version"] != expected_version:
                raise VersionConflict("operation changed since it was read")
            count = row["readbacks"] + 1
            if count >= B37_PROBES:
                return self._op_move(key, "held", expected_version, event_id, "ahc-core",
                                     {"readbacks": count, "incident": 1, "probe_at": None})
            self.db.execute("UPDATE operations SET readbacks=?, probe_at=?, version=version+1, updated=? WHERE key=?",
                            (count, self.now() + B37_PROBE_SECONDS, self.now(), key))
            return self._row("operations", "key", key)

    def after_absence(self, key, params, tip_obs, *, expected_version, event_id, lease_ok):
        """From absent-proven, exactly one of: E11 held (grant revoked, or the third dispatch used); E8 abandoned
        (p1 or p2, or the tip is no longer B; the grant retires); E7 intent (p3 only, below 3 dispatches, same
        parameters, grant reserved, tip still B, lease valid)."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None or row["state"] != "absent-proven":
                raise ContractError("this step applies to an absent-proven operation")
            grant = self._row("grants", "id", row["grant_id"]) if row["grant_id"] else None
            if (grant is not None and grant["state"] == "revoked") or row["dispatch_count"] >= B10_DISPATCHES:
                return self._op_move(key, "held", expected_version, event_id, "ahc-core", {"incident": 1})
            self._fresh(tip_obs)
            if row["proof"] != "p3" or tip_obs.get("tip") != row["base"]:
                return self._op_move(key, "abandoned", expected_version, event_id, "ahc-core",
                                     {"proof": "all-sends-absent"})
            if _sha(params) != row["params_sha256"]:
                raise OperationConflict("a retry must carry the same parameters")
            if lease_ok is not True:
                raise ContractError("retry needs a valid lease")
            if grant is None or grant["state"] != "reserved":
                raise ContractError("retry needs the grant still reserved")
            return self._op_move(key, "intent", expected_version, event_id, "ahc-core")

    def abandon_unsent(self, key, *, expected_version, event_id, reason):
        """E9 intent -> abandoned: the owning item left merge-ready while the op is in intent, never sent or with
        every send proven absent (an intent row reached by E7 always is). The grant retires (G5), and the next W7
        for the same M uses generation g+1."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["proven_absent"] < row["dispatch_count"]:
                raise ContractError("an operation with a send not proven absent is never abandoned unsent")
            proof = "never-sent" if row["dispatch_count"] == 0 else "all-sends-absent"
            return self._op_move(key, "abandoned", expected_version, event_id, "ahc-core",
                                 {"proof": proof}, reason=reason)

    def settle_held(self, key, evidence, *, expected_version, event_id, actor):
        """E10 held -> abandoned: by main with evidence, or by the reconcile once the B54 horizon has passed with M
        unreachable and the tip no longer at B (a late CAS cannot apply). The outcome stayed unknown, so the grant
        is spent (G4). A held operation found merged goes through confirm()."""
        if actor not in self.OPERATORS or not isinstance(evidence, dict) or not evidence:
            raise ContractError("a held operation is settled only by main or the reconcile, with evidence")
        with self.tx():
            row = self._row_or_raise(key)
            if actor == "reconcile":
                self._fresh(evidence)
                if self.now() - float(row["dispatched_at"] or 0) < B54_LATE_SECONDS:
                    raise ContractError("the B54 late-request horizon has not passed")
                if evidence.get("m_reachable") is not False or not evidence.get("tip") \
                        or evidence.get("tip") == row["base"]:
                    raise ContractError("reconcile abandons only with M unreachable and the tip no longer at B")
            return self._op_move(key, "abandoned", expected_version, event_id, actor,
                                 {"proof": "unknown-spent", "evidence": _canon(evidence)})

    # ---- L5 late-apply watch and the per-repo merging switch

    LATE_WATCH_SECONDS = 30 * 86400

    def watched(self, repo):
        """Abandoned operations for the repo settled in the last 30 days whose M must not become reachable."""
        return [dict(zip(("key", "merge_sha", "base"), r)) for r in self.db.execute(
            "SELECT key, merge_sha, base FROM operations WHERE repo=? AND state='abandoned' AND settled_at >= ?",
            (str(repo).lower(), self.now() - self.LATE_WATCH_SECONDS))]

    def late_apply(self, key, evidence, *, event_id):
        """L5: a readback found an abandoned operation's M reachable from the tip. Raise one incident naming the op
        and turn the repo's merging off until main turns it back on. A detector, not a fence."""
        if not isinstance(evidence, dict) or evidence.get("m_reachable") is not True:
            raise ContractError("a late apply is recorded only on a readback showing M reachable")
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] != "abandoned":
                raise ContractError("the late-apply watch applies to abandoned operations")
            self._fresh(evidence)
            if self.db.execute("SELECT 1 FROM transitions WHERE event_id=?", (event_id,)).fetchone():
                raise ContractError("event id %s was already applied" % event_id)
            self.set_merging(row["repo"], off=True, cause="late-apply:%s" % key, actor="ahc-core", _in_tx=True)
            self.db.execute("UPDATE operations SET incident=incident+1 WHERE key=?", (key,))
            self._a0("operation", key, "abandoned", "abandoned", event_id, "ahc-core", late_apply=evidence,
                     incident="late-apply")
            return self._row("repo_flags", "repo", row["repo"])

    def set_merging(self, repo, *, off, cause, actor, _in_tx=False):
        """Turning merging off is open to ahc-core (L5) and main; turning it back on is main's only (the caller
        verifies main's stamp: C6 obligation)."""
        if actor not in ("ahc-core", "main") or (not off and actor != "main"):
            raise ContractError("only main turns a repo's merging back on")
        def write():
            self.db.execute("INSERT INTO repo_flags(repo, merging_off, cause, actor, at) VALUES (?,?,?,?,?) "
                            "ON CONFLICT(repo) DO UPDATE SET merging_off=excluded.merging_off, cause=excluded.cause, "
                            "actor=excluded.actor, at=excluded.at", (str(repo).lower(), 1 if off else 0, cause,
                                                                     actor, self.now()))
        if _in_tx:
            write()
        else:
            with self.tx():
                write()

    def merging_off(self, repo):
        row = self._row("repo_flags", "repo", str(repo).lower())
        return bool(row and row["merging_off"])

    def legacy_unsettled(self):
        """Rows kept from a pre-v4 ledger (grants_v3_legacy / operations_v3_legacy) that were not terminal. Each one
        is a reconcile item for main; any one makes its repo ineligible."""
        out = []
        for table, terminal in (("grants_v3_legacy", self.GRANT_TERMINAL), ("operations_v3_legacy",
                                                                          self.OP_TERMINAL)):
            if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                continue
            cols = [r[1] for r in self.db.execute("PRAGMA table_info(%s)" % table)]
            ident = "id" if "id" in cols else "key"
            repo_col = "repo" if "repo" in cols else "NULL"
            for ident_v, state, repo in self.db.execute("SELECT %s, state, %s FROM %s" % (ident, repo_col, table)):
                if state not in terminal:
                    out.append({"table": table, "id": ident_v, "state": state, "repo": repo})
        return out

    def retain(self):
        """B48: a terminal operation older than B48 after settlement becomes a tombstone (key, outcome and
        settled_at kept, parameters dropped). A non-terminal operation never expires."""
        cutoff = self.now() - B48_RETENTION_SECONDS
        with self.tx():
            cur = self.db.execute("UPDATE operations SET tombstone=1, params=NULL, evidence=NULL WHERE tombstone=0 "
                                  "AND state IN ('confirmed', 'abandoned') AND settled_at IS NOT NULL "
                                  "AND settled_at <= ?", (cutoff,))
            return cur.rowcount
