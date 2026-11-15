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
  receipt TEXT, successor TEXT, data TEXT NOT NULL DEFAULT '{}', created REAL NOT NULL, updated REAL NOT NULL,
  UNIQUE(kind, repo, pr, head, packet_sha256, policy_revision));
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, principal TEXT NOT NULL, scope TEXT NOT NULL,
  policy_revision TEXT NOT NULL, uses INTEGER NOT NULL, expires_at REAL NOT NULL, state TEXT NOT NULL,
  operation TEXT, authority_seq INTEGER, version INTEGER NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS operations (
  key TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, params TEXT, params_sha256 TEXT NOT NULL, grant_id TEXT,
  state TEXT NOT NULL, dispatch_count INTEGER NOT NULL DEFAULT 0, dispatched_at REAL, request_id TEXT,
  probe_at REAL, escalate_at REAL, readbacks INTEGER NOT NULL DEFAULT 0, proof TEXT, evidence TEXT,
  incident INTEGER NOT NULL DEFAULT 0, settled_at REAL, tombstone INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
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

    REVIEW_KINDS = ("spec", "spec-adversarial", "code", "red-team", "headed-test", "sign-off", "receipt-final",
                    "live-test", "adjudication")
    REVIEW_TERMINAL = ("passed", "findings", "superseded", "waived")
    D, P = ("ahc-core",), ("ahc-core", "ahc-review")
    REVIEW = {
        ("required", "queued"): D, ("required", "infra-wait"): D, ("required", "superseded"): D,
        ("required", "waived"): D,
        ("queued", "running"): P, ("queued", "infra-wait"): D, ("queued", "superseded"): D, ("queued", "waived"): D,
        ("running", "passed"): P, ("running", "findings"): P, ("running", "infra-wait"): P,
        ("running", "outcome-unknown"): D, ("running", "cancelling"): D,
        ("cancelling", "superseded"): D,
        ("outcome-unknown", "passed"): D, ("outcome-unknown", "findings"): D, ("outcome-unknown", "queued"): D,
        ("infra-wait", "queued"): D, ("infra-wait", "superseded"): D, ("infra-wait", "waived"): D,
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

    def review(self, rid, to, *, expected_version, event_id, actor="ahc-core", receipt=None, unit_gone=None,
               successor=None, waiver_source=None, cause=None):
        with self.tx():
            row = self._row("reviews", "id", rid)
            if row is None:
                raise ContractError("no review row %s" % rid)
            frm = row["state"]
            self._g0("review", row, expected_version, event_id, actor, self.REVIEW, frm, to)
            if to in ("passed", "findings"):
                self._check_receipt(row, receipt, to)
            if frm == "outcome-unknown" and to == "queued" and unit_gone is not True:
                raise ContractError("outcome-unknown -> queued needs the unit confirmed gone and no bound receipt")
            if to == "superseded" and not successor and frm != "cancelling":
                raise ContractError("superseded needs the successor row id")
            if to == "waived" and not (isinstance(waiver_source, str) and waiver_source.startswith(("user:",
                                                                                                    "answer:"))):
                raise ContractError("waived needs an authenticated user: or answer: source")
            self.db.execute("UPDATE reviews SET state=?, version=version+1, updated=?, receipt=COALESCE(?, receipt), "
                            "successor=COALESCE(?, successor) WHERE id=?",
                            (to, self.now(), _canon(receipt) if receipt is not None else None, successor, rid))
            self._a0("review", rid, frm, to, event_id, actor, cause=cause, waiver_source=waiver_source)
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
        """A changed head: every non-terminal row for (repo, pr) at another head is superseded (running rows go to
        cancelling first; they settle to superseded once the run is stopped). successor_of(row) names the new row."""
        out = []
        with self.tx():
            rows = self.db.execute("SELECT id, state, version FROM reviews WHERE repo=? AND pr=? AND head != ? "
                                   "AND state NOT IN ('passed', 'findings', 'superseded', 'waived', 'cancelling')",
                                   (str(repo).lower(), int(pr), head)).fetchall()
            for rid, state, version in rows:
                to = "cancelling" if state == "running" else "superseded"
                if to == "superseded" and state == "outcome-unknown":
                    continue   # may still have produced a receipt: settles by readback first (3.3)
                self.review(rid, to, expected_version=version, event_id="%s-%s" % (event_prefix, rid), actor=actor,
                            successor=successor_of(rid) if to == "superseded" else None, cause="head-changed")
                out.append((rid, to))
        return out

    # -------------------------------------------------------------- Grant (3.9, 3.9a)

    GRANT_TERMINAL = ("consumed", "expired", "revoked")
    POLICY_PRINCIPALS = ("ahc-policy",)
    REVOKERS = ("main", "kill-switch", "user")
    GRANT = {
        ("proposed", "validated"): ("ahc-policy",),
        ("validated", "active"): ("ahc-policy",),
        ("active", "reserved"): ("ahc-merge", "ahc-core"),
        ("reserved", "consumed"): ("ahc-core",),
        ("reserved", "active"): ("ahc-core",),
        ("reserved", "expired"): ("ahc-core",),
        ("proposed", "expired"): ("ahc-core",), ("validated", "expired"): ("ahc-core",),
        ("active", "expired"): ("ahc-core",),
        ("proposed", "revoked"): REVOKERS, ("validated", "revoked"): REVOKERS, ("active", "revoked"): REVOKERS,
        ("reserved", "revoked"): REVOKERS,
    }
    SCOPE_KEYS = ("repo", "pr", "head", "base")

    def propose_grant(self, kind, source, principal, scope, policy_revision, *, uses=1, lifetime=B47_GRANT_SECONDS,
                      event_id):
        if principal not in self.POLICY_PRINCIPALS:
            raise ContractError("grants are proposed by a policy principal, never by a model or an owner")
        if not isinstance(source, str) or not source.startswith(("user:", "answer:", "queue:", "policy:")):
            raise ContractError("a grant needs an authenticated source")
        gid = "gr-" + _sha({"kind": kind, "scope": scope, "policy": policy_revision, "event": event_id})[:24]
        with self.tx():
            if self._row("grants", "id", gid):
                return self._row("grants", "id", gid)
            now = self.now()
            self.db.execute("INSERT INTO grants(id, kind, source, principal, scope, policy_revision, uses, expires_at, "
                            "state, version, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                            (gid, kind, source, principal, _canon(scope), policy_revision, int(uses), now + lifetime,
                             "proposed", 1, now, now))
            self._a0("grant", gid, None, "proposed", event_id, principal)
            return self._row("grants", "id", gid)

    def _grant_move(self, gid, to, expected_version, event_id, actor, authority_first, operation=None, **data):
        row = self._row("grants", "id", gid)
        if row is None:
            raise ContractError("no grant %s" % gid)
        frm = row["state"]
        self._g0("grant", row, expected_version, event_id, actor, self.GRANT, frm, to)
        seq = row["authority_seq"]
        if authority_first:
            seq = self.authority.append({"event_id": event_id, "grant": gid, "from": frm, "to": to,
                                         "operation": operation if operation is not None else row["operation"],
                                         "scope": json.loads(row["scope"]), "actor": actor})
        self.db.execute("UPDATE grants SET state=?, version=version+1, updated=?, authority_seq=?, operation=? "
                        "WHERE id=?", (to, self.now(), seq,
                                       operation if operation is not None else row["operation"], gid))
        self._a0("grant", gid, frm, to, event_id, actor, **data)
        return self._row("grants", "id", gid)

    def validate_grant(self, gid, *, expected_version, event_id, actor="ahc-policy"):
        with self.tx():
            row = self._row("grants", "id", gid)
            scope = json.loads(row["scope"]) if row else {}
            if not row or not all(scope.get(k) not in (None, "") for k in self.SCOPE_KEYS):
                raise ContractError("a grant's scope names repo, pr, head and base")
            if row["uses"] != 1 or row["expires_at"] <= self.now():
                raise ContractError("a grant states one use and an expiry in the future")
            return self._grant_move(gid, "validated", expected_version, event_id, actor, False)

    def activate_grant(self, gid, *, expected_version, event_id, actor="ahc-policy"):
        with self.tx():
            return self._grant_move(gid, "active", expected_version, event_id, actor, True)

    def reserve_grant(self, gid, op_key, *, expected_version, event_id, actor="ahc-core"):
        with self.tx():
            row = self._row("grants", "id", gid)
            op = self._row("operations", "key", op_key)
            if row is None or op is None:
                raise ContractError("reserve needs an existing grant and operation")
            if row["expires_at"] <= self.now():
                raise ContractError("grant is past expiry: no new reservation")
            if row["operation"]:
                raise ContractError("grant is already reserved for %s" % row["operation"])
            scope, params = json.loads(row["scope"]), json.loads(op["params"] or "{}")
            if any(str(params.get(k, "")).lower() != str(scope.get(k, "")).lower() for k in self.SCOPE_KEYS):
                raise ContractError("operation is outside the grant's scope")
            return self._grant_move(gid, "reserved", expected_version, event_id, actor, True, operation=op_key)

    def revoke_grant(self, gid, *, expected_version, event_id, actor, source):
        if not isinstance(source, str) or not source:
            raise ContractError("a revocation records its source")
        with self.tx():
            return self._grant_move(gid, "revoked", expected_version, event_id, actor, True, source=source)

    def expire_grants(self, event_prefix):
        """Expiry sweep. A reserved grant past expiry has NO transition while its operation is unsettled (3.9a)."""
        out = []
        with self.tx():
            for gid, state, version in self.db.execute(
                    "SELECT id, state, version FROM grants WHERE state IN ('proposed', 'validated', 'active') "
                    "AND expires_at <= ?", (self.now(),)).fetchall():
                self._grant_move(gid, "expired", version, "%s-%s" % (event_prefix, gid), "ahc-core",
                                 state == "active")
                out.append(gid)
        return out

    def _settle_grant_for(self, op, outcome, event_id):
        """Grant side of an operation settling. outcome: confirmed | abandoned-unknown | released."""
        gid = op["grant_id"]
        if not gid:
            return None
        row = self._row("grants", "id", gid)
        if row is None or row["state"] != "reserved" or row["operation"] != op["key"]:
            return row
        if outcome in ("confirmed", "abandoned-unknown"):
            return self._grant_move(gid, "consumed", row["version"], event_id + "-grant", "ahc-core", True)
        to = "expired" if row["expires_at"] <= self.now() else "active"
        moved = self._grant_move(gid, to, row["version"], event_id + "-grant", "ahc-core", True, operation="")
        return moved

    # -------------------------------------------------------------- Operation / Effect (2.5, 3.9a)

    OP_TERMINAL = ("confirmed", "abandoned")
    OP_UNSETTLED = ("intent", "dispatched", "absent-proven", "outcome-unknown", "held")
    OP_KEY_FIELDS = {"merge": ("repo", "pr", "head", "base", "grant")}
    OPERATORS = ("main", "user", "operator")
    PROOFS_FROM_UNKNOWN = ("server-idempotency", "quiescence-ack", "fence-closed-quiet")

    def operation_key(self, kind, params):
        """Derived by core from the operation's identity fields, never supplied by a model."""
        fields = self.OP_KEY_FIELDS.get(kind)
        if not fields:
            raise ContractError("unknown operation kind %r" % kind)
        missing = [f for f in fields if params.get(f) in (None, "")]
        if missing:
            raise ContractError("operation is missing identity fields %s" % missing)
        ident = {f: (str(params[f]).lower() if f == "repo" else params[f]) for f in fields}
        return "op-%s-%s" % (kind, _sha(ident)[:32])

    def intend(self, kind, params, *, item=None, lease_ok, event_id):
        """none -> intent. Same key and same parameters: the existing row (idempotent). Same key, other parameters:
        OperationConflict. A tombstoned or expired key is refused."""
        key = self.operation_key(kind, params)
        params_sha = _sha(params)
        with self.tx():
            row = self._row("operations", "key", key)
            if row is not None:
                if row["tombstone"]:
                    raise ContractError("operation key %s is tombstoned; it can never be reused" % key)
                if row["params_sha256"] != params_sha:
                    raise OperationConflict("operation %s already exists with other parameters" % key)
                return row
            if lease_ok is not True:
                raise ContractError("intent needs a valid owning lease")
            grant = params.get("grant")
            if grant:
                g = self._row("grants", "id", grant)
                if g is None or g["state"] != "active" or g["operation"]:
                    raise ContractError("the operation's grant cannot be reserved")
            now = self.now()
            self.db.execute("INSERT INTO operations(key, kind, item, params, params_sha256, grant_id, state, "
                            "version, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (key, kind, item, _canon(params), params_sha, grant, "intent", 1, now, now))
            self._a0("operation", key, None, "intent", event_id, "ahc-core")
            if grant:
                g = self._row("grants", "id", grant)
                self.reserve_grant(grant, key, expected_version=g["version"], event_id=event_id + "-reserve")
            return self._row("operations", "key", key)

    OP = {
        ("intent", "dispatched"): ("ahc-core", "ahc-merge"),
        ("intent", "abandoned"): ("ahc-core",),
        ("dispatched", "confirmed"): ("ahc-core", "ahc-merge"),
        ("dispatched", "absent-proven"): ("ahc-core", "ahc-merge"),
        ("dispatched", "outcome-unknown"): ("ahc-core", "ahc-merge"),
        ("outcome-unknown", "confirmed"): ("ahc-core",),
        ("outcome-unknown", "absent-proven"): ("ahc-core",),
        ("outcome-unknown", "held"): ("ahc-core",),
        ("outcome-unknown", "outcome-unknown"): ("ahc-core",),   # one more readback, no conclusion
        ("absent-proven", "intent"): ("ahc-core",),
        ("absent-proven", "held"): ("ahc-core",),
        ("absent-proven", "abandoned"): ("ahc-core",),
        ("held", "confirmed"): OPERATORS + ("reconcile",),
        ("held", "absent-proven"): OPERATORS + ("reconcile",),
        ("held", "abandoned"): OPERATORS + ("reconcile",),
    }

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
        return row, self._row("operations", "key", key)

    def _grant_ok_for_dispatch(self, row):
        if not row["grant_id"]:
            return True
        g = self._row("grants", "id", row["grant_id"])
        return g is not None and g["state"] == "reserved" and g["operation"] == row["key"]

    def dispatch(self, key, *, expected_version, event_id, lease_ok, heartbeat_ok=True, request_id=None,
                 actor="ahc-core"):
        """intent -> dispatched. The count rises BEFORE the request leaves; the caller sends only after this commits."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None:
                raise ContractError("no operation %s" % key)
            if row["dispatch_count"] >= B10_DISPATCHES:
                raise ContractError("dispatch budget B10 is spent for %s" % key)
            if lease_ok is not True or heartbeat_ok is not True:
                raise ContractError("dispatch needs a re-read valid lease and a fresh core heartbeat")
            if not self._grant_ok_for_dispatch(row):
                raise ContractError("dispatch needs the grant reserved for this operation")
            now = self.now()
            return self._op_move(key, "dispatched", expected_version, event_id, actor, {
                "dispatch_count": row["dispatch_count"] + 1, "dispatched_at": now, "request_id": request_id,
                "probe_at": now + B55_REQUEST_SECONDS})[1]

    def confirm(self, key, evidence, *, expected_version, event_id, actor="ahc-core"):
        """-> confirmed: the endpoint readback shows the effect bound to this key. The grant is consumed."""
        if not isinstance(evidence, dict) or not evidence:
            raise ContractError("confirmed needs the endpoint readback evidence")
        with self.tx():
            row = self._row("operations", "key", key)
            if row is not None and row["state"] == "held" and actor not in self.OPERATORS + ("reconcile",):
                raise ContractError("a held operation is settled only by an operator or the reconcile read")
            _, new = self._op_move(key, "confirmed", expected_version, event_id, actor,
                                   {"evidence": _canon(evidence)})
            self._settle_grant_for(new, "confirmed", event_id)
            return new

    def absent(self, key, proof, evidence, *, expected_version, event_id, request_closed=False, actor="ahc-core"):
        """-> absent-proven, only with the 2.5 proof: from dispatched a typed refusal; from outcome-unknown a
        server idempotency answer, a quiescence acknowledgement, or the adapter's fence with the request known
        closed and B54 elapsed. "Not there now" is never proof."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None:
                raise ContractError("no operation %s" % key)
            frm = row["state"]
            if frm == "dispatched" and proof != "typed-refusal":
                raise ContractError("dispatched -> absent-proven needs a typed refusal from the endpoint")
            if frm == "outcome-unknown":
                if proof not in self.PROOFS_FROM_UNKNOWN:
                    raise ContractError("outcome-unknown -> absent-proven needs the 2.5 proof, got %r" % proof)
                if proof == "fence-closed-quiet" and not (
                        request_closed and self.now() - float(row["dispatched_at"] or 0) >= B54_LATE_SECONDS):
                    raise ContractError("fence proof needs the request known closed and B54 elapsed since dispatch")
            if not isinstance(evidence, dict) or not evidence:
                raise ContractError("absent-proven records its evidence")
            return self._op_move(key, "absent-proven", expected_version, event_id, actor,
                                 {"proof": proof, "evidence": _canon(evidence)})[1]

    def unknown(self, key, *, expected_version, event_id, restart=False, actor="ahc-core"):
        """dispatched -> outcome-unknown when B55 passed or a restart found no conclusive readback."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None:
                raise ContractError("no operation %s" % key)
            if not restart and self.now() < float(row["probe_at"] or 0):
                raise ContractError("the request has not timed out yet (B55)")
            now = self.now()
            return self._op_move(key, "outcome-unknown", expected_version, event_id, actor, {
                "readbacks": 0, "probe_at": now + B37_PROBE_SECONDS, "escalate_at": now + B42_INCIDENT_SECONDS})[1]

    def readback_missed(self, key, *, expected_version, event_id):
        """One inconclusive readback of an unknown outcome. At the B37 count: held (Q), one incident, the grant
        stays reserved and the record cannot expire."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None or row["state"] != "outcome-unknown":
                raise ContractError("readback applies to an outcome-unknown operation")
            count = row["readbacks"] + 1
            if count >= B37_PROBES:
                return self._op_move(key, "held", expected_version, event_id, "ahc-core",
                                     {"readbacks": count, "incident": 1, "probe_at": None})[1]
            return self._op_move(key, "outcome-unknown", expected_version, event_id, "ahc-core",
                                 {"readbacks": count, "probe_at": self.now() + B37_PROBE_SECONDS})[1]

    def retry(self, key, params, *, expected_version, event_id, lease_ok):
        """absent-proven -> intent (count below B10, same parameters, lease valid, grant not revoked), else -> held."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None or row["state"] != "absent-proven":
                raise ContractError("retry applies to an absent-proven operation")
            if _sha(params) != row["params_sha256"]:
                raise OperationConflict("a retry must carry the same parameters")
            grant = self._row("grants", "id", row["grant_id"]) if row["grant_id"] else None
            if row["dispatch_count"] >= B10_DISPATCHES or (grant is not None and grant["state"] == "revoked"):
                return self._op_move(key, "held", expected_version, event_id, "ahc-core", {"incident": 1})[1]
            if lease_ok is not True:
                raise ContractError("retry needs a valid lease")
            return self._op_move(key, "intent", expected_version, event_id, "ahc-core")[1]

    def abandon(self, key, *, expected_version, event_id, actor="ahc-core", evidence=None):
        """intent or absent-proven -> abandoned (owning item cancelled or superseded): the grant goes back to
        active, or expired past B47. held -> abandoned only by an operator with evidence; the outcome is still
        unknown, so the grant is spent (uncertain use is spent)."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None:
                raise ContractError("no operation %s" % key)
            if row["state"] == "held" and not (isinstance(evidence, dict) and evidence):
                raise ContractError("settling a held operation needs evidence")
            old, new = self._op_move(key, "abandoned", expected_version, event_id, actor,
                                     {"evidence": _canon(evidence) if evidence else None})
            self._settle_grant_for(new, "abandoned-unknown" if old["state"] == "held" else "released", event_id)
            return new

    def retain(self):
        """B48: a terminal operation older than B48 after settlement becomes a tombstone (key, outcome, settled_at
        kept; parameters dropped). A non-terminal operation never expires."""
        cutoff = self.now() - B48_RETENTION_SECONDS
        with self.tx():
            cur = self.db.execute("UPDATE operations SET tombstone=1, params=NULL, evidence=NULL WHERE tombstone=0 "
                                  "AND state IN ('confirmed', 'abandoned') AND settled_at IS NOT NULL "
                                  "AND settled_at <= ?", (cutoff,))
            return cur.rowcount
