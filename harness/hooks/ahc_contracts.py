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
from pathlib import Path

import ahc_clock
import ahc_fs as fs
from ahc_crash import crash_after, crash_before

# The attached spec these tables implement: M-1 v2g16 (goodqa#16049, attach comment 1a9b9eaf). The vendored copy of
# its State machine section, docs/spec/ahc-m1-state-machine.md, names this core in its header (AC-1).
SPEC_CORE_SHA256 = "0130008d4280234e1320b0d433a5dcfabe210dda228b2e9893745ae40a2b006f"

# Bounds from design v3 1.1 (the only numbers here)
B10_DISPATCHES = 3            # physical dispatches per operation key, in total, the first included
B37_PROBE_SECONDS = 60        # readback rate per unknown outcome
B37_PROBES = 20               # automatic readbacks per episode before held
B42_INCIDENT_SECONDS = 1800   # unknown-effect age that raises an incident
B47_GRANT_SECONDS = 86400     # grant lifetime
B48_RETENTION_SECONDS = 30 * 86400   # operation record retention after settlement; then a tombstone, kept forever
B55_REQUEST_SECONDS = 120     # one effect, readback or probe request
# spec ahc-m1-v2g2: there is no B54 horizon (Codex v2e F2): elapsed time never abandons an operation.
FENCED_ESCALATE_SECONDS = 4 * 3600   # a fenced op escalates to main 4 h after entry (then every 24 h, runner side)
E13_FIRST_READ_SECONDS = 120         # E13's first activity read is at least 2 min after the dispatch
E13_READ_GAP_SECONDS = 60            # and its second read at least 60 s after the first (activity lag, CHK-ACT)

# Schema v4 (spec ahc-m1-v2g2, folded into v4 by the spec owner's ruling: no v4 ledger was ever installed). Code
# review rows bind (repo, pr, H, B_r, packet, revision); spec rows store snapshot_base '' (never NULL, so the
# unique key still de-duplicates). Spec rows also bind the spec core they review (`spec_core`, folded into v4 by the
# spec owner's slice 1a ruling Q-A6); code rows store ''. Grants are scoped (repo, pr, H, B); operations keyed (repo, pr, B, H, revision,
# g). There is no candidate M: integration is a fast-forward of the default branch from B to H.
SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL,
  snapshot_base TEXT NOT NULL, packet_sha256 TEXT NOT NULL, policy_revision TEXT NOT NULL, state TEXT NOT NULL,
  version INTEGER NOT NULL, receipt TEXT, successor TEXT, producer_unit TEXT, producer_uid INTEGER,
  data TEXT NOT NULL DEFAULT '{}', created REAL NOT NULL, updated REAL NOT NULL,
  spec_core TEXT NOT NULL DEFAULT '',
  round INTEGER NOT NULL DEFAULT 1, base_move INTEGER NOT NULL DEFAULT 0,
  CHECK ((kind = 'spec' AND length(spec_core) = 64 AND spec_core NOT GLOB '*[^0-9a-f]*')
         OR (kind != 'spec' AND spec_core = '')),
  CHECK (round >= 1 AND base_move IN (0, 1)),
  UNIQUE(item, kind, repo, pr, head, snapshot_base, packet_sha256, policy_revision, spec_core, round));
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, principal TEXT NOT NULL,
  repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL, base TEXT NOT NULL,
  policy_revision TEXT NOT NULL, uses INTEGER NOT NULL, expires_at REAL NOT NULL, state TEXT NOT NULL,
  operation TEXT, authority_epoch INTEGER NOT NULL, kill_epoch INTEGER NOT NULL, cap_day INTEGER NOT NULL,
  cap_held INTEGER NOT NULL, authority_seq INTEGER, version INTEGER NOT NULL, created REAL NOT NULL,
  updated REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS grants_one_live_per_scope ON grants(kind, repo, pr, base, head)
  WHERE state IN ('validated', 'active', 'reserved');
CREATE TABLE IF NOT EXISTS operations (
  key TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, repo TEXT NOT NULL, pr INTEGER NOT NULL,
  head TEXT NOT NULL, base TEXT NOT NULL, policy_revision TEXT NOT NULL,
  generation INTEGER NOT NULL, params TEXT, params_sha256 TEXT NOT NULL, grant_id TEXT,
  state TEXT NOT NULL, dispatch_count INTEGER NOT NULL DEFAULT 0, proven_absent INTEGER NOT NULL DEFAULT 0,
  dispatched_at REAL, wait_mono REAL, wait_boot TEXT, request_id TEXT, refusal TEXT, probe_at REAL, escalate_at REAL,
  readbacks INTEGER NOT NULL DEFAULT 0, proof TEXT, evidence TEXT, incident INTEGER NOT NULL DEFAULT 0,
  pr_unmarked INTEGER NOT NULL DEFAULT 0, settled_at REAL, tombstone INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS attributions (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, entry_id TEXT UNIQUE, op_key TEXT NOT NULL, repo TEXT NOT NULL,
  how TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS contract_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
INSERT OR IGNORE INTO contract_meta(k, v) VALUES ('authority_epoch', '1');
CREATE TABLE IF NOT EXISTS repo_flags (
  repo TEXT PRIMARY KEY, merging_off INTEGER NOT NULL, cause TEXT, actor TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS work_items (
  id TEXT PRIMARY KEY, lineage TEXT NOT NULL, repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL,
  base TEXT NOT NULL, policy_revision TEXT NOT NULL, spec_core TEXT NOT NULL, packet_sha256 TEXT NOT NULL,
  state TEXT NOT NULL, marks TEXT NOT NULL DEFAULT '', successor TEXT, cause TEXT, version INTEGER NOT NULL,
  created REAL NOT NULL, updated REAL NOT NULL, elig_core TEXT, elig_policy TEXT, w21_base TEXT,
  red_team INTEGER NOT NULL DEFAULT 0 CHECK (red_team IN (0, 1)),
  CHECK (state IN ('pr-gate', 'merge-ready', 'waiting-dep', 'waiting-ask', 'exhausted', 'merged',
                   'headed-verified', 'handed-to-staging', 'superseded', 'closed-unmerged', 'cancelled')),
  CHECK (marks IN ('', 'head-moved', 'closed-in-flight')));
CREATE UNIQUE INDEX IF NOT EXISTS work_items_one_live_per_head ON work_items(repo, pr, head)
  WHERE state NOT IN ('headed-verified', 'handed-to-staging', 'superseded', 'closed-unmerged', 'cancelled');
CREATE TABLE IF NOT EXISTS wi_notices (
  event_id TEXT NOT NULL, item TEXT NOT NULL, row_id TEXT NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL,
  created REAL NOT NULL, delivered REAL,
  CHECK (kind IN ('incident', 'ticket', 'owner', 'digest')), PRIMARY KEY (event_id, kind));
CREATE TABLE IF NOT EXISTS transitions (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT NOT NULL, id TEXT NOT NULL, from_state TEXT,
  to_state TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE, actor TEXT NOT NULL, at REAL NOT NULL, data TEXT);
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY, boot TEXT NOT NULL, mono REAL NOT NULL, seq INTEGER NOT NULL, at REAL NOT NULL,
  repo TEXT NOT NULL, pr INTEGER NOT NULL, item TEXT, source TEXT NOT NULL, refs TEXT NOT NULL,
  digest TEXT NOT NULL, fields TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS w21_sends (
  request_id TEXT PRIMARY KEY, item TEXT NOT NULL, repo TEXT NOT NULL, pr INTEGER NOT NULL, base TEXT NOT NULL,
  head TEXT NOT NULL, seq INTEGER NOT NULL, event_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL, reason TEXT,
  attempted_at REAL, gh_request_id TEXT, new_head TEXT, successor TEXT, version INTEGER NOT NULL,
  created REAL NOT NULL, updated REAL NOT NULL,
  CHECK (state IN ('intent', 'attempted', 'readback-pending', 'lost', 'resolved', 'cancelled')),
  UNIQUE(item, base, seq));
CREATE UNIQUE INDEX IF NOT EXISTS w21_one_unresolved_per_repo ON w21_sends(repo)
  WHERE state IN ('intent', 'attempted', 'readback-pending');
CREATE TABLE IF NOT EXISTS launch_intents (
  id TEXT PRIMARY KEY, row TEXT NOT NULL, row_version INTEGER NOT NULL, unit TEXT NOT NULL UNIQUE,
  cmd_sha256 TEXT NOT NULL, lineage TEXT NOT NULL, charge INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT,
  created REAL NOT NULL, updated REAL NOT NULL,
  CHECK (state IN ('open', 'started', 'closed', 'orphaned')));
CREATE TABLE IF NOT EXISTS review_blocks (
  row TEXT PRIMARY KEY, unit TEXT NOT NULL, reason TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS lineage_budget (
  lineage TEXT PRIMARY KEY, b33_used INTEGER NOT NULL DEFAULT 0 CHECK (b33_used >= 0));
CREATE TABLE IF NOT EXISTS timers (
  owner TEXT NOT NULL, name TEXT NOT NULL, deadline_wall REAL NOT NULL, duration REAL NOT NULL, boot TEXT,
  anchor REAL, PRIMARY KEY (owner, name));
CREATE TABLE IF NOT EXISTS w16_proofs (
  proof_id TEXT PRIMARY KEY, item TEXT NOT NULL, target TEXT NOT NULL, expected_version INTEGER NOT NULL,
  argv_sha256 TEXT NOT NULL, accepted TEXT NOT NULL DEFAULT '[]', ticket TEXT, extension INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL,
  CHECK (target IN ('pr-gate', 'cancelled')), CHECK (extension >= 0));
CREATE TABLE IF NOT EXISTS wi_quarantine (
  event_id TEXT NOT NULL, item TEXT NOT NULL, row_id TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT NOT NULL,
  created REAL NOT NULL, PRIMARY KEY (event_id, kind));
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


def _is_oid(value):
    return isinstance(value, str) and len(value) in (40, 64) and all(c in "0123456789abcdef" for c in value)


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
            directory = Path(os.path.abspath(os.path.dirname(self.path) or "."))
            os.makedirs(str(directory), mode=0o700, exist_ok=True)   # the log's own directory; fs checks it next
            crash_before("contracts.authority")
            # the log's directory is its root: it must be ours at 0700, and the append never follows a link
            fs.append_file(directory, directory / os.path.basename(self.path), _canon(entry) + "\n")
            crash_after("contracts.authority")
        except OSError as error:
            raise AuthorityError("authority record not written: %s" % type(error).__name__) from None
        return entry["seq"]


# ------------------------------------------------------------------ common guard and action

def _boot_id():
    """This boot's id (D-a3): monotonic stamps compare only within one boot. On Linux it is the kernel's boot id.
    Elsewhere it is an id for this process, so an observation stamped by another process counts as stale, which
    fails closed."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if value:
            return "linux:" + value
    except OSError:
        pass
    return "process:%d:%s" % (os.getpid(), os.urandom(8).hex())


class Contracts:
    """Transitions over one connection. `now` (wall clock: log stamps and the CAP1 UTC day), `mono` (monotonic
    clock: observation age, T2/D-a3) and `boot_id` are injectable for tests; `authority` is an AuthorityLog."""

    def __init__(self, db, authority, now=None, mono=None, boot_id=None):
        self.db = db
        self.authority = authority
        self._now = now or time.time
        self._mono = mono or ahc_clock.boot_clock      # AC-10: CLOCK_BOOTTIME where the platform has it
        self.boot_id = boot_id or _boot_id()
        # AC-10: every timer reads this one clock service (effective wall plus boot-clock elapsed)
        self.clock = ahc_clock.Clock(db, wall=self._now, boot=self._mono, boot_id=self.boot_id)

    def stamp(self, obs):
        """An observation row stamped as read now: wall time for the log, plus this boot's monotonic stamp that
        T2 measures age on. Producers call this at the moment they read the facts."""
        return dict(obs, at=self.now(), mono=float(self._mono()), boot=self.boot_id)

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
        crash_before("contracts.commit")
        self.db.execute("COMMIT")
        crash_after("contracts.commit")

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

    # -------------------------------------------------------------- WorkItem (spec M-1 v2g16, W1-W27)

    # Shadow only in slice 1 (a): the P0 item machine in ahc_runner stays authoritative until the cutover, and no
    # WorkItem row sends anything. These tables equal the vendored spec section one to one (AC-1,
    # tests.test_ahc_core.TransitionTableTests). States: name -> (class, outcome, next actor).
    WI_STATES = {
        "pr-gate": ("active", "-", "ahc-review"),
        "merge-ready": ("active", "-", "ahc-core"),
        "waiting-dep": ("waiting", "-", "ahc-core"),
        "waiting-ask": ("waiting", "-", "main"),
        "exhausted": ("waiting", "-", "main"),
        "merged": ("waiting", "-", "ahc-core"),
        "headed-verified": ("terminal", "success", "none"),
        "handed-to-staging": ("terminal", "neutral", "none"),
        "superseded": ("terminal", "neutral", "none"),
        "closed-unmerged": ("terminal", "failure", "none"),
        "cancelled": ("terminal", "neutral", "none"),
    }
    _WI_LIVE = ("pr-gate", "merge-ready", "waiting-dep", "waiting-ask", "exhausted")
    _WI_INFLIGHT = ("merge-ready", "pr-gate", "waiting-ask")      # where an unsettled Effect can be (T7, W24)
    # Rows: id -> (from states, to states, actor). W24 keeps the item where it is, so its To is its From.
    WI_TRANSITIONS = {
        "W1": (("(entry)",), ("pr-gate",), "ahc-core"),
        "W2": (("pr-gate",), ("merge-ready",), "ahc-core"),
        "W3": (("pr-gate",), ("waiting-ask",), "ahc-core"),
        "W4": (_WI_LIVE, ("superseded",), "ahc-core"),
        "W5": (("merge-ready",), ("waiting-dep",), "ahc-core"),
        "W6": (("waiting-dep",), ("merge-ready",), "ahc-core"),
        "W7": (("merge-ready",), ("merge-ready",), "ahc-core"),
        "W8": (("merge-ready",), ("merged",), "ahc-core"),
        "W9": (("merge-ready",), ("pr-gate",), "ahc-core"),
        "W10": (("merge-ready",), ("waiting-ask",), "ahc-core"),
        "W11": (("merged",), ("handed-to-staging",), "ahc-core"),
        "W12": (("merged",), ("headed-verified",), "ahc-core"),
        "W13": (_WI_LIVE, ("closed-unmerged",), "ahc-core"),
        "W14": (_WI_LIVE, ("merged",), "ahc-core"),
        "W15": (("pr-gate",), ("exhausted",), "ahc-core"),
        "W16": (("waiting-ask", "exhausted", "waiting-dep"), ("pr-gate", "cancelled"), "main"),
        "W17": (("pr-gate", "merge-ready", "waiting-dep"), ("waiting-ask",), "ahc-core"),
        "W18": (("pr-gate", "merge-ready", "waiting-dep"), ("pr-gate",), "ahc-core"),
        "W19": (("pr-gate",), ("waiting-ask",), "ahc-core"),
        "W20": (("pr-gate",), ("cancelled",), "owner"),
        "W21": (("pr-gate",), ("pr-gate",), "ahc-core"),
        "W22": (("pr-gate",), ("waiting-ask",), "ahc-core"),
        "W23": (("pr-gate",), ("waiting-ask",), "ahc-core"),
        "W24": (_WI_INFLIGHT, _WI_INFLIGHT, "ahc-core"),
        "W25": (_WI_INFLIGHT, ("superseded", "closed-unmerged"), "ahc-core"),
        # W26 from waiting-dep and exhausted is defensive (spec owner ruling Q-A5.2): T7 keeps an unsettled Effect
        # out of those states, but a confirmed merge found there is still recorded, never lost.
        "W26": (("pr-gate", "waiting-dep", "waiting-ask", "exhausted"), ("merged",), "ahc-core"),
        "W27": (("merge-ready",), ("pr-gate",), "ahc-core"),
    }
    WI_TERMINAL = tuple(s for s, (cls, _o, _a) in WI_STATES.items() if cls == "terminal")
    # T7: an Effect in one of these states is unsettled. The spec lists dispatched, outcome-unknown, held and fenced;
    # absent-proven is unsettled too (spec owner ruling, note 8: E7 can re-dispatch it). intent is not: an unsent
    # intent is abandoned by E9 when the item leaves merge-ready.
    T7_UNSETTLED = ("dispatched", "outcome-unknown", "held", "fenced", "absent-proven")
    T7_ALLOWED = ("W8", "W9", "W10", "W24", "W25", "W26")      # the only rows that move an item with one (T7)
    # T7 precedence when two guards hold at once. G8 and G9 are Grant rows evaluated in the same tick (ruling
    # Q-A5.3); select_row orders them with the WorkItem rows and never treats them as WorkItem rows.
    T7_ORDER = ("W4", "W13", "W14", "W18", "W19", "W17", "G8", "G9")
    GRANT_ROWS = ("G8", "G9")
    # Rows whose guard reads only ledger facts are applied here. Rows whose guard needs ELIG, an observation, a
    # budget or main's stamp are wired in later steps of slice 1 (a); until then they are refused (fail closed).
    WI_WIRED = ("W2", "W3", "W4", "W5", "W6", "W8", "W9", "W10", "W13", "W14", "W17", "W18", "W20", "W21", "W24",
                "W25", "W26", "W27")
    PR_STATES = ("OPEN", "CLOSED", "MERGED")

    @classmethod
    def select_row(cls, holding, unsettled):
        """T7: which row moves the item when every row in `holding` has its guard satisfied. With an unsettled
        Effect only T7_ALLOWED rows (and the Grant rows) qualify; then the T7 order; then the lowest-numbered row
        (numerically: W21 before W22 before W23). Returns None when nothing qualifies."""
        rows = []
        for r in holding:
            if r not in cls.WI_TRANSITIONS and r not in cls.GRANT_ROWS:
                raise ContractError("unknown row %r" % r)
            if unsettled and r not in cls.T7_ALLOWED and r not in cls.GRANT_ROWS:
                continue
            rows.append(r)
        if not rows:
            return None
        ranked = [r for r in cls.T7_ORDER if r in rows]
        if ranked:
            return ranked[0]
        return min(rows, key=lambda r: int(r[1:]))

    @staticmethod
    def lineage_of(repo, pr):
        return "ln-" + _sha({"repo": str(repo).lower(), "pr": int(pr)})[:24]

    def admit_item(self, repo, pr, head, base, policy_revision, spec_core, packet_sha256, *, event_id,
                   actor="ahc-core", red_team=False):
        """W1 (entry) -> pr-gate for (lineage, H, B), creating the required Review rows bound to (repo, pr, H, B):
        adversarial and spec, plus red-team when the class requires it. NEG-11: a resubmit at the same head returns
        the live item unchanged; no state, version or Review row moves."""
        if actor != self.WI_TRANSITIONS["W1"][2]:
            raise ContractError("W1: only ahc-core admits an item")
        repo = str(repo).lower()
        for name, value in (("head", head), ("base", base)):
            if not _is_oid(value):
                raise ContractError("an item's %s is a full sha" % name)
        if head == base:
            raise ContractError("an item's head equals its base; nothing to integrate")
        with self.tx():
            live = self.db.execute("SELECT id FROM work_items WHERE repo=? AND pr=? AND head=? AND state NOT IN (%s)"
                                   % ",".join("?" * len(self.WI_TERMINAL)),
                                   (repo, int(pr), head) + self.WI_TERMINAL).fetchone()
            if live:
                return self._row("work_items", "id", live[0])
            iid = "wi-" + _sha({"repo": repo, "pr": int(pr), "head": head, "base": base, "event": event_id})[:24]
            self._g0("work_item", None, None, event_id, actor, {(None, "pr-gate"): (actor,)}, None, "pr-gate")
            now = self.now()
            # PR 268 F2: the class's required review kinds are stored on the item, so a successor (W4, W24)
            # requires the same kinds and e1 can check that none is missing
            self.db.execute("INSERT INTO work_items(id, lineage, repo, pr, head, base, policy_revision, spec_core, "
                            "packet_sha256, state, version, created, updated, red_team) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (iid, self.lineage_of(repo, pr), repo, int(pr), head, base, policy_revision, spec_core,
                             packet_sha256, "pr-gate", 1, now, now, 1 if red_team else 0))
            kinds = ("adversarial", "spec") + (("red-team",) if red_team else ())
            for kind in kinds:
                code = kind in self.ATTEMPT_KINDS
                self.require_review(kind, repo, pr, head, packet_sha256, policy_revision, item=iid,
                                    event_id="%s-%s" % (event_id, kind), snapshot_base=base if code else "",
                                    spec_core="" if code else spec_core)
            self._a0("work_item", iid, None, "pr-gate", event_id, actor, row="W1")
            return self._row("work_items", "id", iid)

    @staticmethod
    def _finding_ids(receipt):
        """The finding ids a findings receipt names (its `finding_ids` list); anything malformed names none."""
        try:
            ids = json.loads(receipt).get("finding_ids") if receipt else None
        except (ValueError, AttributeError):
            return []
        return [i for i in ids if isinstance(i, str) and i] if isinstance(ids, list) else []

    def _item_effects(self, item):
        return self.db.execute("SELECT key, state, version FROM operations WHERE item=? AND head=?",
                               (item["id"], item["head"])).fetchall()

    def item_unsettled(self, item):
        """T7: the item has an Effect for its H in an unsettled state."""
        return any(state in self.T7_UNSETTLED for _k, state, _v in self._item_effects(item))

    def _wi_obs(self, item, obs, *fields):
        """T2: a GitHub fact in a guard is a fresh observation row (under 2 min, never from the future) for this
        item's repo and PR, carrying the named fields. A missing, stale, foreign or malformed one fails closed."""
        self._fresh(obs)
        if str(obs.get("repo", "")).lower() != item["repo"] or obs.get("pr") != item["pr"]:
            raise ContractError("the observation is for another repo or PR")
        for f in fields:
            if f not in obs:
                raise ContractError("the observation has no %s" % f)
        if "pr_state" in fields and obs["pr_state"] not in self.PR_STATES:
            raise ContractError("unknown PR state %r" % obs["pr_state"])
        for f in ("pr_head", "tip"):
            if f in fields and not _is_oid(obs[f]):
                raise ContractError("the observation's %s is not a full sha" % f)
        return obs

    def _wi_notice(self, event_id, item, row_id, kind, text):
        """An escalation written in the row's own transaction (T3); delivery is the outbox's job (H5, later)."""
        self.db.execute("INSERT INTO wi_notices(event_id, item, row_id, kind, text, created) VALUES (?,?,?,?,?,?)",
                        (event_id, item["id"], row_id, kind, text, self.now()))

    # NEG-6 protected paths (spec M-1 v2g16). A pattern without a slash matches the file name at any depth; one
    # with a slash matches the full path from the repo root. Renames are checked on both paths (the caller lists
    # both). The policy file and the test configuration files named under Required checks are added per repo by
    # the policy record (`extra_protected`).
    MIRROR_CAUSE = "mirror undeliverable"     # W5's cause when ELIG holds but the mirror cannot be delivered

    NEG6 = ("merge_gate*", "peer_review*", "caller_identity*", "usage_guard*", "commit_policy*", "ahc*",
            "settings*.json", "hooks_manifest.json", ".github/**", "CODEOWNERS", ".claude/**", ".mcp.json",
            ".codex/**", "CLAUDE.md", "AGENTS.md", "conftest*", "pytest.ini", "setup.cfg", "tox.ini",
            "pyproject.toml", "tests/__init__.py")

    @classmethod
    def protected_path(cls, path, extra=()):
        import fnmatch
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/"):
            return True                                               # an unreadable path counts as protected
        name = path.rsplit("/", 1)[-1]
        for pat in cls.NEG6 + tuple(extra):
            if pat.endswith("/**"):
                if path.startswith(pat[:-2]):
                    return True
            elif "/" in pat:
                if fnmatch.fnmatchcase(path, pat):
                    return True
            elif fnmatch.fnmatchcase(name, pat):
                return True
        return False

    ELIG_FIELDS = ("pr_state", "pr_head", "draft", "tip", "compare", "b_r_ancestors", "attached_core",
                   "open_findings", "paths", "foreign_closing_keyword", "policy", "kill_switch", "chk_cas",
                   "canary_age")

    def elig(self, item, obs, skip=()):
        """ELIG (spec M-1 v2g16), one definition for W2, W6, the queue head and (b)'s G1/E2. Returns the failed
        clauses, empty when ELIG holds. Ledger facts are read here, inside the caller's transaction (T1); GitHub,
        GoodQA and policy facts come from one fresh observation row (T2). Every clause fails closed: a missing,
        malformed or stale field fails its clause, never passes it."""
        failed = []
        try:
            o = self._wi_obs(item, obs, *self.ELIG_FIELDS)
        except ContractError:
            return ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10"]
        head, tip = item["head"], o["tip"]
        pol = o["policy"] if isinstance(o["policy"], dict) else {}
        # e1: every required code Review row passed for (H, packet, policy revision); each B_r an ancestor of B
        code = self.db.execute("SELECT kind, state, snapshot_base FROM reviews WHERE "
                               "item=? AND head=? AND kind IN ('adversarial', 'red-team') AND policy_revision=? "
                               "AND packet_sha256=?", (item["id"], head, item["policy_revision"],
                                                      item["packet_sha256"])).fetchall()
        anc = o["b_r_ancestors"] if isinstance(o["b_r_ancestors"], dict) else {}
        required = {"adversarial"} | ({"red-team"} if item["red_team"] else set())   # PR 268 F2: none missing
        if (not required <= {k for k, _s, _b in code} or o["pr_head"] != head
                or pol.get("revision") != item["policy_revision"]
                or any(s != "passed" or anc.get(br) is not True for _k, s, br in code)):
            failed.append("e1")
        # e2: the spec row for the spec core attached NOW, at this item's packet and policy revision, has passed
        # (PR 268 F1: after W27 the old revision's pass stays terminal beside the replacement and must not count)
        spec = self.db.execute("SELECT state FROM reviews WHERE item=? AND head=? AND kind='spec' AND spec_core=? "
                               "AND policy_revision=? AND packet_sha256=?",
                               (item["id"], head, o["attached_core"], item["policy_revision"],
                                item["packet_sha256"])).fetchall()
        if o["attached_core"] != item["spec_core"] or [s for (s,) in spec] != ["passed"]:
            failed.append("e2")
        if o["open_findings"] != 0 or isinstance(o["open_findings"], bool):
            failed.append("e3")
        paths = o["paths"]
        if (not isinstance(paths, list) or not paths or o["foreign_closing_keyword"] is not False
                or any(self.protected_path(p, pol.get("extra_protected", ())) for p in paths)):
            failed.append("e4")
        flags = self.db.execute("SELECT merging_off FROM repo_flags WHERE repo=?", (item["repo"],)).fetchone()
        if (pol.get("readable") is not True or pol.get("allowlisted") is not True or pol.get("enabled") is not True
                or pol.get("checks_green") is not True or (flags and flags[0])):
            failed.append("e5")
        frozen = self.db.execute("SELECT v FROM contract_meta WHERE k='authority_frozen'").fetchone()
        if o["kill_switch"] is not False or (frozen and frozen[0] == "1"):
            failed.append("e6")
        if self.cap_used(item["repo"]) >= self.CAP1_PER_DAY:
            failed.append("e7")
        if o["pr_state"] != "OPEN" or o["draft"] is not False:
            failed.append("e8")
        age = o["canary_age"]
        if o["chk_cas"] is not True or not isinstance(age, (int, float)) or isinstance(age, bool) or not 0 <= age < 86400:
            failed.append("e9")
        if o["compare"] != "ahead" or tip == head:
            failed.append("e10")
        return [c for c in failed if c not in skip]

    def queue_head(self, repo, observations):
        """The merge queue head for a repo: among its items in pr-gate or merge-ready, ordered by lineage
        admission time, the oldest for which every ELIG clause except e10 holds. `observations` maps item id to
        its ELIG observation; an item without one is not eligible. (The W21-successor exception is wired with
        W21's readback in slice 1 (b).)"""
        rows = self.db.execute(
            "SELECT w.id, (SELECT MIN(created) FROM work_items x WHERE x.lineage = w.lineage) AS admitted "
            "FROM work_items w WHERE w.repo=? AND w.state IN ('pr-gate', 'merge-ready') ORDER BY admitted, w.created, "
            "w.id", (str(repo).lower(),)).fetchall()
        for iid, _admitted in rows:
            item = self._row("work_items", "id", iid)
            if iid in observations and not self.elig(item, observations[iid], skip=("e10",)):
                return iid
        return None

    def wi_move(self, iid, row_id, *, expected_version, event_id, actor, to=None, mark=None, cause=None, obs=None,
                successor_packet=None):
        """The one WorkItem transition function (T1 to T7). One BEGIN IMMEDIATE; the guard re-reads its ledger
        facts; the state change and one audit row commit together (T3). A replay of the same event for the same
        item and row is a no-op that returns the current row (T6), checked before the version so a post-crash replay
        with a stale expected version still lands as a no-op."""
        with self.tx():
            item = self._row("work_items", "id", iid)
            if item is None:
                raise ContractError("no work item %s" % iid)
            prior = self.db.execute("SELECT entity, id, data FROM transitions WHERE event_id=?",
                                    (event_id,)).fetchone() if isinstance(event_id, str) else None
            if prior is not None:
                data = json.loads(prior[2]) if prior[2] else {}
                if prior[0] == "work_item" and prior[1] == iid and data.get("row") == row_id:
                    return item                                     # T6: a replay is a no-op
                raise ContractError("event id %s was already applied to another subject" % event_id)
            if row_id not in self.WI_TRANSITIONS:
                raise ContractError("unknown WorkItem row %r" % row_id)
            src, dst, row_actor = self.WI_TRANSITIONS[row_id]
            if actor != row_actor:
                if actor == "owner":   # NEG-11: an owner's resubmit or ack never moves an item; only W20 is theirs
                    raise ContractError("NEG-11: an owner action moves a work item only by W20 (cancel)")
                raise ContractError("%s is taken by %s, not %r" % (row_id, row_actor, actor))
            frm = item["state"]
            if frm not in src:
                raise ContractError("%s does not leave %s" % (row_id, frm))
            if row_id == "W24":
                to = frm                                            # W24 keeps the item where it is
            elif to is None:
                if len(dst) != 1:
                    raise ContractError("%s needs its target, one of %s" % (row_id, ", ".join(dst)))
                to = dst[0]
            if to not in dst:
                raise ContractError("%s goes to %s, not %r" % (row_id, ", ".join(dst), to))
            if item["version"] != expected_version:
                raise VersionConflict("work item version is %s, caller expected %s" % (item["version"],
                                                                                         expected_version))
            if not isinstance(event_id, str) or not event_id:
                raise ContractError("an event id is required")
            unsettled = self.item_unsettled(item)
            if unsettled and row_id not in self.T7_ALLOWED:
                raise ContractError("T7: %s waits while the item's Effect is unsettled" % row_id)
            if unsettled and to in ("waiting-dep", "exhausted"):
                # Q-A5.2: unreachable through the table under T7; kept as an invariant so a future row cannot put
                # an in-flight send where no row settles it. Raised as an incident, never applied.
                raise ContractError("incident: %s would put an item with an unsettled Effect in %s" % (row_id, to))
            if row_id not in self.WI_WIRED:
                raise ContractError("%s is not wired in this build of slice 1 (a); refused, fail closed" % row_id)
            mark = self._wi_guard(item, row_id, to, mark, unsettled, obs)
            base = obs["tip"] if row_id == "W18" else item["base"]
            successor = None
            if row_id == "W4" or (row_id == "W24" and mark == "head-moved" and not item["successor"]):
                successor = self._wi_successor(item, obs["pr_head"], successor_packet, event_id)
            extra = {}
            if row_id in ("W2", "W6"):                      # the values ELIG passed on, for W27
                extra = {"elig_core": item["spec_core"], "elig_policy": item["policy_revision"]}
            elif row_id == "W5":
                # every cause that holds is recorded (note 12 ruling); W6 needs each one cleared
                failed = self.elig(item, obs)
                causes = (["ELIG failed: %s" % ", ".join(failed)] if failed else []) + \
                    ([self.MIRROR_CAUSE] if obs.get("mirror_ok") is False else [])
                cause = "; ".join(causes)                     # derived, never taken from the caller
            elif row_id == "W27":
                extra = {"spec_core": obs["attached_core"], "policy_revision": obs["policy"]["revision"]}
            elif row_id == "W21":
                # authority log first (T4): the record of the one update-branch this item may get at this B. Slice
                # 1 (a) is shadow only: nothing is sent; slice 1 (b)'s ahc-merge sends it after this row commits.
                self.authority.append({"event_id": event_id, "item": iid, "row": "W21", "repo": item["repo"],
                                       "pr": item["pr"], "expected_head_sha": item["head"], "base": obs["tip"],
                                       "action": "update-branch (recorded, not sent)"})
                extra = {"w21_base": obs["tip"]}
            sets = "".join(", %s=?" % k for k in extra)
            self.db.execute("UPDATE work_items SET state=?, marks=?, cause=COALESCE(?, cause), base=?, "
                            "successor=COALESCE(?, successor), version=version+1, updated=?%s WHERE id=?" % sets,
                            (to, mark, cause, base, successor, self.now()) + tuple(extra.values()) + (iid,))
            self._wi_effects(item, row_id, event_id, obs)
            self._a0("work_item", iid, frm, to, event_id, actor, row=row_id, cause=cause,
                     obs=obs.get("id") if isinstance(obs, dict) else None)
            return self._row("work_items", "id", iid)

    def _wi_successor(self, item, new_head, packet_sha256, event_id):
        """W4 and W24: the successor item at H' (W1). It never inherits this item's grant, Effect or Review rows;
        under W4 this item's open Review rows for H go to superseded or, while an attempt may run, cancelling."""
        if not (isinstance(packet_sha256, str) and len(packet_sha256) == 64 and _is_oid(packet_sha256)):
            raise ContractError("the successor at H' needs its own packet sha256")
        succ = self.admit_item(item["repo"], item["pr"], new_head, item["base"], item["policy_revision"],
                               item["spec_core"], packet_sha256, event_id=event_id + "-successor",
                               red_team=bool(item["red_team"]))
        return succ["id"]

    def _wi_effects(self, item, row_id, event_id, obs):
        """The Effects column of the applied row, in the same transaction (T3)."""
        if row_id == "W4":
            new = self._row("work_items", "id", self._row("work_items", "id", item["id"])["successor"])
            by_kind = {k: rid for k, rid in self.db.execute("SELECT kind, id FROM reviews WHERE item=?", (new["id"],))}
            kinds = dict(self.db.execute("SELECT id, kind FROM reviews WHERE item=?", (item["id"],)).fetchall())
            self.supersede_reviews(item["repo"], item["pr"], new["head"],
                                   lambda rid: by_kind.get(kinds.get(rid)) or new["id"], event_id + "-r12")
        if row_id == "W27":
            # SLICE-AT-3: replacement rows for the new core or policy revision; the old passed rows stay terminal
            # and, bound to the old values, no longer satisfy e1 or e2. Queued or infra-wait rows are superseded
            # (R12 lists W27).
            new = self._row("work_items", "id", item["id"])
            made = {}
            for kind in sorted({k for (k,) in self.db.execute("SELECT kind FROM reviews WHERE item=?",
                                                              (item["id"],))}):
                if kind != "spec" and new["policy_revision"] == item["policy_revision"]:
                    continue                              # a core change alone needs only a new spec row
                code = kind in self.ATTEMPT_KINDS
                made[kind] = self.require_review(kind, item["repo"], item["pr"], item["head"], item["packet_sha256"],
                                                 new["policy_revision"], item=item["id"],
                                                 event_id="%s-%s" % (event_id, kind),
                                                 snapshot_base=item["base"] if code else "",
                                                 spec_core="" if code else new["spec_core"])["id"]
            for rid, kind, state, version in self.db.execute(
                    "SELECT id, kind, state, version FROM reviews WHERE item=? AND state IN ('required', 'queued', "
                    "'infra-wait')", (item["id"],)).fetchall():
                if kind in made and rid != made[kind]:
                    self.review(rid, "superseded", expected_version=version, event_id="%s-r12-%s" % (event_id, rid),
                                successor=made[kind], cause="spec core or policy changed (W27)")
        if row_id == "W20":
            # PR 268 F3: the owner withdrew the item; an attempt that may still run is stopped first (R14), so no
            # result can settle its row afterwards (cancelling accepts none; R15 settles it once the unit is gone)
            for rid, version in self.db.execute("SELECT id, version FROM reviews WHERE item=? AND state IN "
                                                "('running', 'outcome-unknown') ORDER BY id",
                                                (item["id"],)).fetchall():
                self.review(rid, "cancelling", expected_version=version, event_id="%s-r14-%s" % (event_id, rid),
                            cause="owner cancelled (W20)")
        if row_id in ("W4", "W5", "W13", "W14", "W17", "W18", "W27"):
            for key, state, version in self._item_effects(item):
                if state == "intent":                                # E9: an intent never sent is abandoned
                    self.abandon_unsent(key, expected_version=version, event_id="%s-e9-%s" % (event_id, key),
                                        reason="item left by %s" % row_id)
        if row_id == "W5":
            self._wi_notice(event_id, item, row_id, "ticket", "waiting on a dependency: %s"
                            % (self._row("work_items", "id", item["id"])["cause"]))
        elif row_id == "W17":
            self._wi_notice(event_id, item, row_id, "ticket", "protected path; main integrates by hand")
        elif row_id == "W3":
            # PR 268 F4: escalate with the finding ids of every findings row (from its bound receipt)
            parts = []
            for rid, kind, receipt in self.db.execute("SELECT id, kind, receipt FROM reviews WHERE item=? AND "
                                                      "state='findings' ORDER BY kind, id", (item["id"],)):
                parts.append("%s %s: %s" % (kind, rid, ", ".join(self._finding_ids(receipt)) or "finding ids missing"))
            text = "findings on " + "; ".join(parts)
            self._wi_notice(event_id, item, row_id, "ticket", text)
            self._wi_notice(event_id, item, row_id, "owner", text)
        elif row_id == "W10":
            # PR 268 F4: the Effect is held; a person decides (the grant stays reserved; W26 settles it)
            keys = [k for k, state, _v in self._item_effects(item) if state == "held"]
            text = "%s held; a person decides" % ", ".join(keys)
            self._wi_notice(event_id, item, row_id, "incident", text)
            self._wi_notice(event_id, item, row_id, "ticket", text)
        elif row_id in ("W8", "W26"):
            # keyed by the op key, not the event, so the integration is announced exactly once (W26: a restart
            # cannot repeat it); recorded as integrated at H only, never at a successor's H'
            key = [k for k, state, _v in self._item_effects(item) if state == "confirmed"][0]
            text = "integrated at %s by %s" % (item["head"], key)
            self._wi_notice("op:%s" % key, item, row_id, "ticket", text)
            self._wi_notice("op:%s" % key, item, row_id, "digest", text)
            if item["marks"] == "closed-in-flight":                                    # L7
                self._wi_notice("op:%s" % key, item, row_id, "owner", "the closed PR's H %s was integrated; revert "
                                "by a normal PR if unwanted" % item["head"])
        elif row_id == "W25":
            key, state, _v = [e for e in self._item_effects(item) if e[1] == "abandoned"][0]
            self._wi_notice(event_id, item, row_id, "ticket", "%s ended %s; item %s" % (
                key, state, self._row("work_items", "id", item["id"])["state"]))
        elif row_id == "W13":
            self._wi_notice(event_id, item, row_id, "ticket", "closed without integration at %s" % item["head"])
        elif row_id == "W14":
            self._wi_notice(event_id, item, row_id, "incident", "PR shows merged; no confirmed ahc Effect made it")
        elif row_id == "W18" and not self.db.execute(
                "SELECT 1 FROM operations WHERE repo=? AND state='confirmed' AND head=? AND base=?",
                (item["repo"], obs["tip"], item["base"])).fetchone():
            # L1, L2: a move no confirmed ahc Effect explains (read from the ledger, never from the caller)
            kind = "digest" if obs.get("fast_forward") is True else "incident"
            self._wi_notice(event_id, item, row_id, kind, "default branch moved %s -> %s" % (item["base"],
                                                                                            obs["tip"]))

    def _wi_guard(self, item, row_id, to, mark, unsettled, obs=None):
        """Guards of the wired rows: ledger facts read inside the transaction (T1) and fresh observations (T2).
        Returns the item's marks after the row."""
        effects = {state for _k, state, _v in self._item_effects(item)}
        marks = item["marks"]
        if row_id in ("W2", "W6"):
            failed = self.elig(item, obs)
            if failed:
                raise ContractError("%s needs ELIG; failed: %s" % (row_id, ", ".join(failed)))
            # W6: every recorded cause has cleared (spec owner ruling on note 12). An ELIG cause is covered by ELIG
            # holding, on this fresh observation; a mirror cause is not an ELIG clause, so the same fresh
            # observation must show mirror_ok True. A stale or other-boot observation already failed ELIG above.
            if row_id == "W6" and self.MIRROR_CAUSE in (item["cause"] or "").split("; ") \
                    and obs.get("mirror_ok") is not True:
                raise ContractError("W6 needs the mirror deliverable again (the recorded cause)")
        elif row_id == "W5":
            failed = self.elig(item, obs)
            mirror_down = isinstance(obs, dict) and obs.get("mirror_ok") is False
            if not (set(failed) & {"e5", "e6", "e7", "e8", "e10"}) and not mirror_down:
                raise ContractError("W5 needs ELIG failing on e5, e6, e7, e8 or e10, or the mirror undeliverable")
        elif row_id == "W17":
            if "e4" not in self.elig(item, obs):
                raise ContractError("W17 needs a protected path or a foreign closing keyword (e4)")
        elif row_id == "W27":
            o = self._wi_obs(item, obs, "attached_core", "policy")
            pol = o["policy"] if isinstance(o["policy"], dict) else {}
            core, revision = o["attached_core"], pol.get("revision")
            if not (isinstance(core, str) and len(core) == 64 and _is_oid(core)) or not isinstance(revision, str) \
                    or not revision:
                raise ContractError("W27 needs the attached spec core and the policy revision read now")
            if (core, revision) == (item["elig_core"], item["elig_policy"]):
                raise ContractError("W27 needs the spec core or the policy revision changed since ELIG passed")
        elif row_id == "W21":
            o = self._wi_obs(item, obs, "queue", "mergeable", "tip")
            queue = o["queue"] if isinstance(o["queue"], dict) else {}
            listed = {r[0] for r in self.db.execute("SELECT id FROM work_items WHERE repo=? AND state IN "
                                                    "('pr-gate', 'merge-ready')", (item["repo"],))}
            if set(queue) != listed:
                raise ContractError("W21 needs an ELIG observation for every item in the repo's queue")
            if self.queue_head(item["repo"], queue) != item["id"]:
                raise ContractError("W21 is taken only by the head of the repo's merge queue")
            failed = self.elig(item, queue[item["id"]])
            if failed != ["e10"]:
                raise ContractError("W21 needs every ELIG clause but e10 to hold, and the PR behind (e10)")
            if o["mergeable"] is not True:
                raise ContractError("W21 needs GitHub reporting the PR mergeable with no conflict")
            if item["w21_base"] == o["tip"]:
                raise ContractError("an update-branch was already recorded for this item at the current B")
        if row_id in ("W4", "W13", "W14"):
            o = self._wi_obs(item, obs, "pr_state", "pr_head")
            want = {"W4": "OPEN", "W13": "CLOSED", "W14": "MERGED"}[row_id]
            if o["pr_state"] != want:
                raise ContractError("%s needs the PR %s, the readback says %s" % (row_id, want, o["pr_state"]))
            if row_id == "W4" and o["pr_head"] == item["head"]:
                raise ContractError("W4 needs the PR head moved away from H")
            if row_id == "W14" and "confirmed" in effects:
                raise ContractError("W14 is for a merge no confirmed ahc Effect made; this item's Effect did (W8)")
        elif row_id == "W18":
            o = self._wi_obs(item, obs, "tip", "fast_forward")
            if o["tip"] == item["base"]:
                raise ContractError("W18 needs the default branch moved from B")
        elif row_id == "W24":
            o = self._wi_obs(item, obs, "pr_state", "pr_head", "tip")
            moved = o["pr_head"] != item["head"]
            fact = {"head-moved": moved, "closed-in-flight": o["pr_state"] == "CLOSED",
                    "": o["pr_state"] == "MERGED" or o["tip"] != item["base"]}.get(mark or "")
            if not fact:
                raise ContractError("W24's observation does not show what its mark %r claims" % (mark or ""))
        if row_id == "W3":
            findings = self.db.execute("SELECT 1 FROM reviews WHERE item=? AND head=? AND state='findings'",
                                       (item["id"], item["head"])).fetchone()
            if not findings:
                raise ContractError("W3 needs a Review row of this item ending findings")
        elif row_id in ("W8", "W26"):
            if "confirmed" not in effects:
                raise ContractError("%s needs a confirmed Effect of this item for its H" % row_id)
        elif row_id == "W9":
            if "abandoned" not in effects or unsettled:
                raise ContractError("W9 needs the item's Effect abandoned")
            if marks:
                raise ContractError("W9 is for an unmarked item; a %s item takes W25" % marks)
        elif row_id == "W10":
            if "held" not in effects:
                raise ContractError("W10 needs the item's Effect held")
        elif row_id == "W24":
            if not unsettled:
                raise ContractError("W24 applies only while the item's Effect is unsettled")
            if mark not in (None, "", "head-moved", "closed-in-flight"):
                raise ContractError("W24 marks head-moved or closed-in-flight, not %r" % mark)
            if mark and marks and mark != marks:
                raise ContractError("the item is already marked %s" % marks)
            return mark or marks
        elif row_id == "W25":
            if "abandoned" not in effects or unsettled:
                raise ContractError("W25 needs the item's Effect abandoned")
            want = {"head-moved": "superseded", "closed-in-flight": "closed-unmerged"}.get(marks)
            if want != to:
                raise ContractError("W25 sends a %s item to %s" % (marks or "unmarked", want))
        elif row_id == "W20":
            pass                                                    # the owner cancels its own item from pr-gate
        if mark not in (None, ""):
            raise ContractError("only W24 sets a mark")
        return marks

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
        ("running", "cancelling"): D,         # R14: the subject changed (W4, W9, W18) or the owner cancelled (W20)
        ("cancelling", "superseded"): D,      # R15: the unit is gone; a later result is stored as late only
        ("outcome-unknown", "passed"): D,     # R8
        ("outcome-unknown", "findings"): D,   # R8
        ("outcome-unknown", "queued"): D,     # R9
        ("outcome-unknown", "cancelling"): D,  # R14 (v2g16): its unit may still be running, so it is stopped first
        ("infra-wait", "queued"): D,          # R10
        ("infra-wait", "superseded"): D,      # R12
    }

    def require_review(self, kind, repo, pr, head, packet_sha256, policy_revision, item=None, event_id=None,
                       actor="ahc-core", snapshot_base="", spec_core="", round=1, base_move=False):
        """none -> required, or the existing row for this exact binding (idempotent). R1: a code kind is bound to
        (repo, pr, H, B_r, packet, revision), where B_r is the default-branch tip at queue time and differs from H;
        a spec kind has no B_r and stores '', and is bound to the spec core it reviews (Q-A6), so a new attached
        core at the same head, packet and policy is a new row (W27) and the old pass cannot satisfy e2."""
        if kind not in self.REVIEW_KINDS:
            raise ContractError("unknown review kind %r" % kind)
        if actor not in self.D:
            raise ContractError("review rows are created by ahc-core")
        if kind in self.ATTEMPT_KINDS:
            if not isinstance(snapshot_base, str) or not _is_oid(snapshot_base) or snapshot_base == head:
                raise ContractError("a code review is bound to its snapshot base B_r (a full sha other than H)")
            if spec_core != "":
                raise ContractError("a code review carries no spec core")
        else:
            if snapshot_base != "":
                raise ContractError("a spec review has no snapshot base")
            if not (isinstance(spec_core, str) and len(spec_core) == 64 and _is_oid(spec_core)):
                raise ContractError("a spec review is bound to the full sha256 spec core it reviews")
        # AC-16 (v5): a Review row's identity includes its WorkItem and its round. Rows are looked up by that key,
        # never by recomputing an id, so a migrated row keeps its id and is still found for its own item; a row made
        # in v5 takes an id derived from the whole key. R9-3: a v5 row always names its item (only migrated legacy
        # rows may have none, and SQLite would let NULL items escape the unique key).
        if not isinstance(item, str) or not item:
            raise ContractError("a review row is created for a work item (AC-16)")
        if type(round) is not int or round < 1:
            raise ContractError("a review round is an integer from 1")
        binding = {"item": item, "kind": kind, "repo": str(repo).lower(), "pr": int(pr), "head": head,
                   "snapshot_base": snapshot_base, "packet_sha256": packet_sha256, "policy_revision": policy_revision,
                   "spec_core": spec_core, "round": round}
        with self.tx():
            found = self.db.execute(
                "SELECT id FROM reviews WHERE item=? AND kind=? AND repo=? AND pr=? AND head=? AND snapshot_base=? "
                "AND packet_sha256=? AND policy_revision=? AND spec_core=? AND round=?",
                (item, kind, binding["repo"], binding["pr"], head, snapshot_base, packet_sha256, policy_revision,
                 spec_core, round)).fetchone()
            if found:
                return self._row("reviews", "id", found[0])
            rid = "rv-" + _sha(binding)[:24]
            now = self.now()
            self.db.execute("INSERT INTO reviews(id, kind, item, repo, pr, head, snapshot_base, packet_sha256, "
                            "policy_revision, state, version, created, updated, spec_core, round, base_move) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (rid, kind, item, binding["repo"], binding["pr"], head, snapshot_base, packet_sha256,
                             policy_revision, "required", 1, now, now, spec_core, round, 1 if base_move else 0))
            self._a0("review", rid, None, "required", event_id or "ev-" + rid + "-required", actor)
            return self._row("reviews", "id", rid)

    def start_attempt(self, rid, unit, uid, *, expected_version, event_id, actor="ahc-review"):
        """R3 queued -> running: binds the row to the one attempt unit core started and the uid systemd allocated to
        it (read by core from the unit, never from the attempt). Only that uid's result can settle the row."""
        if not isinstance(unit, str) or not unit or type(uid) is not int or uid <= 0:
            raise ContractError("running needs the attempt's unit name and its allocated uid")
        with self.tx():
            # goodqa#16204 (spec owner ruling): a row of a finished item is inert; no attempt starts for it, and
            # nothing changes. The scheduler skipping such rows is a slice (b) obligation.
            owner = self.db.execute("SELECT w.id, w.state FROM reviews r JOIN work_items w ON w.id = r.item "
                                    "WHERE r.id=?", (rid,)).fetchone()
            if owner and (owner[1] in self.WI_TERMINAL or owner[1] == "merged"):
                raise ContractError("inert: item %s is %s; no attempt starts for its review rows" % owner)
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
        if row["snapshot_base"]:      # R4: a code receipt names the B_r the reviewer diffed against
            want["snapshot_base"] = row["snapshot_base"]
            got["snapshot_base"] = receipt.get("snapshot_base")
        if row["kind"] == "spec":     # R11 (Q-A6): the attach record is for the core this row reviews
            want["spec_core"] = row["spec_core"]
            got["spec_core"] = receipt.get("spec_core")
        if got != want:
            raise ContractError("receipt is bound to another subject: %s" % sorted(k for k in want
                                                                                   if want[k] != got[k]))
        verdict = receipt.get("verdict")
        if (to == "passed") != (verdict == "PASS"):
            raise ContractError("receipt verdict %r does not match %s" % (verdict, to))

    def supersede_reviews(self, repo, pr, head, successor_of, event_prefix, actor="ahc-core"):
        """R12 and R14, a changed head: every required, queued or infra-wait row for (repo, pr) at another head is
        superseded (R12); a running or outcome-unknown row goes to cancelling first (R14) and settles to superseded
        once its unit is stopped (R15). A receipt that arrives for either authorizes nothing. successor_of(row id)
        names the new row."""
        out = []
        with self.tx():
            rows = self.db.execute("SELECT id, state, version FROM reviews WHERE repo=? AND pr=? AND head != ? "
                                   "AND state NOT IN ('passed', 'findings', 'superseded', 'cancelling')",
                                   (str(repo).lower(), int(pr), head)).fetchall()
            for rid, state, version in rows:
                to = "cancelling" if state in ("running", "outcome-unknown") else "superseded"
                self.review(rid, to, expected_version=version, event_id="%s-%s" % (event_prefix, rid), actor=actor,
                            successor=successor_of(rid) if to == "superseded" else None, cause="head-changed")
                out.append((rid, to))
        return out

    # -------------------------------------------------------------- Grant (spec ahc-m1-v2g2 G1-G9)

    GRANT_TERMINAL = ("consumed", "retired", "expired", "revoked")
    GRANT_LIVE = ("validated", "active", "reserved")
    POLICY_PRINCIPALS = ("ahc-policy",)
    CAP1_PER_DAY = 10              # spec A3: integrations per repo per UTC day, reserved at G1
    SCOPE = ("repo", "pr", "head", "base")
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
        """CAP1's UTC day, on the effective wall (AC-10: it never goes backwards across restarts)."""
        return int((self.clock.effective_wall() if at is None else at) // 86400)

    def cap_used(self, repo, day=None):
        return self.db.execute("SELECT COUNT(*) FROM grants WHERE repo=? AND cap_day=? AND cap_held=1",
                               (str(repo).lower(), self.utc_day() if day is None else day)).fetchone()[0]

    def issue_grant(self, kind, source, principal, scope, policy_revision, *, event_id, kill_epoch,
                    lifetime=B47_GRANT_SECONDS):
        """G1: none -> validated, authority log first. The caller (ahc-policy in W7) checked ELIG on fresh
        observations. Scope (repo, pr, H, B); one non-terminal grant per (kind, repo, pr, B, H) by unique index; a
        CAP1 slot for the UTC day of G1 is reserved in the same transaction; the grant carries the current authority
        epoch and the kill epoch the caller read."""
        if principal not in self.POLICY_PRINCIPALS:
            raise ContractError("grants are issued by a policy principal, never by a model or an owner")
        if not isinstance(source, str) or not source.startswith(("user:", "answer:", "queue:")):
            raise ContractError("a grant needs the source of the user's decision")
        if not isinstance(scope, dict) or set(scope) != set(self.SCOPE) \
                or any(scope.get(k) in (None, "") for k in self.SCOPE):
            raise ContractError("a grant's scope is exactly repo, pr, head H and base B")
        if not _is_oid(scope["head"]) or not _is_oid(scope["base"]) or scope["head"] == scope["base"]:
            raise ContractError("a grant's H and B are distinct full commit shas")
        if type(kill_epoch) is not int:
            raise ContractError("a grant records the kill epoch it was issued under")
        repo, pr = str(scope["repo"]).lower(), int(scope["pr"])
        head, base = scope["head"], scope["base"]
        gid = "gr-" + _sha({"kind": kind, "repo": repo, "pr": pr, "b": base, "h": head, "policy": policy_revision,
                            "event": event_id})[:24]
        with self.tx():
            live = self.db.execute("SELECT id FROM grants WHERE kind=? AND repo=? AND pr=? AND base=? AND head=? AND "
                                   "state IN ('validated', 'active', 'reserved')",
                                   (kind, repo, pr, base, head)).fetchone()
            if live:
                raise ContractError("a non-terminal grant %s already covers this (B, H)" % live[0])
            day = self.utc_day()
            if self.cap_used(repo, day) >= self.CAP1_PER_DAY:
                raise ContractError("CAP1 reached for %s on this UTC day" % repo)
            self._g0("grant", None, None, event_id, "ahc-core", {(None, "validated"): ("ahc-core",)}, None,
                     "validated")
            now, epoch = self.now(), self.authority_epoch()
            seq = self.authority.append({"event_id": event_id, "grant": gid, "from": None, "to": "validated",
                                         "operation": None, "scope": {"repo": repo, "pr": pr, "head": head,
                                                                      "base": base},
                                         "actor": principal, "epochs": [epoch, kill_epoch]})
            self.db.execute("INSERT INTO grants(id, kind, source, principal, repo, pr, head, base, "
                            "policy_revision, uses, expires_at, state, authority_epoch, kill_epoch, cap_day, "
                            "cap_held, authority_seq, version, created, updated) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (gid, kind, source, principal, repo, pr, head, base, policy_revision, 1,
                             now + lifetime, "validated", epoch, kill_epoch, day, 1, seq, 1, now, now))
            self._a0("grant", gid, None, "validated", event_id, "ahc-core", principal=principal)
            self.clock.start(gid, "B47", lifetime)                  # AC-10: expiry on either clock
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
                                     "operation": op or None, "scope": {k: row[k] for k in self.SCOPE},
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
            if row["expires_at"] <= self.now() or self.clock.due(gid, "B47"):
                raise ContractError("grant is past expiry: no new reservation")
            if row["operation"]:
                raise ContractError("grant is already reserved for %s" % row["operation"])
            if op["state"] != "intent" or any(str(op[k]).lower() != str(row[k]).lower() for k in self.SCOPE):
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
            now = self.now()
            for gid, version, expires in self.db.execute(
                    "SELECT id, version, expires_at FROM grants WHERE state IN ('validated', 'active') ORDER BY id"
                    ).fetchall():
                if not (expires <= now or self.clock.due(gid, "B47")):     # AC-10: expired on either clock
                    continue
                self._grant_move(gid, "expired", version, "%s-%s" % (event_prefix, gid), "ahc-core")
                out.append(gid)
        return out

    # The ONLY abandonment proofs that retire a grant (G5: CAP1 released, g may rise): nothing was ever sent, or
    # every send was proven absent by p1 or p3. Anything else (E15, main's evidence on a held op, an unknown use)
    # consumes the grant (G4): fail closed, the slot stays charged and the (B, H) never gets a new generation.
    RETIRE_PROOFS = ("never-sent", "all-sends-absent")

    def _settle_grant_for(self, op, event_id):
        """The grant side of an operation reaching a terminal state: G5 (retired) only for an abandonment on the
        RETIRE_PROOFS allow-list; G4 (consumed) for a confirmation and for every other abandonment."""
        gid = op["grant_id"]
        row = self._row("grants", "id", gid) if gid else None
        if row is None or row["state"] != "reserved" or row["operation"] != op["key"]:
            return row
        if op["state"] == "abandoned" and op["proof"] in self.RETIRE_PROOFS:
            return self._grant_move(gid, "retired", row["version"], event_id + "-grant", "ahc-core")
        return self._grant_move(gid, "consumed", row["version"], event_id + "-grant", "ahc-core")

    # -------------------------------------------------------------- Effect / Operation (spec ahc-m1-v2g2 E1-E16)

    OP_TERMINAL = ("confirmed", "abandoned")
    OP_UNSETTLED = ("intent", "dispatched", "absent-proven", "outcome-unknown", "held", "fenced")
    OPERATORS = ("main", "reconcile")
    PROOFS = ("p1", "p3")         # E4: the two admissible absence proofs; p2 is not absence, it fences (E13)
    P1_KINDS = ("non-fast-forward", "ref-lock", "protected-ref")
    P3_STAGES = ("dns", "tcp", "tls")
    OBSERVATION_SECONDS = 120     # T2: an external fact in a guard is under 2 min old
    PR_MARK_SECONDS = 600         # E12: the PR does not show merged within 10 min of the dispatch
    METHOD = "fast-forward"       # E2: updateRefs beforeOid B, afterOid H, force false; no other send path
    OP_KIND = "fast-forward"      # operations.kind; the only Effect kind in M-1
    OP = {
        ("intent", "dispatched"): ("ahc-merge",),                           # E2
        ("dispatched", "confirmed"): ("ahc-merge",),                        # E3, E12
        ("outcome-unknown", "confirmed"): ("ahc-merge",),                   # E3, E12
        ("dispatched", "absent-proven"): ("ahc-merge",),                    # E4
        ("outcome-unknown", "absent-proven"): ("ahc-merge",),               # E4
        ("dispatched", "fenced"): ("ahc-core",),                            # E13
        ("outcome-unknown", "fenced"): ("ahc-core",),                       # E13
        ("fenced", "confirmed"): ("ahc-core",),                             # E14 (late-apply watch)
        ("fenced", "abandoned"): ("main",),                                 # E15
        ("dispatched", "outcome-unknown"): ("ahc-core",),                   # E5
        ("outcome-unknown", "held"): ("ahc-core",),                         # E6
        ("absent-proven", "intent"): ("ahc-core",),                         # E7
        ("absent-proven", "abandoned"): ("ahc-core",),                      # E8, E16
        ("intent", "abandoned"): ("ahc-core",),                             # E9
        ("held", "confirmed"): OPERATORS,                                   # E10 confirmed
        ("held", "abandoned"): ("main",),                                   # E10 abandoned: main's evidence only
        ("held", "fenced"): ("reconcile",),                                 # E10 fenced
        ("absent-proven", "held"): ("ahc-core",),                           # E11
    }

    @staticmethod
    def operation_key(repo, pr, base, head, policy_revision, generation):
        """E1: (repo, pr, B, H, policy revision, g), derived by core, never supplied by a model. A base move or a
        head move always gives a new key."""
        if any(v in (None, "") for v in (repo, pr, base, head, policy_revision)) or type(generation) is not int \
                or generation < 0:
            raise ContractError("an operation key needs repo, pr, B, H, policy revision and generation")
        if not _is_oid(base) or not _is_oid(head) or base == head:
            raise ContractError("an operation's B and H are distinct full commit shas")
        # The kind is part of the key so a later Effect kind (v2g3 may make W21's update-branch one) gets its own
        # keyspace with no schema change; M-1 has exactly one kind.
        ident = {"kind": Contracts.OP_KIND, "repo": str(repo).lower(), "pr": int(pr), "b": base, "h": head,
                 "policy": policy_revision, "g": generation}
        return "op-ff-%s" % _sha(ident)[:32]

    def next_generation(self, repo, pr, base, head, policy_revision):
        """g rises only when the previous operation for the same (B, H) was abandoned on the RETIRE_PROOFS
        allow-list (nothing sent, or every send proven absent by p1 or p3). A fenced, held or otherwise unsettled
        op keeps its g (intend returns that row); an op abandoned any other way never yields a new g."""
        rows = self.db.execute("SELECT generation, state, proof FROM operations WHERE repo=? AND pr=? AND base=? "
                               "AND head=? AND policy_revision=? ORDER BY generation DESC LIMIT 1",
                               (str(repo).lower(), int(pr), base, head, policy_revision)).fetchall()
        if not rows:
            return 0
        g, state, proof = rows[0]
        if state == "abandoned" and proof in self.RETIRE_PROOFS:
            return g + 1
        if state == "abandoned":
            raise ContractError("an operation with a send not proven absent never yields a new generation")
        return g

    PARAMS = ("repo", "pr", "head", "base", "policy_revision", "method", "default_branch")

    def intend(self, params, *, item=None, lease_ok, event_id):
        """E1 none -> intent. params: repo, pr, head H, base B, policy_revision, method ("fast-forward" only),
        default_branch. Same key and same parameters returns the row; same key with other parameters raises."""
        for k in self.PARAMS:
            if params.get(k) in (None, ""):
                raise ContractError("operation is missing %s" % k)
        if set(params) != set(self.PARAMS):
            raise ContractError("operation parameters are exactly %s" % ", ".join(self.PARAMS))
        if params["method"] != self.METHOD:
            raise ContractError("only the fast-forward method is allowed")
        with self.tx():
            g = self.next_generation(params["repo"], params["pr"], params["base"], params["head"],
                                     params["policy_revision"])
            key = self.operation_key(params["repo"], params["pr"], params["base"], params["head"],
                                     params["policy_revision"], g)
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
            self.db.execute("INSERT INTO operations(key, kind, item, repo, pr, head, base, policy_revision, "
                            "generation, params, params_sha256, state, version, created, updated) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (key, self.OP_KIND, item, str(params["repo"]).lower(), int(params["pr"]),
                             params["head"], params["base"], params["policy_revision"], g, _canon(params),
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
        for name, seconds in self.TIMERS_ON_ENTRY.get(to, ()):
            self.clock.start(key, name, seconds)                     # AC-10: each timer's row and anchor
        self._a0("operation", key, frm, to, event_id, actor, **data)
        new = self._row("operations", "key", key)
        if to in self.OP_TERMINAL:
            self._settle_grant_for(new, event_id)
        return new

    def _fresh(self, obs):
        def num(v):
            return isinstance(v, (int, float)) and not isinstance(v, bool)
        if not isinstance(obs, dict) or not num(obs.get("at")) or not num(obs.get("mono")):
            raise ContractError("the guard needs an observation row with its time and monotonic stamp (T2)")
        # D-a3: age is measured on the monotonic clock, never the wall clock, which can step (NTP, a manual set).
        # A stamp from another boot is meaningless, so the observation is stale.
        if obs.get("boot") != self.boot_id:
            raise ContractError("observation is from another boot; its age is unknown (T2, D-a3)")
        if not 0 <= float(self._mono()) - float(obs["mono"]) < self.OBSERVATION_SECONDS:
            raise ContractError("observation is stale (over 2 min) or from the future (T2)")

    @staticmethod
    def _bh_entry(row, obs):
        """The activity-log fact every confirm, fence and absence row reads: True when the default branch's
        activity has an entry with before B and after H, False when a COMPLETE read has none. An activity read that
        failed, was paginated incompletely, or is malformed raises: absence of an entry is a claim only a complete
        read can make (fail closed)."""
        act = obs.get("activity") if isinstance(obs, dict) else None
        if not isinstance(act, dict) or act.get("complete") is not True or not isinstance(act.get("entries"), list):
            raise ContractError("the activity read is missing or incomplete: no (B, H) claim can be made")
        for entry in act["entries"]:
            if not isinstance(entry, dict):
                raise ContractError("the activity read is malformed")
            if entry.get("before") == row["base"] and entry.get("after") == row["head"]:
                return True
        return False

    @staticmethod
    def _bh_entries(row, obs):
        """Every (before B, after H) entry of a complete activity read, in read order (raises like _bh_entry)."""
        if not Contracts._bh_entry(row, obs):
            return []
        return [e for e in obs["activity"]["entries"]
                if e.get("before") == row["base"] and e.get("after") == row["head"]]

    # ---- watch attribution (spec v2g4, Late-apply watch): each activity entry id explains at most one op

    @staticmethod
    def _entry_id(entry):
        eid = entry.get("id")
        return eid if isinstance(eid, str) and eid else None

    def _attributed(self, entry_id):
        return self.db.execute("SELECT 1 FROM attributions WHERE entry_id=?", (entry_id,)).fetchone() is not None

    def _attribute(self, row, entry_id, how):
        self.db.execute("INSERT INTO attributions(entry_id, op_key, repo, how, at) VALUES (?,?,?,?,?)",
                        (entry_id, row["key"], row["repo"], how, self.now()))

    def _holds_entry(self, key):
        return self.db.execute("SELECT 1 FROM attributions WHERE op_key=? AND entry_id IS NOT NULL",
                               (key,)).fetchone() is not None

    def _claim(self, row, obs, how):
        """After an op confirmed (E3/E12/E10/E14) or was abandoned under E16: attribute to it the first (B, H) entry
        of the read that has an id and is not yet attributed, if the op holds none. A read without a complete
        activity log claims nothing (the watch may claim the entry later, see _explainers)."""
        act = obs.get("activity") if isinstance(obs, dict) else None
        if self._holds_entry(row["key"]) or not isinstance(act, dict) or act.get("complete") is not True:
            return
        for entry in self._bh_entries(row, obs):
            eid = self._entry_id(entry)
            if eid and not self._attributed(eid):
                self._attribute(row, eid, how)
                return

    def _explainers(self, row):
        """The ops whose integration explains an update B -> H at this op's (repo, pr, B, H, revision): every
        confirmed op, and every op abandoned under E16 (its incident already named the integration)."""
        cur = self.db.execute(
            "SELECT o.* FROM operations o WHERE o.repo=? AND o.pr=? AND o.base=? AND o.head=? AND "
            "o.policy_revision=? AND (o.state='confirmed' OR EXISTS (SELECT 1 FROM attributions a WHERE "
            "a.op_key=o.key AND a.how='E16')) ORDER BY o.created, o.key",
            (row["repo"], row["pr"], row["base"], row["head"], row["policy_revision"]))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _applied(self, row, obs):
        """E3 / E10 / E14 / E16: the update (B -> H) is shown applied when the tip equals H, or a complete activity
        read has the (before B, after H) entry. Reachability of H is never evidence (a later integration containing
        H would make it reachable)."""
        if obs.get("tip") == row["head"]:
            return True
        return self._bh_entry(row, obs)

    def _row_or_raise(self, key):
        row = self._row("operations", "key", key)
        if row is None:
            raise ContractError("no operation %s" % key)
        return row

    def dispatch(self, key, obs, *, expected_version, event_id, lease_ok, mirror_read_back, request_id=None):
        """E2 intent -> dispatched. Every guard is re-read here; the count rises BEFORE the request is sent, and the
        caller sends only after this commits (T5), holding the T9 lock shared. The request is updateRefs on the
        default branch with beforeOid B, afterOid H (this row's head, the reviewed H) and force false."""
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
                problems.append("PR not open and ready at H")
            if obs.get("tip") != row["base"]:
                problems.append("default branch not at B")
            if obs.get("compare") != "ahead":      # e10: compare B...H is exactly 'ahead' (B is a proper ancestor)
                problems.append("B is not an ancestor of H")
            if obs.get("checks_green") is not True:
                problems.append("policy checks not green on H")
            if problems:
                raise ContractError("E2 guard false: " + "; ".join(problems))
            now = self.now()
            return self._op_move(key, "dispatched", expected_version, event_id, "ahc-merge", {
                "dispatch_count": row["dispatch_count"] + 1, "dispatched_at": now, "request_id": request_id,
                "wait_mono": float(self._mono()), "wait_boot": self.boot_id,    # E13's wait starts here (D-a3)
                "probe_at": now + B55_REQUEST_SECONDS}, observation=obs,
                request={"method": "updateRefs", "beforeOid": row["base"], "afterOid": row["head"], "force": False})

    def confirm(self, key, obs, *, expected_version, event_id, actor="ahc-merge"):
        """E3: the tip equals H, or a complete activity read shows (before B, after H). E12: the same, but the PR is
        not shown merged 10 min after the dispatch: still confirmed, flagged so ahc comments on the PR. E10 by main
        with evidence, or the reconcile under the E3 readback."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] == "fenced":
                raise ContractError("a fenced operation is confirmed only by the late-apply watch (E14)")
            if row["state"] == "held" and actor == "main":
                if not isinstance(obs, dict) or not obs:
                    raise ContractError("main settles a held operation with evidence")
                new = self._op_move(key, "confirmed", expected_version, event_id, "main", {"evidence": _canon(obs)})
                self._claim(new, obs, "confirm")
                return new
            if row["state"] == "held" and actor != "reconcile":
                raise ContractError("a held operation is settled only by main or the reconcile")
            self._fresh(obs)
            if not self._applied(row, obs):
                raise ContractError("readback does not show the update B -> H applied")
            unmarked = obs.get("pr_merged") is not True
            if unmarked and row["state"] != "held" and not self.clock.due(key, "E12"):
                raise ContractError("the PR is not shown merged yet; wait up to 10 min before E12")
            new = self._op_move(key, "confirmed", expected_version, event_id, actor,
                                {"evidence": _canon(obs), "pr_unmarked": 1 if unmarked else 0})
            self._claim(new, obs, "confirm")
            return new

    def absent(self, key, proof, evidence, *, expected_version, event_id):
        """E4 -> absent-proven with one of exactly two admissible proofs. "Not there now" is never one.
        p1: a typed server refusal (evidence {"kind": non-fast-forward | ref-lock | protected-ref}).
        p3: the connection failed before any request byte was written (evidence {"stage": dns | tcp | tls}); a reset
            or close after the request was written is never p3.
        An error response or no response is not absence: see fence() (E13). Each proof covers the one send in
        flight, so proven_absent rises by one."""
        if proof not in self.PROOFS or not isinstance(evidence, dict):
            raise ContractError("absent-proven needs proof p1 or p3 with its evidence")
        with self.tx():
            row = self._row_or_raise(key)
            if proof == "p1" and evidence.get("kind") not in self.P1_KINDS:
                raise ContractError("p1 needs a typed server refusal")
            if proof == "p3" and evidence.get("stage") not in self.P3_STAGES:
                raise ContractError("p3 needs a failure before the request was sent")
            return self._op_move(key, "absent-proven", expected_version, event_id, "ahc-merge",
                                 {"refusal": evidence.get("kind") or evidence.get("stage"), "proof": proof,
                                  "proven_absent": row["proven_absent"] + 1, "evidence": _canon(evidence)})

    def _off_bh(self, row, read):
        """A fresh, complete read in which the tip is neither B nor H and there is no (B, H) entry (p2, E10)."""
        self._fresh(read)
        if not read.get("tip") or read["tip"] in (row["base"], row["head"]):
            raise ContractError("the tip is B or H (or unread): not a fence")
        if self._bh_entry(row, read):
            raise ContractError("the activity log shows (B, H): the update applied, confirm instead")

    def e13_wait_start(self, key):
        """The monotonic stamp E13's minimum delays count from: the dispatch's, when it was on this boot. After a
        restart onto another boot the old stamp means nothing, so the wait restarts from this boot's first call
        here, which is recorded. This only ever delays E13 (fails closed). It is bookkeeping, not a transition: no
        version change and no audit row."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["wait_boot"] == self.boot_id and isinstance(row["wait_mono"], (int, float)):
                return float(row["wait_mono"])
            start = float(self._mono())
            self.db.execute("UPDATE operations SET wait_mono=?, wait_boot=? WHERE key=?", (start, self.boot_id, key))
            return start

    def fence(self, key, error, reads, *, expected_version, event_id):
        """E13 dispatched | outcome-unknown -> fenced (p2): an error response or no response (error names it),
        followed by two complete activity reads, the first at least 2 min after the dispatch and the second at
        least 60 s after the first, each with the tip neither B nor H and no (before B, after H) entry. Not absence:
        the request may still apply if the branch is ever rewound exactly to B (L5), so the grant stays reserved,
        no new grant or generation is issued for this (B, H), and the op is never tombstoned."""
        if not isinstance(error, str) or not error:
            raise ContractError("a fence names the error response or 'no-response'")
        if not isinstance(reads, (list, tuple)) or len(reads) != 2:
            raise ContractError("a fence needs exactly two activity reads")
        start = self.e13_wait_start(key)
        with self.tx():
            row = self._row_or_raise(key)
            first, second = reads
            for read in reads:
                self._off_bh(row, read)                 # each fresh, so each is from this boot (T2, D-a3)
            # elapsed time on the monotonic clock only, never wall stamps (spec owner T-2, goodqa#16193)
            if row["wait_boot"] != self.boot_id or float(first["mono"]) < start + E13_FIRST_READ_SECONDS:
                raise ContractError("E13's first read is at least 2 min after the dispatch, or after the restart "
                                    "that restarted the wait (activity lag)")
            if float(second["mono"]) - float(first["mono"]) < E13_READ_GAP_SECONDS:
                raise ContractError("E13's two reads are at least 60 s apart")
            return self._op_move(key, "fenced", expected_version, event_id, "ahc-core", {
                "proof": "p2", "refusal": error, "evidence": _canon({"error": error, "reads": list(reads)}),
                "escalate_at": self.now() + FENCED_ESCALATE_SECONDS, "probe_at": None}, escalate="digest")

    def watch_confirm(self, key, obs, *, event_id, expected_version):
        """E14 fenced -> confirmed: the late-apply watch found the tip equal to H or a (before B, after H) entry.
        An incident names the op, the repo's merging turns off until main turns it on, and the grant is consumed
        (G4)."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] != "fenced":
                raise ContractError("E14 applies to a fenced operation")
            self._fresh(obs)
            if not self._applied(row, obs):
                raise ContractError("the watch read does not show the update B -> H applied")
            self.set_merging(row["repo"], off=True, cause="late-apply:%s" % key, actor="ahc-core", _in_tx=True)
            new = self._op_move(key, "confirmed", expected_version, event_id, "ahc-core",
                                {"evidence": _canon(obs), "incident": row["incident"] + 1}, incident="late-apply")
            self._claim(new, obs, "confirm")
            return new

    def settle_fenced(self, key, evidence, *, expected_version, event_id, actor):
        """E15 fenced -> abandoned, by main only, on stamped evidence that the request can never apply (the caller
        verifies main's stamp: C6 obligation). The grant is consumed (G4), never retired: CAP1 stays charged."""
        if actor != "main" or not isinstance(evidence, dict) or not evidence:
            raise ContractError("a fenced operation is abandoned only by main, with evidence")
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] != "fenced":
                raise ContractError("E15 applies to a fenced operation")
            return self._op_move(key, "abandoned", expected_version, event_id, "main",
                                 {"proof": "never-applies", "evidence": _canon(evidence)}, incident="closed")

    def unknown(self, key, *, expected_version, event_id, restart=False):
        """E5 dispatched -> outcome-unknown when B55 passed or a restart found no conclusive readback."""
        # B55 is a wait (both clocks). It is read before the transaction: a new boot's re-anchor must commit even
        # when this call is refused, or every refused call would restart the wait again (AC-10)
        waited = restart or self.clock.due(key, "B55", B55_REQUEST_SECONDS)
        with self.tx():
            row = self._row_or_raise(key)
            if not waited:
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
            self.clock.start(key, "B37", B37_PROBE_SECONDS)
            return self._row("operations", "key", key)

    def after_absence(self, key, params, read, *, expected_version, event_id, lease_ok):
        """From absent-proven, exactly one of:
        E11 held: the grant was revoked, or the third dispatch was used.
        E16 abandoned: a fresh read shows the update B -> H applied (tip == H, or a complete activity read with the
            (B, H) entry). The proof (p1 or p3) says this op's request did not apply, so something else integrated
            H: an incident (L1 or a sibling op); the grant retires (G5); the WorkItem takes W14.
        E8 abandoned: p1, or p3 with the tip no longer B, and a complete activity read has no (B, H) entry; the
            grant retires (G5).
        E7 intent: p3 only, the tip still B, below 3 dispatches, the same parameters, the grant reserved, a lease.
        An incomplete activity read raises: neither E8 nor E16 fires on a partial read."""
        with self.tx():
            row = self._row("operations", "key", key)
            if row is None or row["state"] != "absent-proven":
                raise ContractError("this step applies to an absent-proven operation")
            grant = self._row("grants", "id", row["grant_id"]) if row["grant_id"] else None
            if (grant is not None and grant["state"] == "revoked") or row["dispatch_count"] >= B10_DISPATCHES:
                return self._op_move(key, "held", expected_version, event_id, "ahc-core", {"incident": 1})
            self._fresh(read)
            tip = read.get("tip")
            if not tip:
                raise ContractError("the read names no tip")
            if tip == row["head"] or (not (row["proof"] == "p3" and tip == row["base"]) and self._bh_entry(row, read)):
                new = self._op_move(key, "abandoned", expected_version, event_id, "ahc-core",
                                    {"proof": "all-sends-absent", "incident": row["incident"] + 1},
                                    incident="integrated-elsewhere", row="E16")
                self._claim(new, read, "E16")
                if not self._holds_entry(key):
                    self._attribute(new, None, "E16")     # E16 by the tip alone: the marker, no entry yet
                return new
            if row["proof"] == "p1" or tip != row["base"]:
                # E8: reached only after a complete read showed no (B, H) entry (_bh_entry raised on a partial one)
                return self._op_move(key, "abandoned", expected_version, event_id, "ahc-core",
                                     {"proof": "all-sends-absent"}, row="E8")
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
        for the same (B, H) uses generation g+1."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["proven_absent"] < row["dispatch_count"]:
                raise ContractError("an operation with a send not proven absent is never abandoned unsent")
            proof = "never-sent" if row["dispatch_count"] == 0 else "all-sends-absent"
            return self._op_move(key, "abandoned", expected_version, event_id, "ahc-core",
                                 {"proof": proof}, reason=reason)

    def settle_held(self, key, evidence, *, expected_version, event_id, actor):
        """E10 held -> abandoned: by main only, with stamped evidence that the request can never apply (the caller
        verifies main's stamp). Elapsed time is never evidence: there is no horizon. The outcome stayed unknown, so
        the grant is consumed (G4). A held op found applied goes through confirm(); one found off (B, H) goes
        through fence_held()."""
        if actor != "main" or not isinstance(evidence, dict) or not evidence:
            raise ContractError("a held operation is abandoned only by main, with evidence")
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] != "held":
                raise ContractError("E10 applies to a held operation")
            return self._op_move(key, "abandoned", expected_version, event_id, "main",
                                 {"proof": "unknown-spent", "evidence": _canon(evidence)})

    def fence_held(self, key, read, *, expected_version, event_id):
        """E10 held -> fenced (the reconcile): a fresh complete read with the tip neither B nor H and no (B, H)
        entry. The grant stays reserved; the op is watched without expiry (L5)."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] != "held":
                raise ContractError("E10 applies to a held operation")
            self._off_bh(row, read)
            return self._op_move(key, "fenced", expected_version, event_id, "reconcile", {
                "proof": "p2", "evidence": _canon(read), "escalate_at": self.now() + FENCED_ESCALATE_SECONDS})

    # ---- L5 late-apply watch and the per-repo merging switch

    LATE_WATCH_SECONDS = 30 * 86400
    # AC-10: the timers an operation starts when it enters a state (clock-service rows keyed by the operation)
    TIMERS_ON_ENTRY = {
        "dispatched": (("E12", PR_MARK_SECONDS), ("B55", B55_REQUEST_SECONDS)),
        "outcome-unknown": (("B37", B37_PROBE_SECONDS), ("B42", B42_INCIDENT_SECONDS)),
        "fenced": (("FENCED", FENCED_ESCALATE_SECONDS),),
        "confirmed": (("B48", B48_RETENTION_SECONDS),),
        "abandoned": (("B48", B48_RETENTION_SECONDS), ("LATE_WATCH", LATE_WATCH_SECONDS)),
    }

    def watched(self, repo):
        """What the late-apply watch checks on every repo poll: every fenced op (no expiry) and every op abandoned
        in the last 30 days, each with the (B, H) whose update must not appear."""
        rows = self.db.execute(
            "SELECT key, base, head, state FROM operations WHERE repo=? AND (state='fenced' OR "
            "(state='abandoned' AND tombstone=0)) ORDER BY created, key", (str(repo).lower(),)).fetchall()
        # AC-10: LATE_WATCH is a monitoring window; it stops only when both clocks agree it ended
        return [dict(zip(("key", "base", "head", "state"), r)) for r in rows
                if r[3] == "fenced" or not self.clock.due(r[0], "LATE_WATCH", self.LATE_WATCH_SECONDS)]

    def late_apply(self, key, evidence, *, event_id):
        """L5: a read found an abandoned operation's update applied (tip == H, or the (B, H) activity entry). The
        watch fires only when that application is unexplained (spec v2g4 attribution):
        - a (B, H) entry is explained when its id is already attributed (it confirmed an op under E3/E12/E14/E10,
          was named by an E16 incident, or already raised a late-apply incident), or when a confirmed or E16 op at
          the same (repo, pr, B, H, revision) holds no entry yet: that op claims it here;
        - tip == H is explained when such a confirmed or E16 op exists.
        An entry without an id cannot be attributed, so it is never explained (fail closed). On an unexplained
        application: one incident naming the op, its fresh entries attributed to it (so the same entry never raises
        twice), and the repo's merging off until main turns it back on; returns the repo flag. When everything is
        explained, returns None and records only the claims. A detector, not a fence. A fenced op's late apply is
        E14 (watch_confirm)."""
        with self.tx():
            row = self._row_or_raise(key)
            if row["state"] != "abandoned":
                raise ContractError("the late-apply watch records an incident on abandoned operations (E14 for "
                                    "fenced ones)")
            self._fresh(evidence)
            if not self._applied(row, evidence):
                raise ContractError("a late apply is recorded only on a read showing the update B -> H")
            if self.db.execute("SELECT 1 FROM transitions WHERE event_id=?", (event_id,)).fetchone():
                raise ContractError("event id %s was already applied" % event_id)
            tip_h = evidence.get("tip") == row["head"]
            entries = [] if tip_h and not isinstance(evidence.get("activity"), dict) else \
                self._bh_entries(row, evidence)
            explainers = self._explainers(row)
            free = [e for e in explainers if not self._holds_entry(e["key"])]
            fresh = []
            for entry in entries:
                eid = self._entry_id(entry)
                if eid and self._attributed(eid):
                    continue
                if eid and free:
                    claimer = free.pop(0)
                    self._attribute(claimer, eid, "E16" if claimer["state"] == "abandoned" else "confirm")
                    continue
                fresh.append(eid)
            tip_unexplained = tip_h and not explainers and not self.db.execute(
                "SELECT 1 FROM attributions WHERE op_key=? AND how LIKE 'late-apply%'", (key,)).fetchone()
            if not fresh and not tip_unexplained:
                return None
            for eid in fresh:
                if eid:
                    self._attribute(row, eid, "late-apply")
            if tip_unexplained and not any(fresh):
                self._attribute(row, None, "late-apply-tip")
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
        is a reconcile item for main; any one makes its repo ineligible. (reviews_v3_legacy rows authorize nothing:
        they carry no B_r, and a fresh bound review is required, so they are not reconcile items.)"""
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
        settled_at kept, parameters dropped). A non-terminal operation (fenced and held included) never expires and
        is never tombstoned."""
        cutoff = self.now() - B48_RETENTION_SECONDS
        with self.tx():
            keys = [k for (k,) in self.db.execute(
                "SELECT key FROM operations WHERE tombstone=0 AND state IN ('confirmed', 'abandoned') "
                "AND settled_at IS NOT NULL AND settled_at <= ? ORDER BY key", (cutoff,)).fetchall()
                if self.clock.due(k, "B48", B48_RETENTION_SECONDS)]       # AC-10: retention needs both clocks
            for k in keys:
                self.db.execute("UPDATE operations SET tombstone=1, params=NULL, evidence=NULL WHERE key=?", (k,))
            return len(keys)
