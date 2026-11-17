#!/usr/bin/env python3
"""ahc_merge: the E2 sender of spec ahc-m1 v2g16 (goodqa#16049 slice 1 (b), sub-slice "the ahc_merge adapter").

This is the one program that sends a write to GitHub for ahc. It runs as the OS user `ahcmerge`, never as the
daemon: the daemon keeps refusing `gh api graphql` under its AC-13 guard. It holds no clone, builds no commit and
runs no repository code. It makes exactly two kinds of write (spec Trust model, NEG-8, NEG-17):
- the E2 compare-and-swap: GraphQL `updateRefs` on `refs/heads/{default}` with beforeOid B, afterOid H (the head the
  passed adversarial Review row names) and force false;
- the CHK-CAS canary on the scratch ref `refs/ahc/canary` (e9).
There is no other send path: no plain push, no merge, squash or rebase commit, no force (NEG-19, L4). W21's
update-branch is NOT here: the owner's ruling puts it in the daemon behind AHC_W21_SEND (slice 1(b) spec r9 AC-7).

What it does, by spec row:
- E2 (`Sender.dispatch`): under the T9 dispatch lock held SHARED it re-reads the kill epoch, checks the merge identity
  was verified within 10 min (AC-8), re-reads the grant and the CHK-CAS record, takes the reviewed H from the Review
  row, takes fresh observations (T2), commits intent -> dispatched through the ledger port (the count rises before
  the send), reads that committed row back, and only then sends one request, with a 30 s client deadline. On the
  deadline the request is abandoned locally and the lock is released; the op settles by readback, never as absent.
- Readback (`Sender.settle`, one step per call, driven by the caller's tick): tip, activity log and PR. E3/E12
  confirm (attribution `ahc-proven` only when this process saw its own success response), E4 with the two
  admissible proofs only (p1 a typed refusal, p3 a failure before any request byte), E5 after B55, B37 readbacks to
  E6 held, the E13 quiet window (two complete activity reads, the first at least 2 min after the dispatch and the
  second at least 60 s after the first) to `fenced`, and E14 for a fenced op.
- T9 (`Fence`): kill, grant revoke and repo disable take the dispatch lock EXCLUSIVELY, at most 45 s. If a sender
  still holds it, the kill writes the new epoch first, then the terminator SIGKILLs the sender and confirms it is
  gone; only then does it return `kill complete`, naming the op in flight. Unconfirmed: `kill-incomplete` and an
  incident. Revoke and disable use the same bound and fallback.
- AC-8 (`MergeIdentity`): the pinned login and numeric id, the check age, the token scope record (O1): refusal
  without contents write, a warning on admin or all-repo scope (unreported scopes count as all-repo).
- e9 (`Canary`): the four CHK-CAS cases on `refs/ahc/canary`, the no-workflow assertion, and the record e9 reads.
- AC-18: named crash seams around every durable write and the send (MERGE_SEAMS, MERGE_INVENTORY).

Not wired: nothing imports this module yet. The ledger is reached through `LedgerPort`, an in-process shim over
ahc_contracts (ASSUMPTION A-port: in production `ahcmerge` cannot write the ledger, NEG-8, so these calls become
requests to ahc-core; that channel is not built). Proposed contract changes are listed in PROPOSED_CONTRACT_DIFFS.

Agent-ruled choices, each labelled ASSUMPTION where it is made: A-port (above), A-kill (the kill-epoch file's
place and shape), A-p3 (which gh errors prove a failure before any request byte), A-canary (the three commits and the
zero-oid create and delete), A-attr (E3 attribution rides in the confirm evidence until a column exists), A-lock (the T9 wording: the sender holds the lock shared, the fences take
it exclusive, as spec T9 says; the brief's "exclusive dispatch flock" is read as the fence side).
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import stat
import subprocess
import threading
import time
from pathlib import Path

import ahc_contracts as C
import ahc_fs as fs
from ahc_crash import crash_after, crash_before

ZERO_OID = "0" * 40
SEND_DEADLINE_SECONDS = 30.0        # T9: the send's client deadline while the shared lock is held
FENCE_BOUND_SECONDS = 45.0          # T9: a kill, revoke or disable waits at most this long for the lock
IDENTITY_FRESH_SECONDS = 600        # AC-8 / M-1H: merging holds when the identity check is older than 10 min
SENDER_LOCK_WAIT_SECONDS = 5.0      # the sender waits this long for the shared lock, then defers (a fence holds it)
CANARY_REF = "refs/ahc/canary"
DISPATCH_LOCK_PATH = "/run/ahc/dispatch.lock"   # spec T9
SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")

# AC-18: the sender's own seams. They are not in ahc_crash.SEAMS yet: tests.test_ahc_crash checks that tuple against
# a fixed module list and a scenario set, so registering them there is a proposed diff (PROPOSED_CONTRACT_DIFFS).
MERGE_SEAMS = (
    "merge.send",           # around the one updateRefs request (after the dispatched row committed and was read back)
    "merge.canary_record",  # around the fsynced canary record that e9 reads
    "merge.kill_epoch",     # around the fsynced kill-epoch write (the fence side)
)
# Every durable write and send of this module, with its seam or the reason it has none (checked by
# tests.test_ahc_merge.CrashSeamTests against ahc_crash.inventory and seam_calls of this file).
MERGE_INVENTORY = {
    ("ahc_merge", "KillStore.write", "fs.write_file"): (1, "seam:merge.kill_epoch"),
    ("ahc_merge", "CanaryStore.write", "fs.write_file"): (1, "seam:merge.canary_record"),
}

PROPOSED_CONTRACT_DIFFS = (
    "operations.attribution column and confirm(attribution=) (replace A-attr)",
    "observation field merge_identity_ok, read by W5/W6 as a cause like mirror_ok ('merge identity unavailable')",
    "ahc_crash.SEAMS += MERGE_SEAMS; InventoryTests.MODULES and test_ahc_fs.MODULES += ahc_merge",
    "Contracts.dispatch (E2 guard) refuses while repo_flags.merging_off is set (found by T9Tests: a disabled repo's "
    "intent still passed E2; ahc_merge checks it itself meanwhile)",
)


class SenderError(RuntimeError):
    """A refusal before anything was sent. Nothing left this process."""


class TransportError(RuntimeError):
    """A read failed or was malformed: the readback is inconclusive (fail closed)."""


# ---------------------------------------------------------------- send results

OK = "ok"                     # the server answered and reported the update applied
P1 = "p1"                     # a typed refusal from the server (E4 p1)
P3 = "p3"                     # the connection failed before any request byte was written (E4 p3)
UNTYPED = "untyped"           # an error response that proves nothing (Codex v2d F3)
NO_RESPONSE = "no-response"   # a timeout, a reset after the write, or the client deadline: proves nothing


class SendResult(dict):
    """{"outcome": OK|P1|P3|UNTYPED|NO_RESPONSE, "kind": the p1 kind or p3 stage, "detail": short text}."""

    def __init__(self, outcome, detail="", kind=None):
        super().__init__(outcome=outcome, detail=str(detail)[:300], kind=kind)

    @property
    def outcome(self):
        return self["outcome"]


class Outcome(dict):
    """What one sender call did: {"state": ..., "why": ..., "sent": bool}."""

    def __init__(self, state, why="", sent=False, **extra):
        super().__init__(state=state, why=why, sent=sent, **extra)


# ---------------------------------------------------------------- the transport

class Transport:
    """The one interface to GitHub. Writes: update_refs. Reads: read_ref, read_activity, read_pr,
    compare, commit_parents, workflow_runs, whoami, repo_permissions. Tests use an in-process fake; the real class is
    GhTransport, which tests never run against GitHub."""

    def update_refs(self, repo, ref, before_oid, after_oid, force, timeout):     # pragma: no cover - interface
        raise NotImplementedError


# GraphQL errors. A stale beforeOid answers untyped when B is an ancestor of the tip and typed otherwise
# (chk-ff-dispatch); only these typed texts are p1 (P1_KINDS of ahc_contracts).
P1_PATTERNS = (
    ("non-fast-forward", re.compile(r"rejecting non-fast forward update|non-fast-forward", re.I)),
    ("ref-lock", re.compile(r"cannot lock ref|ref.?lock", re.I)),
    ("protected-ref", re.compile(r"protected branch|protected ref", re.I)),
)
# ASSUMPTION A-p3 (PENDING_REAL_TEST gh-p3-classes): only these gh/Go errors prove that no request byte was written.
# A reset, EOF or timeout after the connection was made is never p3.
P3_PATTERNS = (
    ("dns", re.compile(r"dial tcp: lookup \S+.*(no such host|server misbehaving|i/o timeout)")),
    ("tcp", re.compile(r"dial tcp \S+: connect: (connection refused|network is unreachable|no route to host)")),
    ("tls", re.compile(r"(tls: handshake failure|TLS handshake timeout|x509: )")),
)
AFTER_WRITE = re.compile(r"(read tcp|write tcp|connection reset|broken pipe|EOF|context deadline)", re.I)


def classify_graphql(rc, stdout, stderr, timed_out=False):
    """The SendResult of one `gh api graphql` updateRefs call. Fail closed: anything not positively typed is
    UNTYPED or NO_RESPONSE, never an absence proof."""
    err = str(stderr or "")
    if timed_out:
        return SendResult(NO_RESPONSE, "client deadline")
    if rc != 0 and not str(stdout or "").strip():
        if AFTER_WRITE.search(err):
            return SendResult(NO_RESPONSE, "connection failed after the request was written")
        for stage, pat in P3_PATTERNS:
            if pat.search(err):
                return SendResult(P3, "before any request byte: %s" % stage, kind=stage)
        return SendResult(UNTYPED, "gh exit %s" % rc)
    try:
        body = json.loads(stdout)
    except ValueError:
        return SendResult(UNTYPED, "the response is not JSON")
    errors = body.get("errors") if isinstance(body, dict) else None
    if errors:
        text = " ".join(str(e.get("message", "")) for e in errors if isinstance(e, dict))
        for kind, pat in P1_PATTERNS:
            if pat.search(text):
                return SendResult(P1, text, kind=kind)
        return SendResult(UNTYPED, text or "an error without a message")
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, dict) and isinstance(data.get("updateRefs"), dict):
        return SendResult(OK, "updateRefs answered")
    return SendResult(UNTYPED, "no updateRefs payload")


class GhTransport(Transport):
    """The production transport: `gh` at a fixed absolute path, run as `ahcmerge` with gh's own sign-in (gh reads
    its config itself; this class never reads token bytes). Every behaviour against GitHub is PENDING_REAL_TEST
    (M-1 AC-9 is the live proof); tests check only its argv and its classification."""

    HEADERS = ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
    UPDATE_REFS = ("mutation($id: ID!, $u: [RefUpdate!]!) { updateRefs(input: {repositoryId: $id, refUpdates: $u}) "
                   "{ clientMutationId } }")

    def __init__(self, gh, home, run=None):
        if not os.path.isabs(str(gh)):
            raise SenderError("gh must be an absolute path")
        self.gh = str(gh)
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C", "GH_PROMPT_DISABLED": "1",
                    "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1"}
        self._run = run or self._subprocess

    def _subprocess(self, argv, stdin, timeout):
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, env=self.env)
            return p.returncode, p.stdout, p.stderr, False
        except subprocess.TimeoutExpired:
            return None, "", "", True

    def update_refs_argv(self):
        return [self.gh, "api", "graphql"] + self.HEADERS + ["--input", "-"]

    @staticmethod
    def update_refs_body(repo_id, ref, before_oid, after_oid):
        # force is never a parameter of this function: it is always false (hard rule 4, L4)
        return json.dumps({"query": GhTransport.UPDATE_REFS, "variables": {"id": repo_id, "u": [
            {"name": ref, "beforeOid": before_oid, "afterOid": after_oid, "force": False}]}})

    def _get(self, endpoint, timeout=30):
        rc, out, err, timed_out = self._run([self.gh, "api", "--method", "GET"] + self.HEADERS + [endpoint], None,
                                            timeout)
        if timed_out or rc != 0:
            raise TransportError("gh api GET failed")
        try:
            return json.loads(out)
        except ValueError:
            raise TransportError("gh api GET: not JSON") from None

    def update_refs(self, repo, ref, before_oid, after_oid, force, timeout):
        if force is not False:
            raise SenderError("force is never sent")
        repo_id = self._get("repos/%s" % repo).get("node_id")
        if not isinstance(repo_id, str) or not repo_id:
            return SendResult(P3, "no repository id: nothing was sent", kind="tcp")
        rc, out, err, timed_out = self._run(self.update_refs_argv(),
                                            self.update_refs_body(repo_id, ref, before_oid, after_oid), timeout)
        return classify_graphql(rc, out, err, timed_out)

    def read_ref(self, repo, ref):
        obj = self._get("repos/%s/git/ref/%s" % (repo, ref[len("refs/"):]))
        sha = (obj.get("object") or {}).get("sha") if isinstance(obj, dict) else None
        if not (isinstance(sha, str) and SHA.fullmatch(sha)):
            raise TransportError("the ref read is not a full sha")
        return sha

    def read_activity(self, repo, branch):
        entries = self._get("repos/%s/activity?ref=refs/heads/%s&per_page=100" % (repo, branch))
        if not isinstance(entries, list):
            raise TransportError("the activity read is not a list")
        out = [{"id": str(e.get("id")), "before": e.get("before"), "after": e.get("after"),
                "type": e.get("activity_type")} for e in entries if isinstance(e, dict)]
        # ASSUMPTION (PENDING_REAL_TEST chk-act): one page of 100 holds every entry the watch needs; a full page is
        # reported incomplete so no absence claim is made on it.
        return {"complete": len(entries) < 100, "entries": out}

    def read_pr(self, repo, pr):
        p = self._get("repos/%s/pulls/%d" % (repo, int(pr)))
        state = "MERGED" if p.get("merged") is True else {"open": "OPEN", "closed": "CLOSED"}.get(p.get("state"))
        return {"state": state, "head": (p.get("head") or {}).get("sha"), "merged": p.get("merged") is True,
                "draft": p.get("draft"), "mergeable": p.get("mergeable"), "mergeable_state": p.get("mergeable_state")}

    def compare(self, repo, base, head):
        return self._get("repos/%s/compare/%s...%s" % (repo, base, head)).get("status")

    def commit_parents(self, repo, oid):
        return [p.get("sha") for p in self._get("repos/%s/commits/%s" % (repo, oid)).get("parents") or []]

    def workflow_runs(self, repo):
        return self._get("repos/%s/actions/runs?per_page=1" % repo).get("total_count")

    def whoami(self):
        rc, out, err, timed_out = self._run([self.gh, "api", "--include", "user"], None, 30)
        if timed_out or rc != 0:
            raise TransportError("gh api user failed")
        head, _, body = out.replace("\r\n", "\n").partition("\n\n")
        scopes = None
        for line in head.split("\n"):
            k, _, v = line.partition(":")
            if k.strip().lower() == "x-oauth-scopes":
                scopes = [s.strip() for s in v.split(",") if s.strip()]
        user = json.loads(body)
        return {"login": user.get("login"), "id": user.get("id"), "scopes": scopes}

    def repo_permissions(self, repo):
        return self._get("repos/%s" % repo).get("permissions") or {}


# ---------------------------------------------------------------- T9: the dispatch lock

class DispatchLock:
    """The T9 flock on /run/ahc/dispatch.lock. The sender holds it SHARED from its last kill-epoch read through the
    send; a kill, revoke or disable takes it EXCLUSIVELY. The file is created by the install (root), never here, so
    this class opens it read-only, without following a link, and requires a regular file."""

    def __init__(self, path=DISPATCH_LOCK_PATH, sleep=time.sleep, monotonic=time.monotonic):
        self.path = str(path)
        self._sleep, self._mono = sleep, monotonic
        self.fd = None

    def _open(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise SenderError("the dispatch lock is not a regular file")
        return fd

    def acquire(self, mode, timeout):
        """True when the lock was taken within `timeout` seconds; False otherwise (nothing held)."""
        if self.fd is not None:
            raise SenderError("the dispatch lock is already held by this object")
        fd = self._open()
        deadline = self._mono() + float(timeout)
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                self.fd = fd
                return True
            except OSError as error:
                if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    os.close(fd)
                    raise
            if self._mono() >= deadline:
                os.close(fd)
                return False
            self._sleep(0.01)

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def shared(self, timeout):
        return _Held(self, fcntl.LOCK_SH, timeout)

    def exclusive(self, timeout):
        return _Held(self, fcntl.LOCK_EX, timeout)


class _Held:
    def __init__(self, lock, mode, timeout):
        self.lock, self.mode, self.timeout = lock, mode, timeout

    def __enter__(self):
        return self.lock.acquire(self.mode, self.timeout)

    def __exit__(self, *exc):
        self.lock.release()
        return False


# ---------------------------------------------------------------- the kill epoch

class KillStore:
    """The kill switch and its epoch: {"on": bool, "epoch": int} in `<directory>/kill.json`. ASSUMPTION A-kill: the
    file lives in a directory core owns (written through ahc_fs, fsynced before the write returns, so every later
    dispatch sees it) and the sender reads it without following a link, requiring a regular file owned by the writer
    uid and not writable by group or other. Unreadable or malformed reads as on (fail closed)."""

    NAME = "kill.json"

    def __init__(self, directory, writer_uid=None):
        self.dir = Path(directory)
        self.path = self.dir / self.NAME
        self.writer_uid = os.geteuid() if writer_uid is None else int(writer_uid)

    def read(self):
        try:
            fd = os.open(str(self.path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        except OSError as error:
            return {"on": True, "epoch": None, "error": "kill state unreadable (%s)" % type(error).__name__}
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.writer_uid or info.st_mode & 0o022:
                return {"on": True, "epoch": None, "error": "kill state file is not the writer's private file"}
            raw = os.read(fd, 4096)
        finally:
            os.close(fd)
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"on": True, "epoch": None, "error": "kill state malformed"}
        if not isinstance(data, dict) or type(data.get("on")) is not bool or type(data.get("epoch")) is not int:
            return {"on": True, "epoch": None, "error": "kill state malformed"}
        return {"on": data["on"], "epoch": data["epoch"]}

    def write(self, on, epoch):
        crash_before("merge.kill_epoch")
        fs.write_file(self.dir, self.path, C._canon({"on": bool(on), "epoch": int(epoch)}))
        crash_after("merge.kill_epoch")

    def bump(self):
        """Turn the kill switch on with a new epoch (one more than any readable epoch); returns the new state."""
        cur = self.read()
        new = (cur["epoch"] if type(cur.get("epoch")) is int else 0) + 1
        self.write(True, new)
        return {"on": True, "epoch": new}


# ---------------------------------------------------------------- the ledger port (shim)

class LedgerPort:
    """ASSUMPTION A-port. Every ledger read and write the sender makes goes through here. In tests it is an
    in-process shim over ahc_contracts.Contracts; in production `ahcmerge` cannot write the ledger (NEG-8), and these
    calls become requests to ahc-core over its socket (not built). The port writes nothing directly."""

    def __init__(self, contracts):
        self.c = contracts

    # reads
    def operation(self, key):
        return self.c._row("operations", "key", key)

    def grant(self, gid):
        return self.c._row("grants", "id", gid) if gid else None

    def item(self, iid):
        return self.c._row("work_items", "id", iid) if iid else None

    def params(self, row):
        try:
            return json.loads(row["params"]) if row.get("params") else {}
        except ValueError:
            return {}

    def stamp(self, obs):
        return self.c.stamp(obs)

    def mono(self):
        return float(self.c._mono())

    def reviewed_head(self, op):
        """The H the passed adversarial Review row of the op's item names, at the op's policy revision (latest round).
        The op's own head is never trusted alone: the two must agree, or nothing is sent."""
        if not op.get("item"):
            return None
        heads = {h for (h,) in self.c.db.execute(
            "SELECT head FROM reviews WHERE item=? AND kind='adversarial' AND state='passed' AND policy_revision=?"
            + C.Contracts.LATEST_ROUND, (op["item"], op["policy_revision"])).fetchall()}
        return heads.pop() if len(heads) == 1 else None

    def mirror_read_back(self, op):
        """ASSUMPTION: the mirror read-back G3 required is the reservation itself; a dedicated record is proposed."""
        g = self.grant(op.get("grant_id"))
        return bool(g and g["state"] == "reserved" and g["operation"] == op["key"])

    def committed_request(self, key, request_id):
        """The committed dispatched row for this request id, and the request record E2 stored with it."""
        row = self.operation(key)
        if row is None or row["state"] != "dispatched" or row["request_id"] != request_id:
            return None
        data = self.c.db.execute("SELECT data FROM transitions WHERE entity='operation' AND id=? AND "
                                 "to_state='dispatched' ORDER BY seq DESC LIMIT 1", (key,)).fetchone()
        try:
            return dict(json.loads(data[0]).get("request") or {}, count=row["dispatch_count"])
        except (TypeError, ValueError, AttributeError):
            return None

    def due(self, key, name, seconds):
        with self.c.tx():
            return self.c.clock.due(key, name, seconds)

    def dispatched_ops(self):
        return [k for (k,) in self.c.db.execute("SELECT key FROM operations WHERE state='dispatched' ORDER BY key")]

    def live_grants(self):
        return self.c.db.execute("SELECT id, version FROM grants WHERE state IN ('validated', 'active', 'reserved') "
                                 "ORDER BY id").fetchall()

    # writes (each one Contracts transition)
    def dispatch(self, key, obs, **kw):
        return self.c.dispatch(key, obs, **kw)

    def confirm(self, key, obs, **kw):
        return self.c.confirm(key, obs, **kw)

    def absent(self, key, proof, evidence, **kw):
        return self.c.absent(key, proof, evidence, **kw)

    def after_absence(self, key, params, read, **kw):
        return self.c.after_absence(key, params, read, **kw)

    def unknown(self, key, **kw):
        return self.c.unknown(key, **kw)

    def readback_missed(self, key, **kw):
        return self.c.readback_missed(key, **kw)

    def e13_wait_start(self, key):
        return self.c.e13_wait_start(key)

    def fence(self, key, error, reads, **kw):
        return self.c.fence(key, error, reads, **kw)

    def fence_held(self, key, read, **kw):
        return self.c.fence_held(key, read, **kw)

    def watch_confirm(self, key, obs, **kw):
        return self.c.watch_confirm(key, obs, **kw)

    def revoke_grant(self, gid, **kw):
        return self.c.revoke_grant(gid, **kw)

    def set_merging(self, repo, **kw):
        return self.c.set_merging(repo, **kw)

    def merging_off(self, repo):
        return self.c.merging_off(repo)


# ---------------------------------------------------------------- AC-8: the merge identity

class IdentityError(SenderError):
    """The token is not the pinned account, or lacks contents write: refused, with an incident."""


class MergeIdentity:
    """The pinned merge identity (login and numeric id, pinned at onboarding) and its last check. `fresh()` holds only
    when a check passed within IDENTITY_FRESH_SECONDS on this boot's monotonic clock. The check reads `GET /user` (its
    login, id and X-OAuth-Scopes header) and each allowlisted repo's permissions; it never reads token bytes."""

    ALL_REPO_SCOPES = ("repo",)
    ADMIN_SCOPES = ("admin:org", "admin:repo_hook", "admin:public_key", "admin:enterprise", "delete_repo",
                    "site_admin", "admin:org_hook")

    def __init__(self, pinned_login, pinned_id, *, mono, boot_id):
        if not isinstance(pinned_login, str) or not pinned_login or type(pinned_id) is not int or pinned_id <= 0:
            raise IdentityError("the pinned identity is a login and a numeric id")
        self.login, self.id = pinned_login, pinned_id
        self._mono, self.boot_id = mono, boot_id
        self.record = None
        self.incidents = []

    def check(self, transport, repos):
        """One identity check. Returns the scope record (O1); raises IdentityError on a wrong account or a token
        without contents write. A failed check clears the last good one, so merging holds until a check passes."""
        self.record = None
        me = transport.whoami()
        if type(me.get("id")) is not int or me["id"] != self.id or str(me.get("login", "")).lower() != \
                self.login.lower():
            self.incidents.append("merge identity is not the pinned account")
            raise IdentityError("merge identity is not the pinned account (incident)")
        scopes = me.get("scopes")
        perms = {r: transport.repo_permissions(r) for r in sorted(repos)}
        write = all(isinstance(p, dict) and p.get("push") is True for p in perms.values()) and bool(perms)
        if not write:
            self.incidents.append("merge token has no contents write on an allowlisted repo")
            raise IdentityError("merge token has no contents write on every allowlisted repo")
        admin = any(isinstance(p, dict) and p.get("admin") is True for p in perms.values()) or (
            isinstance(scopes, list) and any(s in self.ADMIN_SCOPES for s in scopes))
        all_repo = not isinstance(scopes, list) or any(s in self.ALL_REPO_SCOPES for s in scopes)
        warnings = []
        if admin:
            warnings.append("WARNING: the merge token has admin scope (L2)")
        if all_repo:
            warnings.append("WARNING: the merge token reaches every repo the user can%s (L2)" % (
                "" if isinstance(scopes, list) else "; its scopes are not reported, so it counts as all-repo"))
        self.record = {"login": me["login"], "id": me["id"], "scopes": scopes, "contents_write": True,
                       "admin": admin, "all_repo": all_repo, "warnings": warnings, "boot": self.boot_id,
                       "mono": float(self._mono())}
        return dict(self.record)

    def fresh(self):
        r = self.record
        return bool(r and r["boot"] == self.boot_id and 0 <= float(self._mono()) - r["mono"] < IDENTITY_FRESH_SECONDS)

    def status_lines(self):
        lines = ["identity: merges act as the user's own GitHub account %s (id %d)" % (self.login, self.id)]
        if not self.fresh():
            lines.append("merging: waiting-dep (merge identity unavailable)")
        return lines + list((self.record or {}).get("warnings", []))


# ---------------------------------------------------------------- e9: the CHK-CAS canary

class CanaryStore:
    """The canary records e9 reads, one file per repo under `directory` (owned by `ahcmerge`), written through ahc_fs.
    Shaped for ahc_clock.Clock.canary_age: {"boot", "mono", "github_date"} plus the case results."""

    def __init__(self, directory):
        self.dir = Path(directory)

    def _path(self, repo):
        if not REPO.fullmatch(str(repo)):
            raise SenderError("not a repo slug")
        return self.dir / ("canary-%s.json" % str(repo).lower().replace("/", "__"))

    def write(self, record):
        crash_before("merge.canary_record")
        fs.write_file(self.dir, self._path(record["repo"]), C._canon(record))
        crash_after("merge.canary_record")

    def read(self, repo):
        try:
            fd = fs.open_file(self.dir, self._path(repo), os.O_RDONLY)
        except OSError:
            return None
        try:
            raw = os.read(fd, 65536)
        finally:
            os.close(fd)
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def chk_cas(self, repo, identity):
        """e9's CHK-CAS: the last record for the repo passed every case under the identity in use."""
        rec = self.read(repo)
        return bool(rec and rec.get("passed") is True and rec.get("identity") == {"login": identity.login,
                                                                                 "id": identity.id})

    def local_facts(self, repo, identity):
        """The e9 fields of ahc_observe's `local(repo)`: chk_cas, and the canary stamp canary_age reads."""
        rec = self.read(repo) or {}
        canary = {k: rec[k] for k in ("boot", "mono", "github_date") if k in rec} if rec.get("passed") else None
        return {"chk_cas": self.chk_cas(repo, identity), "canary": canary}


class Canary:
    """CHK-CAS under the merge identity on `refs/ahc/canary` (never a branch): (1) create from zero, (2) a correct
    fast-forward, (3) a typed non-fast-forward refusal with the ref unchanged, (4) a stale-beforeOid refusal with the
    ref unchanged; and no workflow started. ASSUMPTION A-canary: the commits are the default-branch tip T, its first
    parent P and P's first parent G; an existing canary ref is deleted first with afterOid zero. A failed canary turns
    the repo's merging off and escalates once (until a pass)."""

    def __init__(self, transport, identity, store, port, lock, kill):
        self.t, self.identity, self.store, self.port, self.lock, self.kill = (transport, identity, store, port, lock,
                                                                               kill)
        self.escalations = []

    def _cas(self, repo, before, after):
        return self.t.update_refs(repo, CANARY_REF, before, after, force=False, timeout=SEND_DEADLINE_SECONDS)

    def _ref(self, repo):
        try:
            return self.t.read_ref(repo, CANARY_REF)
        except TransportError:
            return None

    def run(self, repo, branch):
        if not self.identity.fresh():
            return Outcome("waiting-dep", "merge identity unavailable")
        cases = {}
        with self.lock.shared(SENDER_LOCK_WAIT_SECONDS) as held:
            epoch = self.kill.read() if held else {"on": True}
            if not held or epoch.get("on") is not False:
                return Outcome("deferred", "kill switch on, unreadable, or a fence holds the lock")
            tip = self.t.read_ref(repo, "refs/heads/%s" % branch)
            p = (self.t.commit_parents(repo, tip) or [None])[0]
            g = (self.t.commit_parents(repo, p) or [None])[0] if p else None
            if not (p and g):
                return Outcome("refused", "the default branch needs two ancestors for the canary")
            runs = self.t.workflow_runs(repo)
            cur = self._ref(repo)
            if cur:
                cases["cleanup"] = self._cas(repo, cur, ZERO_OID).outcome == OK and self._ref(repo) is None
            r = self._cas(repo, ZERO_OID, g)
            cases["create"] = r.outcome == OK and self._ref(repo) == g
            r = self._cas(repo, g, p)
            cases["fast-forward"] = r.outcome == OK and self._ref(repo) == p
            r = self._cas(repo, p, g)
            cases["typed-non-fast-forward"] = r.outcome == P1 and r["kind"] == "non-fast-forward" and \
                self._ref(repo) == p
            r = self._cas(repo, g, tip)
            cases["stale-before"] = r.outcome in (P1, UNTYPED) and self._ref(repo) == p
            cases["no-workflow"] = self.t.workflow_runs(repo) == runs
        passed = all(cases.values()) and len(cases) >= 5
        prior = self.store.read(repo) or {}
        rec = {"repo": str(repo).lower(), "identity": {"login": self.identity.login, "id": self.identity.id},
               "passed": passed, "cases": cases, "boot": self.identity.boot_id, "mono": self.port.mono(),
               "escalated": bool(prior.get("escalated")) and not passed}
        if not passed:
            self.port.set_merging(repo, off=True, cause="CHK-CAS canary failed", actor="ahc-core")
            if not prior.get("escalated") or prior.get("passed"):
                self.escalations.append("CHK-CAS canary failed for %s: %s" % (
                    repo, ", ".join(sorted(k for k, v in cases.items() if not v))))
                rec["escalated"] = True
        self.store.write(rec)
        return Outcome("passed" if passed else "failed", "", sent=True, record=rec)


# ---------------------------------------------------------------- E2 and the readbacks

class Sender:
    """E2 and its readbacks for one `ahcmerge` process. `checks(row)` returns True only when the repo's required
    checks are green for (repo, B, H, policy revision) (the core-recorded result, ASSUMPTION). `hooks` maps a point
    name to a callable, for tests only (production passes none)."""

    def __init__(self, port, transport, lock, kill, identity, cas, *, allowlist, checks,
                 send_deadline=SEND_DEADLINE_SECONDS, hooks=None):
        self.port, self.t, self.lock, self.kill, self.identity, self.cas = (port, transport, lock, kill, identity,
                                                                             cas)
        self.allowlist = {str(r).lower() for r in allowlist}
        self.checks = checks
        self.send_deadline = float(send_deadline)
        self.hooks = dict(hooks or {})
        self._epoch_at_start = kill.read()
        self._own_success = set()      # ops whose own CAS response arrived and reported success (this process only)
        self._last_error = {}          # op key -> the error text of its send (this process only)
        self._e13 = {}                 # op key -> the first quiet-window read (this process only)
        self._n = 0

    def _at(self, point):
        hook = self.hooks.get(point)
        if hook is not None:
            hook()

    def _ev(self, key, step):
        self._n += 1
        return "%s:%s:%d:%s" % (key, step, self._n, os.urandom(4).hex())

    def _branch(self, row):
        branch = self.port.params(row).get("default_branch")
        if not (isinstance(branch, str) and branch and ".." not in branch):
            raise SenderError("the operation names no default branch")
        return branch

    # ------------------------------------------------------------ E2

    def observe(self, row, epoch):
        """The E2 guard's fresh observation (T2): the tip, the PR, compare B...H and the checks, plus the kill switch
        and epoch read under the lock."""
        tip = self.t.read_ref(row["repo"], "refs/heads/%s" % self._branch(row))
        pr = self.t.read_pr(row["repo"], row["pr"])
        return self.port.stamp({"repo": row["repo"], "pr": row["pr"], "kill_switch": epoch["on"],
                                "kill_epoch": epoch["epoch"], "pr_state": pr.get("state"),
                                "pr_head": pr.get("head"), "draft": pr.get("draft"), "tip": tip,
                                "compare": self.t.compare(row["repo"], row["base"], row["head"]),
                                "checks_green": self.checks(row) is True})

    def payload(self, row, req, reviewed):
        """The one updateRefs request, built from the committed dispatched row and the reviewed H. force is
        always false; beforeOid is always B."""
        if not req or req.get("method") != "updateRefs" or req.get("force") is not False:
            raise SenderError("the committed request is not updateRefs with force false")
        if req.get("beforeOid") != row["base"] or req.get("afterOid") != reviewed:
            raise SenderError("the committed request is not (B, reviewed H)")
        return {"repo": row["repo"], "ref": "refs/heads/%s" % self._branch(row),
                "beforeOid": row["base"],
                "afterOid": reviewed,
                "force": False}

    def dispatch(self, key, *, lease_ok=True):
        """E2 for one operation: at most one updateRefs request, only after the dispatched row is committed."""
        rid = "req-" + os.urandom(8).hex()
        with self.lock.shared(SENDER_LOCK_WAIT_SECONDS) as held:     # T9: shared while it re-reads and sends
            if not held:
                return Outcome("deferred", "the dispatch lock is held by a kill, revoke or disable")
            epoch = self.kill.read()                                 # T9: the kill epoch, re-read under the lock
            if epoch.get("on") is not False or type(epoch.get("epoch")) is not int:
                return Outcome("refused", "kill switch on or unreadable")
            self._at("epoch-checked")
            if not self.identity.fresh():                            # AC-8: checked within the last 10 min
                return Outcome("waiting-dep", "merge identity unavailable")
            row = self.port.operation(key)
            if row is None or row["state"] != "intent":
                return Outcome(row["state"] if row else "missing", "only an intent is dispatched; a dispatched "
                               "row is never sent again (it settles by readback)")
            if row["repo"] not in self.allowlist:
                return Outcome("refused", "repo off the allowlist")
            if self.port.merging_off(row["repo"]):                   # T9 disable, E14: the repo's merging is off
                return Outcome("refused", "the repo's merging is off")
            if not self.cas.chk_cas(row["repo"], self.identity):     # e9 / NEG-19: no other send path exists
                return Outcome("refused", "CHK-CAS has not passed for this repo under the merge identity")
            reviewed = self.port.reviewed_head(row)                  # H from the passed Review row only
            if reviewed is None or reviewed != row["head"]:
                return Outcome("refused", "the passed adversarial Review row does not name this op's H")
            grant = self.port.grant(row["grant_id"])
            if grant is None or grant["kill_epoch"] != epoch["epoch"]:
                return Outcome("refused", "the grant is missing or from another kill epoch")
            try:
                obs = self.observe(row, epoch)
                self.port.dispatch(key, obs, expected_version=row["version"], event_id=self._ev(key, "e2"),
                                   lease_ok=lease_ok, mirror_read_back=self.port.mirror_read_back(row),
                                   request_id=rid)
            except (C.ContractError, TransportError, SenderError) as error:
                return Outcome("refused", "E2 not committed: %s" % error)
            req = self.port.committed_request(key, rid)              # the committed dispatched row, read back
            payload = self.payload(row, req, reviewed)
            self._at("committed")
            crash_before("merge.send")
            result = self._send(payload)
            crash_after("merge.send")
        return self.record(key, result)

    def _send(self, payload):
        """One request, with the client deadline. On the deadline the request is abandoned locally (the worker thread
        is left behind) and the caller releases the lock; the result proves nothing."""
        box = {}

        def run():
            try:
                box["r"] = self.t.update_refs(payload["repo"], payload["ref"], payload["beforeOid"],
                                              payload["afterOid"], payload["force"], self.send_deadline)
            except Exception as error:                 # an exception after the call began proves nothing
                box["r"] = SendResult(UNTYPED, "transport raised %s" % type(error).__name__)

        worker = threading.Thread(target=run, name="ahc-merge-send", daemon=True)
        worker.start()
        worker.join(self.send_deadline)
        if worker.is_alive() or "r" not in box:
            return SendResult(NO_RESPONSE, "client deadline %.0f s" % self.send_deadline)
        return box["r"]

    def record(self, key, result):
        """The response enters the ledger only through a later row (T5)."""
        if not isinstance(result, dict) or result.get("outcome") not in (OK, P1, P3, UNTYPED, NO_RESPONSE):
            result = SendResult(UNTYPED, "unrecognised send result")
        if result["outcome"] == OK:
            self._own_success.add(key)
        else:
            self._last_error[key] = result["detail"] or result["outcome"]
        if result["outcome"] in (P1, P3):
            row = self.port.operation(key)
            evidence = {"kind": result["kind"]} if result["outcome"] == P1 else {"stage": result["kind"]}
            try:
                self.port.absent(key, result["outcome"], evidence, expected_version=row["version"],
                                 event_id=self._ev(key, "e4"))
            except C.ContractError as error:
                return Outcome(row["state"], "E4 not recorded: %s" % error, sent=True)
        out = self.settle(key)
        out["sent"] = True
        out["result"] = result["outcome"]
        return out

    # ------------------------------------------------------------ readbacks

    def readback(self, row):
        """A fresh read of the tip, the default branch's activity and the PR (stamped, T2)."""
        branch = self._branch(row)
        tip = self.t.read_ref(row["repo"], "refs/heads/%s" % branch)
        act = self.t.read_activity(row["repo"], branch)
        pr = self.t.read_pr(row["repo"], row["pr"])
        return self.port.stamp({"repo": row["repo"], "pr": row["pr"], "tip": tip, "activity": act,
                                "pr_merged": pr.get("merged") is True, "pr_state": pr.get("state"),
                                "pr_head": pr.get("head")})

    @staticmethod
    def applied(row, read):
        """True: the tip is H, or a complete activity read has (before B, after H). False: a complete read shows
        neither. None: inconclusive (an incomplete activity read). Reachability of H is never evidence."""
        if read.get("tip") == row["head"]:
            return True
        act = read.get("activity")
        if not isinstance(act, dict) or act.get("complete") is not True or not isinstance(act.get("entries"), list):
            return None
        return any(isinstance(e, dict) and e.get("before") == row["base"] and e.get("after") == row["head"]
                   for e in act["entries"])

    def settle(self, key):
        """One readback step for an unsettled op (no loop: the caller's tick calls it again)."""
        row = self.port.operation(key)
        if row is None:
            return Outcome("missing", "no such operation")
        state = row["state"]
        if state in ("confirmed", "abandoned", "intent", "held"):
            return Outcome(state, "nothing to read back")
        try:
            read = self.readback(row)
        except TransportError as error:
            return Outcome(state, "readback inconclusive: %s" % error)
        done = self.applied(row, read)
        try:
            if state == "absent-proven":
                self.port.after_absence(key, self.port.params(row), read, expected_version=row["version"],
                                        event_id=self._ev(key, "after-absence"), lease_ok=True)
                return Outcome(self.port.operation(key)["state"], "after an absence proof")
            if state == "fenced":
                if done is True:                                                     # E14: the late-apply watch
                    self.port.watch_confirm(key, read, expected_version=row["version"], event_id=self._ev(key, "e14"))
                return Outcome(self.port.operation(key)["state"], "fenced op watched (L5)")
            if done is True:
                return self._confirm(row, read)
            if state == "dispatched" and self.port.due(key, "B55", C.B55_REQUEST_SECONDS):
                row = self.port.unknown(key, expected_version=row["version"], event_id=self._ev(key, "e5"))
                state = row["state"]                                                 # E5
            if done is False and read["tip"] != row["base"]:
                return self._quiet_window(row, read)                                 # toward E13
            self._e13.pop(key, None)
            if state == "outcome-unknown" and self.port.due(key, "B37", C.B37_PROBE_SECONDS):
                row = self.port.readback_missed(key, expected_version=row["version"], event_id=self._ev(key, "b37"))
            return Outcome(row["state"], "no conclusive readback yet; nothing is sent again")
        except C.ContractError as error:
            return Outcome(self.port.operation(key)["state"], "readback not recorded: %s" % error)

    def reconcile(self, key):
        """E10's reconcile for a held op (ASSUMPTION A-reconcile: ahc-merge runs it at start and on its tick): a fresh
        read showing the update applied confirms it (attribution `observed`); a complete read with the tip neither B
        nor H and no (B, H) entry fences it. Anything else leaves it held. Elapsed time is never evidence, and
        nothing is ever sent for a held op."""
        row = self.port.operation(key)
        if row is None or row["state"] != "held":
            return Outcome(row["state"] if row else "missing", "the reconcile reads back held ops only")
        try:
            read = self.readback(row)
        except TransportError as error:
            return Outcome("held", "reconcile inconclusive: %s" % error)
        done = self.applied(row, read)
        try:
            if done is True:
                self.port.confirm(key, dict(read, attribution="observed"), expected_version=row["version"],
                                  event_id=self._ev(key, "e10"), actor="reconcile")
                return Outcome("confirmed", "E10 by the reconcile (observed)", attribution="observed")
            if done is False and read["tip"] != row["base"]:
                self.port.fence_held(key, read, expected_version=row["version"], event_id=self._ev(key, "e10f"))
                return Outcome("fenced", "E10: held, then fenced by a complete off read")
        except C.ContractError as error:
            return Outcome(self.port.operation(key)["state"], "reconcile not recorded: %s" % error)
        return Outcome("held", "held: a person decides; nothing is sent")

    def _confirm(self, row, read):
        key = row["key"]
        if read.get("pr_merged") is not True and not self.port.due(key, "E12", C.Contracts.PR_MARK_SECONDS):
            return Outcome(row["state"], "applied; waiting up to 10 min for the PR to show merged (E12)")
        attribution = "ahc-proven" if key in self._own_success else "observed"          # A-attr
        self.port.confirm(key, dict(read, attribution=attribution), expected_version=row["version"],
                          event_id=self._ev(key, "e3"))
        return Outcome("confirmed", "E3 (%s)" % attribution, attribution=attribution)

    def _quiet_window(self, row, read):
        """E13: the tip left B and is not H, with no (B, H) entry. Two complete reads, the first at least 2 min after
        the dispatch (or the restart that restarted the wait), the second 60 to 120 s after the first."""
        key = row["key"]
        start = self.port.e13_wait_start(key)
        first = self._e13.get(key)
        if first is not None and (read["mono"] - first["mono"] >= C.Contracts.OBSERVATION_SECONDS
                                  or first["boot"] != read["boot"]):
            first = None                                       # too old to be fresh at the fence: start again
        if first is None:
            if read["mono"] >= start + C.E13_FIRST_READ_SECONDS:
                self._e13[key] = read
            return Outcome(row["state"], "quiet window: waiting for the activity log to settle (E13)")
        if read["mono"] - first["mono"] < C.E13_READ_GAP_SECONDS:
            return Outcome(row["state"], "quiet window: second read not due yet (E13)")
        error = self._last_error.get(key, "no-response")
        self.port.fence(key, error, [first, read], expected_version=row["version"], event_id=self._ev(key, "e13"))
        self._e13.pop(key, None)
        return Outcome("fenced", "E13: the request may still apply if the branch is rewound to B (L5)")


# ---------------------------------------------------------------- T9: kill, revoke, disable

class Terminator:
    """Stops the sender's unit and confirms its cgroup is empty. Production: SystemdTerminator. Tests inject one."""

    def stop(self):                     # pragma: no cover - interface
        raise NotImplementedError

    def confirmed_gone(self):           # pragma: no cover - interface
        raise NotImplementedError


class SystemdTerminator(Terminator):
    """SIGKILL the `ahc-merge` unit and read its cgroup's process list. PENDING_REAL_TEST t9-systemd-kill: run only
    on the coordinator host; tests never call systemctl."""

    def __init__(self, systemctl, unit="ahc-merge.service", run=None):
        self.systemctl, self.unit = str(systemctl), unit
        self._run = run or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=10))

    def stop(self):
        self._run([self.systemctl, "kill", "--signal=SIGKILL", self.unit])

    def confirmed_gone(self):
        p = self._run([self.systemctl, "show", "-p", "ControlGroup", "--value", self.unit])
        cg = (p.stdout or "").strip()
        if p.returncode != 0 or not cg.startswith("/"):
            return False
        try:
            with open("/sys/fs/cgroup%s/cgroup.procs" % cg, encoding="ascii") as handle:
                return handle.read().strip() == ""
        except FileNotFoundError:
            return True                  # the unit's cgroup is gone with it
        except OSError:
            return False


class Fence:
    """T9's three fences. Each takes the dispatch lock EXCLUSIVELY within FENCE_BOUND_SECONDS; if a sender still holds
    it, the kill writes its epoch first, then each fence terminates the sender and confirms it gone before it acts and
    returns. `kill-incomplete` (and an incident) when the stop cannot be confirmed; the caller's timer retries."""

    def __init__(self, port, lock, kill, terminator, *, bound=FENCE_BOUND_SECONDS, stop_tries=3, sleep=time.sleep):
        self.port, self.lock, self.kill, self.term = port, lock, kill, terminator
        self.bound, self.stop_tries, self._sleep = float(bound), int(stop_tries), sleep
        self.incidents = []
        self._n = 0

    def _ev(self, what):
        self._n += 1
        return "fence:%s:%d:%s" % (what, self._n, os.urandom(4).hex())

    def _stop_sender(self):
        """Terminate and confirm, then take the lock to prove no sender holds it."""
        for _ in range(self.stop_tries):
            self.term.stop()
            if self.term.confirmed_gone():
                if self.lock.acquire(fcntl.LOCK_EX, timeout=1.0):
                    return True
            self._sleep(0.05)
        return False

    def _fenced(self, what, act, before_stop=None):
        in_flight = self.port.dispatched_ops()
        took = self.lock.acquire(fcntl.LOCK_EX, timeout=self.bound)       # T9: exclusive, at most 45 s
        try:
            if not took:
                if before_stop is not None:
                    before_stop()                       # the kill writes its epoch before the stop
                if not self._stop_sender():
                    self.incidents.append("%s incomplete: the sender could not be confirmed stopped" % what)
                    return {"result": "%s-incomplete" % what, "in_flight": in_flight}
                in_flight = sorted(set(in_flight) | set(self.port.dispatched_ops()))
            elif before_stop is not None:
                before_stop()
            act()
        finally:
            self.lock.release()
        return {"result": "%s complete" % what, "in_flight": in_flight}

    def kill_switch(self):
        """Turn the kill switch on: new epoch (fsynced), every live grant revoked (G9); a request already in flight
        settles by readback and is named by key."""
        state = {}

        def write_epoch():
            state.update(self.kill.bump())

        def revoke_all():
            if not state:
                write_epoch()
            for gid, version in self.port.live_grants():
                self.port.revoke_grant(gid, expected_version=version, event_id=self._ev("g9-" + gid),
                                       by="kill-switch", source="kill epoch %d" % state["epoch"])
        out = self._fenced("kill", revoke_all, before_stop=write_epoch)
        out["epoch"] = state.get("epoch")
        return out

    def revoke(self, gid, *, source):
        """G8: main's revoke (the caller verified main's stamp)."""
        def act():
            g = self.port.grant(gid)
            self.port.revoke_grant(gid, expected_version=g["version"], event_id=self._ev("g8-" + gid), by="main",
                                   source=source)
        return self._fenced("revoke", act)

    def disable(self, repo, *, cause, actor="main"):
        """A per-repo disable: merging off for the repo."""
        def act():
            self.port.set_merging(repo, off=True, cause=cause, actor=actor if actor in ("main", "ahc-core") else
                                  "main")
        return self._fenced("disable", act)
