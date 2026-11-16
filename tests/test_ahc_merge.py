"""ahc_merge: the E2 sender (spec ahc-m1 v2g16, goodqa#16049 slice 1 (b) "the ahc_merge adapter").

EffectTests carries AC-6 cases 1 to 18 (including test_delayed_cas_trace), IdentityTests AC-8 and O1, T9Tests the
dispatch lock and the three fences, CanaryTests e9's CHK-CAS, and CrashSeamTests AC-18 for the send. Everything runs
against FakeGitHub, an in-process stand-in whose updateRefs enforces beforeOid as observed in REALLY_TESTED
chk-cas-updaterefs and chk-ff-dispatch: a typed non-fast-forward refusal; an untyped refusal when the stale beforeOid
is an ancestor of the tip, with the ref unchanged; an activity entry per applied update; a PR shown merged when its
head becomes the tip. No network, no gh, no credential file: fake tokens are built at run time.

Each test that a variant (tests/variants/ahc_merge_variants.py) maps to fails by an assertion, never by an
exception, so a variant kill is an AssertionError (the harness's rule).
"""
import hashlib
import json
import os
import random
import sqlite3
import string
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_contracts as C  # noqa: E402
import ahc_crash  # noqa: E402
import ahc_fs as fs  # noqa: E402
import ahc_merge as M  # noqa: E402

BOOT = "test-boot"
REPO = "o/r"
PR = 5
POLICY = "policy-r1"
CORE1 = "1" * 64
PKT = "d" * 64
KILL = 7
LOGIN, UID_GH = "octo-merger", 4242
MAIN = "refs/heads/main"


def oid(label):
    """A full commit sha built at run time (no sha-shaped literal in the corpus)."""
    return hashlib.sha1(("ahc-merge-test:%s" % label).encode()).hexdigest()


def fake_token():
    """A token-shaped string built at run time only (R5 clean corpus: no token-shaped literal is ever written)."""
    rng = random.Random(16049)
    return "gh" + "p_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


class Clock:
    """One fake clock for wall and monotonic time; optionally backed by a file so a child process shares it."""

    def __init__(self, path=None, start=1_800_000_000.0):
        self.path = Path(path) if path else None
        self._t = start
        if self.path and not self.path.exists():
            self.path.write_text(repr(start))

    @property
    def t(self):
        return float(self.path.read_text()) if self.path else self._t

    @t.setter
    def t(self, value):
        if self.path:
            self.path.write_text(repr(float(value)))
        else:
            self._t = float(value)

    def __call__(self):
        return self.t


# ---------------------------------------------------------------- the fake GitHub

class FakeGitHub(M.Transport):
    """In-process GitHub. `script` holds fault directives consumed by the next updateRefs, in order:
    None (normal), "lose" (applied, response lost), "drop" (not applied, no response), "untyped" (not applied, an
    untyped error), "typed" (not applied, a typed non-fast-forward refusal), "p3" (connection failed before any byte),
    "hang" (blocks until `release` is set, then applies), "delay" (not applied now, no response; `deliver()` applies
    it later as GitHub would, only if the ref is still at beforeOid). `w21_script` does the same for update-branch.
    `on_send()` is called at every write request; its value is stored on the request (the ledger state at send)."""

    def __init__(self, path=None):
        self.path = path
        self.commits = {}
        self.refs = {}
        self.prs = {}
        self.activity = []
        self.requests = []
        self.script = []
        self.w21_script = []
        self.pending = []
        self.runs = 0
        self.runs_on_canary = False
        self.mark_merged = True
        self.act_complete = True
        self.user = {"login": LOGIN, "id": UID_GH, "scopes": ["repo"]}
        self.perms = {REPO: {"push": True, "admin": False}}
        self.accept_non_ff = False
        self.on_send = None
        self.after_send = []          # one-shot callables run after the server processed the next updateRefs
        self.release = threading.Event()
        self._n = 0

    # ---- state helpers
    def commit(self, label, *parents):
        o = oid(label)
        self.commits[o] = list(parents)
        return o

    def ancestor(self, a, b):
        """a is an ancestor of, or equal to, b."""
        seen, todo = set(), [b]
        while todo:
            x = todo.pop()
            if x == a:
                return True
            if x in seen:
                continue
            seen.add(x)
            todo.extend(self.commits.get(x, []))
        return False

    def _entry(self, ref, before, after, kind):
        self._n += 1
        self.activity.append({"id": "act-%d" % self._n, "ref": ref, "before": before, "after": after, "type": kind})

    def push(self, ref, new, kind=None):
        """An out-of-band move (a person or another writer), recorded in the activity log."""
        cur = self.refs.get(ref)
        self.refs[ref] = new
        self._entry(ref, cur, new, kind or ("push" if cur is None or self.ancestor(cur, new) else "force_push"))
        self._mark(ref)

    def _mark(self, ref):
        if ref == MAIN and self.mark_merged:
            for p in self.prs.values():
                if p["state"] == "OPEN" and p["head"] == self.refs[ref]:
                    p["state"], p["merged"] = "MERGED", True

    # ---- writes
    def _apply(self, ref, before, after, force):
        cur = self.refs.get(ref)
        if before is not None and (cur or M.ZERO_OID) != before:
            if cur and before != M.ZERO_OID and self.ancestor(before, cur):
                return M.SendResult(M.UNTYPED, "Something went wrong while executing your query.")
            return M.SendResult(M.P1, "rejecting non-fast forward update", kind="non-fast-forward")
        if after == M.ZERO_OID:
            self.refs.pop(ref, None)
            self._entry(ref, cur, after, "branch_deletion")
            return M.SendResult(M.OK, "deleted")
        if cur is not None and not force and not self.ancestor(cur, after) and not self.accept_non_ff:
            return M.SendResult(M.P1, "rejecting non-fast forward update", kind="non-fast-forward")
        self.refs[ref] = after
        self._entry(ref, cur, after, "push" if cur is None or self.ancestor(cur, after) else "force_push")
        if ref == M.CANARY_REF and self.runs_on_canary:
            self.runs += 1
        self._mark(ref)
        return M.SendResult(M.OK, "updateRefs answered")

    def update_refs(self, repo, ref, before_oid, after_oid, force, timeout):
        req = {"kind": "updateRefs", "repo": repo, "ref": ref, "beforeOid": before_oid, "afterOid": after_oid,
               "force": force, "ledger": self.on_send() if self.on_send else None}
        self.requests.append(req)
        fault = self.script.pop(0) if self.script else None
        if fault == "p3":
            req["reached"] = False
            return M.SendResult(M.P3, "dial tcp: lookup api.github.com: no such host", kind="dns")
        if fault == "drop":
            return M.SendResult(M.NO_RESPONSE, "timeout")
        if fault == "untyped":
            return M.SendResult(M.UNTYPED, "Something went wrong while executing your query.")
        if fault == "typed":
            return M.SendResult(M.P1, "rejecting non-fast forward update", kind="non-fast-forward")
        if fault == "delay":
            self.pending.append((ref, before_oid, after_oid, force))
            return M.SendResult(M.NO_RESPONSE, "timeout")
        if fault == "hang":
            self.release.wait(10.0)
        res = self._apply(ref, before_oid, after_oid, force)
        while self.after_send:
            self.after_send.pop(0)()
        if fault == "lose":
            return M.SendResult(M.NO_RESPONSE, "read tcp: connection reset by peer")
        return res

    def deliver(self):
        """A delayed request reaches the server now (L5): it applies only if the ref is at its beforeOid."""
        out = []
        while self.pending:
            ref, before, after, force = self.pending.pop(0)
            out.append(self._apply(ref, before, after, force))
        return out

    def update_branch(self, repo, pr, expected_head_sha, timeout):
        req = {"kind": "update-branch", "repo": repo, "pr": pr, "expected_head_sha": expected_head_sha,
               "ledger": self.on_send() if self.on_send else None}
        self.requests.append(req)
        fault = self.w21_script.pop(0) if self.w21_script else None
        if fault == "drop":
            return M.SendResult(M.NO_RESPONSE, "timeout")
        p = self.prs[pr]
        if expected_head_sha is None or p["head"] != expected_head_sha:
            return M.SendResult(M.P1, "expected head sha didn't match current head ref", kind="expected-head")
        if p.get("conflict"):
            return M.SendResult(M.UNTYPED, "merge conflict")
        self._n += 1
        new = self.commit("w21-%d" % self._n, p["head"], self.refs[MAIN])
        p["head"] = new
        if fault == "lose":
            return M.SendResult(M.NO_RESPONSE, "timeout")
        return M.SendResult(M.OK, "accepted")

    # ---- reads
    def read_ref(self, repo, ref):
        if ref not in self.refs:
            raise M.TransportError("no such ref")
        return self.refs[ref]

    def read_activity(self, repo, branch):
        ref = "refs/heads/%s" % branch
        return {"complete": self.act_complete, "entries": [dict(e) for e in self.activity if e["ref"] == ref]}

    def read_pr(self, repo, pr):
        p = self.prs[pr]
        return {"state": p["state"], "head": p["head"], "merged": p["merged"], "draft": p["draft"],
                "mergeable": not p.get("conflict"), "mergeable_state": "dirty" if p.get("conflict") else "behind"}

    def compare(self, repo, base, head):
        if base == head:
            return "identical"
        if self.ancestor(base, head):
            return "ahead"
        if self.ancestor(head, base):
            return "behind"
        return "diverged"

    def commit_parents(self, repo, o):
        return list(self.commits.get(o, []))

    def workflow_runs(self, repo):
        return self.runs

    def whoami(self):
        return dict(self.user)

    def repo_permissions(self, repo):
        return dict(self.perms.get(repo, {}))

    def updates(self, kind="updateRefs"):
        return [r for r in self.requests if r["kind"] == kind]

    # ---- persistence (child-process tests)
    STATE = ("commits", "refs", "prs", "activity", "requests", "script", "w21_script", "pending", "runs", "_n",
             "mark_merged", "act_complete")

    def save(self):
        if self.path:
            data = {k: getattr(self, k) for k in self.STATE}
            data["prs"] = {str(k): v for k, v in self.prs.items()}
            Path(self.path).write_text(json.dumps(data))

    def load(self):
        if self.path and Path(self.path).exists():
            data = json.loads(Path(self.path).read_text())
            for k in self.STATE:
                setattr(self, k, data[k])
            self.prs = {int(k): v for k, v in data["prs"].items()}
            self.pending = [tuple(p) for p in self.pending]
        return self


class Persisted(M.Transport):
    """A FakeGitHub shared with a child process through a JSON file: load before, save after every call."""

    def __init__(self, path):
        self.path = path

    def __getattr__(self, name):
        fake = FakeGitHub(self.path).load()
        attr = getattr(fake, name)
        if not callable(attr):
            return attr

        def call(*a, **kw):
            f = FakeGitHub(self.path).load()
            try:
                return getattr(f, name)(*a, **kw)
            finally:
                f.save()
        return call

    def update_refs(self, *a, **kw):
        return self.__getattr__("update_refs")(*a, **kw)

    def update_branch(self, *a, **kw):
        return self.__getattr__("update_branch")(*a, **kw)


# ---------------------------------------------------------------- the scenario

class World:
    """One ledger, kill store, lock, canary store and fake GitHub, built in `root` (a 0700 directory). With
    `files=True` the ledger is a file, the clock is file-backed and the fake persists, so a child process (or a
    restart) reopens the same world."""

    def __init__(self, root, files=False, fake=None):
        self.root = Path(root)
        self.files = files
        self.clock = Clock(self.root / "clock" if files else None)
        # check_same_thread=False: the fake's on_send reads the ledger from the sender's send thread (test only)
        self.db = sqlite3.connect(str(self.root / "ledger.sqlite3") if files else ":memory:", isolation_level=None,
                                  check_same_thread=False)
        C.apply_schema(self.db)
        for d in ("authority", "kill", "canary"):
            os.makedirs(str(self.root / d), mode=0o700, exist_ok=True)
        self.c = C.Contracts(self.db, C.AuthorityLog(self.root / "authority" / "log.jsonl"), now=self.clock,
                             mono=self.clock, boot_id=BOOT)
        self.port = M.LedgerPort(self.c)
        self.kill = M.KillStore(self.root / "kill")
        self.lock_path = self.root / "dispatch.lock"
        self.canary = M.CanaryStore(self.root / "canary")
        self.gh = fake or (Persisted(str(self.root / "fake.json")) if files else FakeGitHub())
        self.identity = M.MergeIdentity(LOGIN, UID_GH, mono=self.clock, boot_id=BOOT)
        self.green = True
        self.n = 0

    def ev(self):
        self.n += 1
        return "w-ev-%d-%s" % (self.n, os.urandom(3).hex())

    def lock(self):
        return M.DispatchLock(self.lock_path)

    def sender(self, **kw):
        kw.setdefault("send_deadline", 2.0)
        return M.Sender(self.port, self.gh, self.lock(), self.kill, self.identity, self.canary, allowlist={REPO},
                        checks=lambda row: self.green, branches={REPO: "main"}, **kw)

    def obs(self, item=None, **changes):
        """A fresh ELIG observation for the WorkItem rows (what core's producer would record)."""
        item = item or self.item()
        o = {"id": "obs-%s" % os.urandom(3).hex(), "at": self.clock.t, "repo": REPO, "pr": item["pr"],
             "pr_state": "OPEN", "pr_head": item["head"], "tip": item["base"], "draft": False, "compare": "ahead",
             "b_r_ancestors": {item["base"]: True}, "attached_core": CORE1, "open_findings": 0,
             "paths": ["harness/lib/x.py"], "foreign_closing_keyword": False,
             "policy": {"revision": POLICY, "readable": True, "allowlisted": True, "enabled": True,
                        "checks_green": True, "grant_source": "queue:fixture#6165f60532c0",
                        "default_branch": "main"},
             "kill_switch": False, "kill_epoch": KILL, "chk_cas": True, "canary_age": 3600.0, "mirror_ok": True}
        o.update(changes)
        o.setdefault("mono", o["at"])
        o.setdefault("boot", BOOT)
        return o

    def item(self, iid=None):
        return self.c._row("work_items", "id", iid or self.iid)

    def move(self, row, iid=None, **kw):
        item = self.item(iid)
        kw.setdefault("actor", "ahc-core")
        kw.setdefault("event_id", self.ev())
        return self.c.wi_move(item["id"], row, expected_version=item["version"], **kw)

    def build(self, *, pr=PR, head=None, base=None, open_pr=True):
        """Commits R -> B -> A -> H on main's line (B the tip), a PR at H, an item admitted, reviews passed, W2 and
        W7, the grant activated and reserved: one op in intent, ready for E2."""
        gh = self.gh if isinstance(self.gh, FakeGitHub) else FakeGitHub(self.gh.path)
        if not gh.commits:
            gh.commit("R")
            gh.commit("B", oid("R"))
            gh.commit("A", oid("B"))
            gh.commit("H", oid("A"))
            gh.commit("S", oid("B"))          # an unrelated successor of B (not an ancestor of H)
            gh.commit("H2", oid("H"))         # a later head (or a later integration that contains H)
            gh.refs[MAIN] = oid("B")
            gh.refs["refs/heads/feature"] = oid("H")
            gh.runs = 3
        head, base = head or oid("H"), base or oid("B")
        gh.prs[pr] = {"state": "OPEN" if open_pr else "CLOSED", "head": head, "merged": False, "draft": False}
        if not isinstance(self.gh, FakeGitHub):
            gh.save()
        self.kill.write(False, KILL)
        if not self.lock_path.exists():
            fs.write_file(self.root, self.lock_path, b"")
        self.identity.check(self.gh, {REPO})
        self.canary.write({"repo": REPO, "identity": {"login": LOGIN, "id": UID_GH}, "passed": True, "cases": {},
                           "boot": BOOT, "mono": self.clock.t})
        item = self.c.admit_item(REPO, pr, head, base, POLICY, CORE1, PKT, event_id=self.ev())
        self.iid = item["id"]
        self.db.execute("UPDATE reviews SET state='passed' WHERE item=?", (item["id"],))
        self.move("W2", obs=self.obs())
        self.move("W7", obs=self.obs())
        g = self.grant_of(item["id"])
        g = self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        key = self.op_of(item["id"])["key"]
        self.c.reserve_grant(g["id"], key, expected_version=g["version"], event_id=self.ev(), mirror_read_back=True,
                             kill_epoch=KILL)
        return key

    def op_of(self, iid):
        cur = self.db.execute("SELECT * FROM operations WHERE item=? ORDER BY created DESC, generation DESC LIMIT 1",
                              (iid,))
        row = cur.fetchone()
        return dict(zip([d[0] for d in cur.description], row)) if row else None

    def grant_of(self, iid):
        item = self.item(iid)
        cur = self.db.execute("SELECT * FROM grants WHERE repo=? AND pr=? AND head=? AND base=? ORDER BY created DESC "
                              "LIMIT 1", (item["repo"], item["pr"], item["head"], item["base"]))
        row = cur.fetchone()
        return dict(zip([d[0] for d in cur.description], row)) if row else None

    def op(self, key):
        return self.c._row("operations", "key", key)

    def grant(self, key):
        return self.c._row("grants", "id", self.op(key)["grant_id"])

    def tick(self, sender, key, seconds=0, n=1):
        """Advance the clock and run `n` settle steps; returns the last outcome."""
        out = None
        for _ in range(n):
            self.clock.t += seconds
            out = sender.settle(key)
        return out


def run_child(root, phase, key, seam=None, count=None, extra=(), timeout=60):
    """Run one phase of a world in a child process (a crash or a restart of ahc-merge)."""
    env = dict(os.environ, AHC_CRASH_UNDER_TEST="1", PYTHONDONTWRITEBYTECODE="1")
    env.pop(ahc_crash.ENV_SEAM, None)
    env.pop(ahc_crash.ENV_COUNT, None)
    if seam:
        env[ahc_crash.ENV_SEAM] = seam
    if count:
        env[ahc_crash.ENV_COUNT] = str(count)
    code = ("import sys; sys.path.insert(0, %r); import tests.test_ahc_merge as T; T._child_main(sys.argv[1:])"
            % str(ROOT))
    return subprocess.run([sys.executable, "-B", "-c", code, str(root), phase, key] + list(extra), cwd=str(ROOT),
                          env=env, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)


def _child_main(argv):
    """A child `ahc-merge` process over a file-backed world. Phases: dispatch (E2 once), resume (a restart: E2 is
    tried again and must not send, then readbacks until the op settles or is held), canary, kill, w21."""
    root, phase, key = Path(argv[0]), argv[1], argv[2]
    w = World(root, files=True)
    w.identity.check(w.gh, {REPO})
    if phase == "dispatch":
        out = w.sender().dispatch(key)
    elif phase == "resume":
        s = w.sender()
        out = s.dispatch(key)
        for _ in range(C.B37_PROBES + 10):
            if w.op(key)["state"] in ("confirmed", "abandoned", "held", "fenced"):
                break
            w.clock.t += C.B37_PROBE_SECONDS
            out = s.settle(key)
    elif phase == "canary":
        out = M.Canary(w.gh, w.identity, w.canary, w.port, w.lock(), w.kill).run(REPO, "main")
    elif phase == "kill":
        out = M.Fence(w.port, w.lock(), w.kill, None, bound=1.0).kill_switch()
    elif phase == "w21":
        out = w.sender().update_branch(key)
    else:
        raise SystemExit("unknown phase")
    sys.stdout.write(json.dumps(out, default=str) + "\n")


def attempt(fn, *a, **kw):
    """(True, result) or (False, the exception): tests assert on it, so a refusal never escapes as an error."""
    try:
        return True, fn(*a, **kw)
    except Exception as error:      # noqa: BLE001 - the caller asserts on the type and text
        return False, error


class Base(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o700)
        self.w = self.world()

    def world(self, files=False):
        root = Path(tempfile.mkdtemp(dir=self.tmp.name))
        os.chmod(str(root), 0o700)
        return World(root, files=files)

    def ledger_state(self, w, key):
        return lambda: w.op(key)["state"]

    def assert_one_cas(self, gh, base, head):
        ups = [r for r in gh.updates() if r["ref"] == MAIN]
        self.assertEqual(len(ups), 1, "exactly one updateRefs request: %s" % ups)
        r = ups[0]
        self.assertEqual((r["beforeOid"], r["afterOid"], r["force"]), (base, head, False),
                         "beforeOid B, afterOid the reviewed H, force false")
        self.assertEqual(r["ledger"], "dispatched", "the request left only after the dispatched row committed")
        return r


# ---------------------------------------------------------------- AC-6: the integration effect

class EffectTests(Base):
    """AC-6 cases 1 to 18 through ahc_merge.Sender (the WorkItem rows around it are driven as ahc-core would)."""

    def ready(self, w=None):
        w = w or self.w
        key = w.build()
        w.gh.on_send = self.ledger_state(w, key)
        return key

    def test_01_success_tip_h_activity_entry_pr_merged(self):
        w = self.w
        key = self.ready()
        out = w.sender().dispatch(key)
        self.assert_one_cas(w.gh, oid("B"), oid("H"))
        self.assertEqual(w.gh.refs[MAIN], oid("H"), "the tip becomes H")
        self.assertIn((oid("B"), oid("H")), [(e["before"], e["after"]) for e in w.gh.activity])
        self.assertEqual(w.gh.prs[PR]["state"], "MERGED")
        self.assertEqual((out["state"], out.get("attribution")), ("confirmed", "ahc-proven"))
        self.assertEqual(json.loads(w.op(key)["evidence"])["attribution"], "ahc-proven")
        self.assertEqual(w.grant(key)["state"], "consumed")
        self.assertEqual(w.move("W8")["state"], "merged")
        # a second call never sends again
        again = w.sender().dispatch(key)
        self.assertEqual((again["state"], again["sent"], len(w.gh.updates())), ("confirmed", False, 1))

    # (2) base moved between the last observation and the send: four tips, each with a typed and an untyped answer
    MOVES = {"to H": "H", "to an ancestor of H": "A", "to an ancestor of B": "R",
             "to an unrelated successor of B": "S"}

    def base_moved(self, label, answer):
        w = self.world()
        key = w.build()
        w.gh.on_send = self.ledger_state(w, key)
        tip = oid(self.MOVES[label])
        w.gh.script = [answer]
        s = w.sender(hooks={"committed": lambda: w.gh.push(MAIN, tip)})
        s.dispatch(key)
        return w, s, key, tip

    def test_02_base_moved_typed_refusal_abandons_and_returns_to_pr_gate(self):
        for label in self.MOVES:
            with self.subTest(tip=label):
                w, s, key, tip = self.base_moved(label, "typed")
                self.assert_one_cas(w.gh, oid("B"), oid("H"))
                if tip == oid("H"):
                    # the tip is H: whatever the answer, the readback shows the update applied (E16 for a typed p1)
                    self.assertEqual(w.op(key)["state"], "abandoned")
                    self.assertEqual(w.grant(key)["state"], "retired")
                    continue
                row = w.op(key)
                self.assertEqual((row["state"], row["proof"]), ("abandoned", "all-sends-absent"), "E8")
                self.assertEqual(w.grant(key)["state"], "retired", "G5: the CAP1 slot is released")
                self.assertEqual(w.c.cap_used(REPO), 0)
                self.assertEqual(w.move("W9")["state"], "pr-gate", "W9")
                self.assertEqual(w.gh.refs[MAIN], tip, "the ref is unchanged")

    def test_02_base_moved_untyped_error_is_never_w9(self):
        for label in self.MOVES:
            with self.subTest(tip=label):
                w, s, key, tip = self.base_moved(label, "untyped")
                self.assert_one_cas(w.gh, oid("B"), oid("H"))
                if tip == oid("H"):
                    s.settle(key)
                    row = w.op(key)
                    self.assertEqual((row["state"], json.loads(row["evidence"])["attribution"]),
                                     ("confirmed", "observed"),
                                     "E3 by readback after an untyped error: observed, never ahc-proven")
                    continue
                # E13: two complete reads, the first 2 min after the dispatch, the second 60 s later
                w.tick(s, key, seconds=C.E13_FIRST_READ_SECONDS)
                w.tick(s, key, seconds=C.E13_READ_GAP_SECONDS)
                row = w.op(key)
                self.assertEqual(row["state"], "fenced", "E13 (p2), never absence")
                self.assertEqual(w.grant(key)["state"], "reserved", "the grant stays reserved")
                self.assertEqual(w.c.cap_used(REPO), 1, "the CAP1 slot stays held")
                self.assertEqual(w.c.next_generation(REPO, PR, oid("B"), oid("H"), POLICY), row["generation"],
                                 "no new generation for this (B, H)")
                self.assertIn(key, [x["key"] for x in w.c.watched(REPO)], "the late-apply watch runs")
                self.assertEqual(w.item()["state"], "merge-ready", "the item stays in merge-ready")
                ok, err = attempt(w.move, "W9")
                self.assertFalse(ok, "W9 never fires on an untyped error")
                self.assertEqual(len(w.gh.updates()), 1, "nothing is sent again")

    def test_05_timeout_then_readback_shows_the_activity_entry(self):
        w = self.w
        key = self.ready()
        w.gh.script = ["lose"]
        w.gh.after_send.append(lambda: w.gh.push(MAIN, oid("H2")))   # a later integration, before the readback
        s = w.sender()
        out = s.dispatch(key)
        self.assertEqual(out["result"], M.NO_RESPONSE, "the response was lost")
        self.assertNotEqual(w.gh.refs[MAIN], oid("H"), "the tip is not H: only the activity entry can confirm")
        self.assertEqual((w.op(key)["state"], out.get("attribution")), ("confirmed", "observed"),
                         "confirmed by the (B, H) activity entry; observed after a lost response")
        self.assert_one_cas(w.gh, oid("B"), oid("H"))

    def test_06_timeout_then_refusal_is_absent_proven(self):
        """A connect timeout before any byte (p3) retries the same key (E7); the retry meets a moved base and a
        typed refusal (p1): absent-proven, then abandoned (E8) with every send proven absent."""
        w = self.w
        key = self.ready()
        w.gh.script = ["p3", "typed"]
        s = w.sender()
        out = s.dispatch(key)
        self.assertEqual(w.op(key)["state"], "intent", "p3 with the tip still B: E7 back to intent")
        out = s.dispatch(key)
        row = w.op(key)
        self.assertEqual((row["state"], row["proof"], row["dispatch_count"], row["proven_absent"]),
                         ("abandoned", "all-sends-absent", 2, 2))
        self.assertEqual(w.grant(key)["state"], "retired")
        ups = w.gh.updates()
        self.assertEqual([u["ledger"] for u in ups], ["dispatched", "dispatched"])
        self.assertEqual(out["result"], M.P1)

    def test_07_timeout_with_no_conclusive_readback_is_held(self):
        w = self.w
        key = self.ready()
        w.gh.script = ["drop"]
        s = w.sender()
        s.dispatch(key)
        w.tick(s, key, seconds=C.B55_REQUEST_SECONDS)
        self.assertEqual(w.op(key)["state"], "outcome-unknown", "E5 after B55")
        w.tick(s, key, seconds=C.B37_PROBE_SECONDS, n=C.B37_PROBES)
        row = w.op(key)
        self.assertEqual((row["state"], row["readbacks"]), ("held", C.B37_PROBES), "E6 after 20 readbacks")
        self.assertEqual(w.grant(key)["state"], "reserved")
        self.assertEqual(len(w.gh.updates()), 1, "no second CAS without p1 or p3 (NEG-3)")

    def test_11_untyped_error_with_tip_at_b_stays_unknown_and_never_retries(self):
        w = self.w
        key = self.ready()
        w.gh.script = ["untyped"]
        s = w.sender()
        out = s.dispatch(key)
        self.assertEqual((out["state"], w.op(key)["proven_absent"]), ("dispatched", 0), "untyped is not absence")
        for _ in range(C.B37_PROBES + 5):
            w.tick(s, key, seconds=C.B37_PROBE_SECONDS)
            self.assertNotIn(w.op(key)["state"], ("absent-proven", "abandoned", "intent"))
            self.assertEqual(s.dispatch(key)["sent"], False, "a dispatched or unknown op is never sent again")
        self.assertEqual(w.op(key)["state"], "held")
        self.assertEqual(w.grant(key)["state"], "reserved", "the grant stays reserved")
        self.assertEqual(len(w.gh.updates()), 1)

    def test_08_crash_after_dispatch_and_before_the_record_never_sends_again(self):
        """A crash right after the send (before its result is recorded) and one right after the dispatch commit
        (before the send): the restart finds the row dispatched, never sends again, and settles it by readback."""
        for seam, sent in (("merge.send:after@1", 1), ("merge.send:before@1", 0)):
            with self.subTest(seam=seam):
                w = self.world(files=True)
                key = w.build()
                died = run_child(w.root, "dispatch", key, seam=seam)
                self.assertEqual(died.returncode, ahc_crash.CRASH_EXIT, died.stderr[-800:])
                self.assertIn("%s %s" % (ahc_crash.MARKER, seam), died.stderr)
                row = w.op(key)
                self.assertEqual((row["state"], row["dispatch_count"]), ("dispatched", 1),
                                 "the count rose before the send and survives the crash")
                self.assertEqual(len(FakeGitHub(w.gh.path).load().updates()), sent)
                resumed = run_child(w.root, "resume", key)
                self.assertEqual(resumed.returncode, 0, resumed.stderr[-800:])
                fake = FakeGitHub(w.gh.path).load()
                self.assertEqual(len(fake.updates()), sent, "the restart never sends a dispatched op again")
                row = w.op(key)
                if sent:
                    self.assertEqual((row["state"], json.loads(row["evidence"])["attribution"]),
                                     ("confirmed", "observed"), "confirmed by readback; observed after a restart")
                else:
                    self.assertEqual(row["state"], "held", "no request went out: held after 20 readbacks, a "
                                     "person decides (never retried)")
                    self.assertEqual(w.grant(key)["state"], "reserved")


if __name__ == "__main__":
    unittest.main()
