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
    it later as GitHub would, only if the ref is still at beforeOid).
    `on_send()` is called at every write request; its value is stored on the request (the ledger state at send)."""

    def __init__(self, path=None):
        self.path = path
        self.commits = {}
        self.refs = {}
        self.prs = {}
        self.activity = []
        self.requests = []
        self.script = []
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
        """A tripwire: ahc_merge never writes a PR branch (W21 is the daemon's, owner ruling). Recorded, not applied."""
        self.requests.append({"kind": "update-branch", "repo": repo, "pr": pr})
        return M.SendResult(M.OK, "accepted")

    def push_git(self, *a, **kw):
        """A tripwire for a plain `git push` fallback (NEG-19): recorded, never applied."""
        self.requests.append({"kind": "git-push"})
        return M.SendResult(M.OK, "pushed")

    def writes(self):
        """Every write request of any kind (for NEG-17 / NEG-19: only updateRefs ever appears)."""
        return [r for r in self.requests if r["kind"] != "updateRefs"]

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
    STATE = ("commits", "refs", "prs", "activity", "requests", "script", "pending", "runs", "_n",
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

    def restart(self):
        """A restart of ahc-core and ahc-merge over the same ledger: new Contracts, port and identity check; every
        in-process memory (own-success, last error, the E13 first read) is gone."""
        self.c = C.Contracts(self.db, C.AuthorityLog(self.root / "authority" / "log.jsonl"), now=self.clock,
                             mono=self.clock, boot_id=BOOT)
        self.port = M.LedgerPort(self.c)
        self.identity = M.MergeIdentity(LOGIN, UID_GH, mono=self.clock, boot_id=BOOT)
        self.identity.check(self.gh, {REPO})

    def sender(self, **kw):
        kw.setdefault("send_deadline", 2.0)
        return M.Sender(self.port, self.gh, self.lock(), self.kill, self.identity, self.canary, allowlist={REPO},
                        checks=lambda row: self.green, **kw)

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
            gh.commit("R0")
            gh.commit("R", oid("R0"))
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
    tried again and must not send, then readbacks until the op settles or is held), canary, kill."""
    root, phase, key = Path(argv[0]), argv[1], argv[2]
    w = World(root, files=True)
    w.identity.check(w.gh, {REPO})
    if phase == "dispatch":
        out = w.sender().dispatch(key)
    elif phase == "gated":
        def gate():
            """The T9 test gate, right after the last epoch check: announce it, then wait. The test's terminator
            ends this process by closing its stdin; it exits at once, as SIGKILL would end it (no cleanup)."""
            (root / "paused").write_text(str(os.getpid()))
            sys.stdin.read()
            os._exit(137)
        out = w.sender(hooks={"epoch-checked": gate}).dispatch(key)
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
    else:
        raise SystemExit("unknown phase")
    sys.stdout.write(json.dumps(out, default=str) + "\n")


def reap(proc):
    """Cleanup for a spawned child: close its pipes (it exits on stdin EOF) and wait for it."""
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe and not pipe.closed:
            pipe.close()
    proc.wait(timeout=20)


def spawn_child(root, phase, key):
    """A long-running child `ahc-merge` (Popen): it pauses at the T9 gate until its stdin closes."""
    env = dict(os.environ, AHC_CRASH_UNDER_TEST="1", PYTHONDONTWRITEBYTECODE="1")
    env.pop(ahc_crash.ENV_SEAM, None)
    code = ("import sys; sys.path.insert(0, %r); import tests.test_ahc_merge as T; T._child_main(sys.argv[1:])"
            % str(ROOT))
    return subprocess.Popen([sys.executable, "-B", "-c", code, str(root), phase, key], cwd=str(ROOT), env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class ChildTerminator(M.Terminator):
    """The test's stand-in for SystemdTerminator: ends the child by closing its stdin (the gate exits at once) and
    confirms it gone by its exit status (the cgroup-empty check, PENDING_REAL_TEST t9-systemd-kill). `works=False`
    models a stop that cannot be confirmed."""

    def __init__(self, proc, works=True, kill_store=None):
        self.proc, self.works, self.store = proc, works, kill_store
        self.calls = []

    def stop(self):
        self.calls.append(("stop", self.store.read() if self.store else None))
        if self.works and self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()

    def confirmed_gone(self):
        self.calls.append(("confirm", None))
        if not self.works:
            return False
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            return False
        return True


def wait_for(path, seconds=20.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if Path(path).exists():
            return True
        time.sleep(0.02)
    return False


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


    def test_03_head_moved_before_dispatch_sends_nothing_then_w4(self):
        w = self.w
        key = self.ready()
        w.gh.prs[PR]["head"] = oid("H2")                         # the author pushed H' after the last observation
        out = w.sender().dispatch(key)
        self.assertEqual((out["state"], out["sent"]), ("refused", False), "the E2 guard re-reads the PR head")
        self.assertEqual(w.gh.requests, [], "nothing is sent")
        self.assertEqual(w.op(key)["state"], "intent")
        item = w.move("W4", obs=w.obs(pr_head=oid("H2")), successor_packet="e" * 64)
        self.assertEqual(item["state"], "superseded", "W4")
        self.assertEqual(w.op(key)["state"], "abandoned", "E9: an intent never sent is abandoned")
        self.assertEqual(w.grant(key)["state"], "retired")

    def test_04_red_check_sends_nothing_then_w5(self):
        w = self.w
        key = self.ready()
        w.green = False
        out = w.sender().dispatch(key)
        self.assertEqual((out["state"], out["sent"]), ("refused", False), "checks_green is false at E2")
        self.assertEqual(w.gh.requests, [])
        obs = w.obs()
        obs["policy"] = dict(obs["policy"], checks_green=False)
        self.assertEqual(w.move("W5", obs=obs)["state"], "waiting-dep", "W5")
        self.assertEqual(w.op(key)["state"], "abandoned", "E9")

    def test_09_same_key_with_other_parameters_is_an_error_and_nothing_is_sent(self):
        w = self.w
        key = self.ready()
        row = w.op(key)
        params = dict(w.port.params(row), default_branch="other")
        ok, err = attempt(w.c.intend, params, item=row["item"], lease_ok=True, event_id=w.ev())
        self.assertFalse(ok, "E1: the same key with other parameters is raised")
        self.assertIsInstance(err, C.ContractError)
        # the request is built only from the committed row and the reviewed H: any other (B, H) is refused
        s = w.sender()
        for req in ({"method": "updateRefs", "beforeOid": oid("B"), "afterOid": oid("H2"), "force": False},
                    {"method": "updateRefs", "beforeOid": oid("A"), "afterOid": oid("H"), "force": False},
                    {"method": "updateRefs", "beforeOid": oid("B"), "afterOid": oid("H"), "force": True},
                    {"method": "push", "beforeOid": oid("B"), "afterOid": oid("H"), "force": False}, None):
            ok, err = attempt(s.payload, row, req, oid("H"))
            self.assertFalse(ok, "payload refuses %s" % req)
        # a Review row that names another H: refused before E2, nothing sent
        w.db.execute("UPDATE reviews SET head=? WHERE item=? AND kind='adversarial'", (oid("H2"), row["item"]))
        out = s.dispatch(key)
        self.assertEqual((out["state"], out["sent"], w.op(key)["state"]), ("refused", False, "intent"))
        self.assertEqual(w.gh.requests, [])

    def test_10_later_integration_containing_h_confirms_only_by_the_activity_entry(self):
        w = self.w
        key = self.ready()
        w.gh.script = ["lose"]
        w.gh.after_send.append(lambda: w.gh.push(MAIN, oid("H2")))   # H2 contains H: H is reachable from the tip
        w.gh.act_complete = False
        s = w.sender()
        s.dispatch(key)
        self.assertTrue(w.gh.ancestor(oid("H"), w.gh.refs[MAIN]), "H is reachable")
        for _ in range(3):
            out = w.tick(s, key, seconds=30)
            self.assertNotEqual(w.op(key)["state"], "confirmed", "reachability alone never confirms (E3)")
            self.assertNotIn("not recorded", out["why"], "the sender never asks the ledger to confirm without a "
                             "(B, H) entry or the tip at H (the ledger's own refusal is a second line, not the first)")
        w.gh.act_complete = True
        w.tick(s, key, seconds=30)
        row = w.op(key)
        self.assertEqual((row["state"], json.loads(row["evidence"])["attribution"]), ("confirmed", "observed"))

    def delayed_cas_trace(self, days):
        w = self.world()
        key = w.build()
        w.gh.on_send = self.ledger_state(w, key)
        w.gh.script = ["delay"]                                   # the request is delayed; its response is lost
        s = w.sender()
        s.dispatch(key)
        w.gh.push(MAIN, oid("S"))                                 # the tip leaves B without (B, H)
        w.tick(s, key, seconds=C.E13_FIRST_READ_SECONDS)
        w.tick(s, key, seconds=C.E13_READ_GAP_SECONDS)
        self.assertEqual(w.op(key)["state"], "fenced", "E13")
        generation, grants = w.op(key)["generation"], w.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
        # a cancel (ASSUMPTION A-cancel: the owner's cancel of the item): refused while the Effect is unsettled (T7)
        item = w.item()
        ok, _ = attempt(w.c.wi_move, item["id"], "W20", expected_version=item["version"], event_id=w.ev(),
                        actor="owner")
        self.assertFalse(ok, "the item is not cancelled under a fenced Effect")
        ok, again = attempt(w.c.intend, w.port.params(w.op(key)), item=item["id"], lease_ok=True, event_id=w.ev())
        self.assertTrue(not ok or (again["key"], again["generation"]) == (key, generation),
                        "no new generation for a fenced (B, H): %r" % (again,))
        w.clock.t += days * 86400
        w.c.retain()
        w.gh.push(MAIN, oid("B"))                                 # the branch is rewound exactly to B
        self.assertEqual(s.settle(key)["state"], "fenced", "still fenced: nothing applied yet")
        applied = w.gh.deliver()                                  # the delayed CAS reaches the server now
        self.assertEqual([r["outcome"] for r in applied], [M.OK])
        s.settle(key)                                             # the watch (E14)
        row = w.op(key)
        self.assertEqual((row["state"], row["incident"], row["tombstone"]), ("confirmed", 1, 0))
        self.assertTrue(w.c.merging_off(REPO), "E14 turns the repo's merging off")
        self.assertEqual(w.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], grants, "no new grant")
        self.assertEqual(w.db.execute("SELECT MAX(generation) FROM operations").fetchone()[0], generation)
        self.assertEqual(len(w.gh.updates()), 1, "ahc-merge sent exactly one request")

    def test_delayed_cas_trace(self):
        for days in (1, 31):
            with self.subTest(days=days):
                self.delayed_cas_trace(days)

    def test_14_no_passing_chk_cas_is_ineligible_and_sends_nothing(self):
        w = self.w
        key = self.ready()
        for record in (None, {"repo": REPO, "identity": {"login": LOGIN, "id": UID_GH}, "passed": False,
                              "cases": {}, "boot": BOOT, "mono": w.clock.t},
                       {"repo": REPO, "identity": {"login": "someone-else", "id": 1}, "passed": True, "cases": {},
                        "boot": BOOT, "mono": w.clock.t}):
            with self.subTest(record=record and (record["passed"], record["identity"]["login"])):
                path = w.canary._path(REPO)
                if record is None:
                    os.unlink(str(path))
                else:
                    w.canary.write(record)
                out = w.sender().dispatch(key)
                self.assertEqual((out["state"], out["sent"]), ("refused", False))
                self.assertEqual(w.gh.requests, [], "no updateRefs, no plain push, no other path (NEG-19)")
                self.assertEqual(w.op(key)["state"], "intent")
                facts = w.canary.local_facts(REPO, w.identity)
                age = w.c.clock.canary_age(facts["canary"])
                failed = w.c.elig(w.item(), w.obs(chk_cas=facts["chk_cas"], canary_age=age))
                self.assertIn("e9", failed, "ELIG e9 fails without a passing CHK-CAS")

    def test_16_absent_proven_while_h_is_on_the_branch_abandons_with_an_incident(self):
        for answer in ("typed", "p3"):
            with self.subTest(answer=answer):
                w = self.world()
                key = w.build()
                w.gh.on_send = self.ledger_state(w, key)
                w.gh.script = [answer]
                s = w.sender(hooks={"committed": lambda: w.gh.push(MAIN, oid("H"))})   # another writer integrates H
                s.dispatch(key)
                row = w.op(key)
                self.assertEqual((row["state"], row["incident"]), ("abandoned", 1), "E16, never confirmed")
                self.assertEqual(json.loads(w.db.execute(
                    "SELECT data FROM transitions WHERE id=? AND to_state='abandoned'", (key,)).fetchone()[0])["row"],
                    "E16")
                self.assertEqual(w.grant(key)["state"], "retired", "G5")
                self.assertEqual(w.c.cap_used(REPO), 0, "the CAP1 slot is released")


    # (13) the head race (L7). Each trace runs with and without a restart between the head move and E3.
    def race(self, move, answer, restart):
        w = self.world()
        key = w.build()
        w.gh.on_send = self.ledger_state(w, key)
        w.gh.script = {"ok": [], "lose": ["lose"], "typed": ["typed"], "p2": ["delay"], "held": ["delay"],
                       "fenced": ["delay"]}[answer]

        mark = "head-moved" if move == "head" else "closed-in-flight"
        extra = {"successor_packet": "e" * 64} if move == "head" else {}

        def w24():                                         # core observes the move while the Effect is unsettled
            obs = w.obs(pr_head=oid("H2")) if move == "head" else w.obs(pr_state="CLOSED")
            item = w.move("W24", mark=mark, obs=obs, **extra)
            self.assertIn(item["state"], ("merge-ready", "waiting-ask"), "W24 keeps the item where it is")

        def race_move():                                   # after the final observation, before the server applies
            if move == "head":
                w.gh.prs[PR]["head"] = oid("H2")
            else:
                w.gh.prs[PR]["state"] = "CLOSED"
            if answer != "held":
                w24()
        s = w.sender(hooks={"committed": race_move})
        s.dispatch(key)
        if answer == "held":
            for _ in range(C.B37_PROBES + 2):
                w.tick(s, key, seconds=C.B55_REQUEST_SECONDS)
            self.assertEqual(w.op(key)["state"], "held")
            w.move("W10")
            w24()
        if restart:
            w.restart()
            s = w.sender()
        self.assertEqual(s.dispatch(key)["sent"], False, "never sent again")
        if answer in ("ok", "lose"):
            w.tick(s, key, seconds=C.Contracts.PR_MARK_SECONDS)          # E3, as E12: the PR never shows merged
            self.assertEqual(w.op(key)["state"], "confirmed")
            w.move("W8")
        elif answer == "typed":
            self.assertEqual(w.op(key)["state"], "abandoned", "E4 then E8")
            self.assertEqual(w.move("W25", to="superseded")["state"], "superseded")
        elif answer == "held":
            w.gh.deliver()                                   # the request applies late, the tip still at B
            self.assertEqual(s.reconcile(key)["state"], "confirmed", "E10 by the reconcile")
            w.move("W26")
        else:                                                # p2 / fenced: the tip leaves B, then E13
            w.gh.push(MAIN, oid("S"))
            w.tick(s, key, seconds=C.E13_FIRST_READ_SECONDS)
            w.tick(s, key, seconds=C.E13_READ_GAP_SECONDS)
            self.assertEqual((w.op(key)["state"], w.item()["state"]), ("fenced", "merge-ready"), "E13, T7")
            if answer == "p2":                               # main's E15, then W25
                row = w.op(key)
                w.c.settle_fenced(key, {"support": "the request was dropped"}, expected_version=row["version"],
                                  event_id=w.ev(), actor="main")
                self.assertEqual(w.move("W25", to="closed-unmerged")["state"], "closed-unmerged")
            else:                                            # rewind to B, late apply, E14, then W8
                w.gh.push(MAIN, oid("B"))
                w.gh.deliver()
                s.settle(key)
                self.assertEqual(w.op(key)["state"], "confirmed", "E14")
                w.move("W8")
        return w, key

    def handovers(self, w, iid):
        return sorted(k for (k,) in w.db.execute("SELECT kind FROM wi_notices WHERE item=? AND row_id IN "
                                                 "('W8', 'W26')", (iid,)))

    def assert_merged_at_h(self, w, key, move):
        item = w.item()
        self.assertEqual((item["state"], item["head"]), ("merged", oid("H")), "merged at H")
        want = ["digest", "ticket"] + (["owner"] if move == "close" else [])
        self.assertEqual(self.handovers(w, item["id"]), sorted(want), "exactly one notice and handover")
        if move == "head":
            succ = w.item(item["successor"])
            self.assertEqual((succ["head"], succ["state"]), (oid("H2"), "pr-gate"), "W24 made H'")
            self.assertEqual(w.db.execute("SELECT COUNT(*) FROM wi_notices WHERE item=? AND text LIKE "
                                          "'%integrated%'", (succ["id"],)).fetchone()[0], 0,
                             "H' is never reported as integrated")

    def test_13_head_race(self):
        for move in ("head", "close"):
            for answer in ("ok", "lose", "held", "fenced"):
                for restart in (False, True):
                    with self.subTest(move=move, answer=answer, restart=restart):
                        w, key = self.race(move, answer, restart)
                        self.assert_merged_at_h(w, key, move)
        for restart in (False, True):
            with self.subTest(trace="head move then typed refusal", restart=restart):
                w, key = self.race("head", "typed", restart)
                self.assertEqual(w.item()["state"], "superseded")
            with self.subTest(trace="closure then p2 then E15", restart=restart):
                w, key = self.race("close", "p2", restart)
                self.assertEqual(w.item()["state"], "closed-unmerged")


# ---------------------------------------------------------------- T9: the dispatch lock and the three fences

class T9Tests(Base):
    """AC-6 (18) and NEG-13. The sender holds the dispatch flock SHARED; kill, revoke and disable take it EXCLUSIVE
    within 45 s (the bound is injected small here), else terminate the sender and confirm it gone before acting."""

    def test_bounds_are_the_spec_values(self):
        self.assertEqual((M.SEND_DEADLINE_SECONDS, M.FENCE_BOUND_SECONDS), (30.0, 45.0))
        self.assertEqual(M.Fence(None, None, None, None).bound, 45.0)

    def test_lock_modes(self):
        w = self.w
        w.build()
        a, b, x = w.lock(), w.lock(), w.lock()
        self.assertTrue(a.acquire(M.fcntl.LOCK_SH, 0.1))
        self.assertTrue(b.acquire(M.fcntl.LOCK_SH, 0.1), "two senders may share it")
        self.assertFalse(x.acquire(M.fcntl.LOCK_EX, 0.1), "a fence waits while a sender holds it")
        a.release()
        b.release()
        self.assertTrue(x.acquire(M.fcntl.LOCK_EX, 0.1))
        self.assertFalse(a.acquire(M.fcntl.LOCK_SH, 0.1), "no sender while a fence holds it")
        out = w.sender().dispatch(w.op_of(w.iid)["key"])
        self.assertEqual((out["state"], out["sent"]), ("deferred", False))
        x.release()
        link = w.root / "lock-link"
        os.symlink(str(w.lock_path), str(link))
        ok, _ = attempt(M.DispatchLock(link).acquire, M.fcntl.LOCK_SH, 0.1)
        self.assertFalse(ok, "the lock is never opened through a link")
        self.assertFalse(M.DispatchLock(w.root / "absent.lock").__class__ is None)
        ok, _ = attempt(M.DispatchLock(w.root / "absent.lock").acquire, M.fcntl.LOCK_SH, 0.1)
        self.assertFalse(ok, "the lock file is never created by the sender")

    def test_a_send_that_hangs_past_the_deadline_releases_the_lock_and_settles_by_readback(self):
        w = self.w
        key = w.build()
        w.gh.on_send = self.ledger_state(w, key)
        w.gh.script = ["hang"]
        s = w.sender(send_deadline=0.3)
        start = time.monotonic()
        out = s.dispatch(key)
        self.assertLess(time.monotonic() - start, 5.0)
        self.assertEqual((out["result"], w.op(key)["state"]), (M.NO_RESPONSE, "dispatched"))
        fence = M.Fence(w.port, w.lock(), w.kill, None, bound=0.5)
        res = fence.kill_switch()
        self.assertEqual(res["result"], "kill complete", "the lock was released at the deadline")
        self.assertEqual(res["in_flight"], [key], "the request in flight is named, never reported stopped")
        self.assertEqual(w.op(key)["state"], "dispatched")
        w.gh.release.set()                         # the hung request reaches the server and applies
        end = time.monotonic() + 5
        while w.gh.refs[MAIN] != oid("H") and time.monotonic() < end:
            time.sleep(0.01)
        w.tick(s, key, seconds=C.Contracts.PR_MARK_SECONDS)
        row = w.op(key)
        self.assertEqual((row["state"], json.loads(row["evidence"])["attribution"]), ("confirmed", "observed"))
        self.assertEqual(len(w.gh.updates()), 1)

    def test_kill_with_no_sender_takes_the_lock_writes_the_epoch_and_revokes(self):
        w = self.w
        key = w.build()
        res = M.Fence(w.port, w.lock(), w.kill, None, bound=0.5).kill_switch()
        self.assertEqual((res["result"], res["epoch"]), ("kill complete", KILL + 1))
        self.assertEqual(w.kill.read(), {"on": True, "epoch": KILL + 1})
        self.assertEqual(w.grant(key)["state"], "revoked", "G9")
        out = w.sender().dispatch(key)
        self.assertEqual((out["state"], out["sent"]), ("refused", False))
        self.assertEqual(w.gh.requests, [])

    def test_the_epoch_is_re_read_under_the_lock_at_every_dispatch(self):
        """A sender started before the kill: the epoch file turns on (the kill writes it before it revokes) and the
        next dispatch, by the same sender object, sends nothing. The grant is still reserved here, so only the
        sender's own re-read under the lock stops it."""
        w = self.w
        key = w.build()
        s = w.sender()
        w.kill.write(True, KILL + 1)
        self.assertEqual(w.grant(key)["state"], "reserved")
        out = s.dispatch(key)
        self.assertEqual((out["state"], out["sent"]), ("refused", False))
        self.assertEqual(w.gh.requests, [])

    FENCES = ("kill", "revoke", "disable")

    def fence(self, w, key, which, term):
        f = M.Fence(w.port, w.lock(), w.kill, term, bound=0.5)
        if which == "kill":
            return f, f.kill_switch()
        if which == "revoke":
            return f, f.revoke(w.op(key)["grant_id"], source="main: stop this grant")
        return f, f.disable(REPO, cause="main: stop this repo")

    def test_18_a_paused_sender_is_terminated_and_confirmed_gone_before_the_fence_returns(self):
        for which in self.FENCES:
            with self.subTest(fence=which):
                w = self.world(files=True)
                key = w.build()
                proc = spawn_child(w.root, "gated", key)
                self.addCleanup(reap, proc)
                self.assertTrue(wait_for(w.root / "paused"), "the child reached the gate after its epoch check")
                term = ChildTerminator(proc, kill_store=w.kill)
                f, res = self.fence(w, key, which, term)
                self.assertEqual(res["result"], "%s complete" % which)
                self.assertIsNotNone(proc.poll(), "the sender was gone before the fence returned")
                self.assertEqual(proc.returncode, 137)
                self.assertEqual([c[0] for c in term.calls[:2]], ["stop", "confirm"])
                if which == "kill":
                    self.assertEqual(term.calls[0][1], {"on": True, "epoch": KILL + 1},
                                     "the kill wrote its epoch before the stop")
                    self.assertEqual(w.grant(key)["state"], "revoked")
                elif which == "revoke":
                    self.assertEqual(w.grant(key)["state"], "revoked")
                else:
                    self.assertTrue(w.c.merging_off(REPO))
                self.assertEqual(w.op(key)["state"], "intent", "paused before E2: nothing was dispatched")
                again = run_child(w.root, "dispatch", key)               # ahc-merge restarts
                self.assertEqual(again.returncode, 0, again.stderr[-800:])
                self.assertEqual(FakeGitHub(w.gh.path).load().updates(), [], "zero requests for that op")
                if which == "disable":
                    # the sender's own layer refuses before any observation or E2 commit attempt; the Contracts E2
                    # guard (b50729c) is the second layer and would say "E2 not committed: ..." instead
                    self.assertEqual(json.loads(again.stdout.splitlines()[-1])["why"], "the repo's merging is off",
                                     "the sender refuses a disabled repo itself, before the contract guard")

    def test_18_an_unconfirmed_stop_returns_incomplete_with_an_incident(self):
        for which in self.FENCES:
            with self.subTest(fence=which):
                w = self.world(files=True)
                key = w.build()
                proc = spawn_child(w.root, "gated", key)
                self.addCleanup(reap, proc)
                self.assertTrue(wait_for(w.root / "paused"))
                f, res = self.fence(w, key, which, ChildTerminator(proc, works=False))
                self.assertEqual(res["result"], "%s-incomplete" % which)
                self.assertTrue(f.incidents, "an incident is raised")
                self.assertIsNone(proc.poll(), "the sender is still there; nothing claims it stopped")
                if which == "kill":
                    self.assertEqual(w.kill.read()["on"], True, "the epoch is still written first")
                else:
                    self.assertEqual(w.grant(key)["state"] if which == "revoke" else
                                     str(w.c.merging_off(REPO)), "reserved" if which == "revoke" else "False",
                                     "an incomplete revoke or disable does not claim to have acted")
                proc.stdin.close()
                proc.wait(timeout=20)


# ---------------------------------------------------------------- AC-8: the merge identity

class IdentityTests(Base):
    """AC-8 and O1: the pinned login and numeric id, the 10 min check age, the scope record, refusal without contents
    write, a warning on admin or all-repo scope."""

    def ident(self):
        return M.MergeIdentity(LOGIN, UID_GH, mono=self.w.clock, boot_id=BOOT)

    def test_the_pinned_account_passes_and_records_its_scopes(self):
        gh = FakeGitHub()
        gh.user = {"login": LOGIN.upper(), "id": UID_GH, "scopes": ["public_repo"]}
        i = self.ident()
        rec = i.check(gh, {REPO})
        self.assertEqual((rec["id"], rec["contents_write"], rec["admin"], rec["all_repo"], rec["warnings"]),
                         (UID_GH, True, False, False, []))
        self.assertTrue(i.fresh())
        self.assertIn("identity: merges act as the user's own GitHub account %s (id %d)" % (LOGIN, UID_GH),
                      i.status_lines())

    def test_another_account_is_refused_with_an_incident(self):
        for user in ({"login": LOGIN, "id": UID_GH + 1, "scopes": []},          # a renamed or recreated account
                     {"login": "someone-else", "id": UID_GH, "scopes": []},
                     {"login": LOGIN, "id": str(UID_GH), "scopes": []},
                     {"login": LOGIN, "id": None, "scopes": []}):
            with self.subTest(user=user):
                gh = FakeGitHub()
                gh.user = user
                i = self.ident()
                ok, err = attempt(i.check, gh, {REPO})
                self.assertFalse(ok)
                self.assertIsInstance(err, M.IdentityError)
                self.assertTrue(i.incidents)
                self.assertFalse(i.fresh(), "merging holds")

    def test_no_contents_write_is_refused(self):
        for perms in ({}, {"push": False}, {"pull": True}):
            with self.subTest(perms=perms):
                gh = FakeGitHub()
                gh.perms = {REPO: perms}
                i = self.ident()
                ok, err = attempt(i.check, gh, {REPO})
                self.assertFalse(ok)
                self.assertIsInstance(err, M.IdentityError)
                self.assertFalse(i.fresh())

    def test_admin_or_all_repo_scope_warns(self):
        for scopes, perms, admin, all_repo in ((["repo"], {"push": True}, False, True),
                                               (None, {"push": True}, False, True),
                                               (["public_repo", "admin:org"], {"push": True}, True, False),
                                               (["public_repo"], {"push": True, "admin": True}, True, False)):
            with self.subTest(scopes=scopes, perms=perms):
                gh = FakeGitHub()
                gh.user = {"login": LOGIN, "id": UID_GH, "scopes": scopes}
                gh.perms = {REPO: perms}
                rec = self.ident().check(gh, {REPO})
                self.assertEqual((rec["admin"], rec["all_repo"]), (admin, all_repo))
                self.assertEqual(len(rec["warnings"]), int(admin) + int(all_repo))
                self.assertTrue(all(wn.startswith("WARNING") for wn in rec["warnings"]))

    def test_the_check_is_stale_after_10_minutes_or_a_reboot_and_nothing_is_sent(self):
        w = self.w
        key = w.build()
        w.clock.t += M.IDENTITY_FRESH_SECONDS
        self.assertFalse(w.identity.fresh())
        self.assertIn("merging: waiting-dep (merge identity unavailable)", w.identity.status_lines())
        out = w.sender().dispatch(key)
        self.assertEqual((out["state"], out["sent"]), ("waiting-dep", False))
        self.assertEqual(w.gh.requests, [], "no send without an identity check in the last 10 min")
        w.identity.check(w.gh, {REPO})
        w.identity.boot_id = "another-boot"
        self.assertFalse(w.identity.fresh(), "a check from another boot is not fresh")

    def test_a_failed_recheck_clears_the_last_good_one(self):
        w = self.w
        key = w.build()
        w.gh.user = dict(w.gh.user, id=UID_GH + 1)
        attempt(w.identity.check, w.gh, {REPO})
        self.assertEqual(w.sender().dispatch(key)["sent"], False)
        self.assertEqual(w.gh.requests, [])


# ---------------------------------------------------------------- e9: the CHK-CAS canary

class CanaryTests(Base):

    def canary(self, w):
        w.build()
        return M.Canary(w.gh, w.identity, w.canary, w.port, w.lock(), w.kill)

    def test_the_canary_passes_on_the_scratch_ref_and_e9_reads_its_record(self):
        w = self.w
        out = self.canary(w).run(REPO, "main")
        self.assertEqual(out["state"], "passed", out)
        rec = out["record"]
        self.assertEqual(sorted(rec["cases"]), ["create", "fast-forward", "no-workflow", "stale-before",
                                                "typed-non-fast-forward"])
        ups = w.gh.updates()
        self.assertTrue(ups and all(u["ref"] == M.CANARY_REF and u["force"] is False for u in ups),
                        "only refs/ahc/canary, never a branch, never force")
        self.assertEqual(w.gh.refs[MAIN], oid("B"), "the default branch is untouched")
        facts = w.canary.local_facts(REPO, w.identity)
        self.assertTrue(facts["chk_cas"])
        w.clock.t += 3600
        self.assertEqual(w.c.clock.canary_age(facts["canary"]), 3600.0, "Clock.canary_age reads the record")
        self.assertNotIn("e9", w.c.elig(w.item(), w.obs(chk_cas=True, canary_age=w.c.clock.canary_age(
            facts["canary"]))))
        w.clock.t += 86400
        self.assertIn("e9", w.c.elig(w.item(), w.obs(chk_cas=True, canary_age=w.c.clock.canary_age(
            facts["canary"]))), "a canary older than 24 h fails e9")

    def test_a_failing_canary_turns_merging_off_and_escalates_once(self):
        for fault in ("non-ff accepted", "workflow ran"):
            with self.subTest(fault=fault):
                w = self.world()
                c = self.canary(w)
                if fault == "non-ff accepted":
                    w.gh.accept_non_ff = True
                else:
                    w.gh.runs_on_canary = True
                out = c.run(REPO, "main")
                self.assertEqual(out["state"], "failed")
                self.assertTrue(w.c.merging_off(REPO))
                self.assertFalse(w.canary.chk_cas(REPO, w.identity))
                c.run(REPO, "main")
                self.assertEqual(len(c.escalations), 1, "escalated once until a pass")

    def test_the_canary_runs_only_under_a_fresh_identity_and_an_off_switch(self):
        w = self.w
        c = self.canary(w)
        w.kill.write(True, KILL + 1)
        self.assertEqual(c.run(REPO, "main")["state"], "deferred")
        w.kill.write(False, KILL)
        w.clock.t += M.IDENTITY_FRESH_SECONDS
        self.assertEqual(c.run(REPO, "main")["state"], "waiting-dep")
        self.assertEqual(w.gh.updates(), [])


# ---------------------------------------------------------------- the transport (argv and classification only)

class TransportTests(unittest.TestCase):
    """GhTransport is never run against GitHub: an injected runner records argv and returns canned output."""

    def gh(self, answers):
        calls = []

        def run(argv, stdin, timeout):
            calls.append((argv, stdin))
            return answers.pop(0)
        return M.GhTransport("/usr/local/bin/gh", "/var/lib/ahcmerge", run=run), calls

    def test_the_send_is_one_graphql_update_refs_with_force_false(self):
        t, calls = self.gh([(0, json.dumps({"node_id": "R_x"}), "", False),
                            (0, json.dumps({"data": {"updateRefs": {"clientMutationId": None}}}), "", False)])
        t.prepare(REPO)
        res = t.update_refs(REPO, MAIN, oid("B"), oid("H"), False, 30)
        self.assertEqual(res["outcome"], M.OK)
        argv, body = calls[-1]
        self.assertEqual(argv[:3], ["/usr/local/bin/gh", "api", "graphql"])
        self.assertEqual(argv[-2:], ["--input", "-"])
        upd = json.loads(body)["variables"]["u"]
        self.assertEqual(upd, [{"name": MAIN, "beforeOid": oid("B"), "afterOid": oid("H"), "force": False}])
        ok, _ = attempt(t.update_refs, REPO, MAIN, oid("B"), oid("H"), True, 30)
        self.assertFalse(ok, "force true is refused before anything is sent")
        self.assertEqual(len(calls), 2)

    def test_an_unprepared_send_sends_nothing_and_claims_no_absence(self):
        t, calls = self.gh([])
        res = t.update_refs(REPO, MAIN, oid("B"), oid("H"), False, 30)
        self.assertEqual((res["outcome"], calls), (M.UNTYPED, []))

    def test_classification(self):
        ok = json.dumps({"data": {"updateRefs": {}}})
        err = lambda m: json.dumps({"errors": [{"message": m}]})            # noqa: E731
        cases = (((0, ok, "", False), M.OK, None),
                 ((0, err("rejecting non-fast forward update"), "", False), M.P1, "non-fast-forward"),
                 ((0, err("cannot lock ref 'refs/heads/main'"), "", False), M.P1, "ref-lock"),
                 ((0, err("protected branch hook declined"), "", False), M.P1, "protected-ref"),
                 ((0, err("Something went wrong while executing your query."), "", False), M.UNTYPED, None),
                 ((1, "", "dial tcp: lookup api.github.com: no such host", False), M.P3, "dns"),
                 ((1, "", "dial tcp 140.82.1.1:443: connect: connection refused", False), M.P3, "tcp"),
                 ((1, "", "tls: handshake failure", False), M.P3, "tls"),
                 ((1, "", "read tcp 10.0.0.2:5->140.82.1.1:443: read: connection reset by peer", False),
                  M.NO_RESPONSE, None),
                 ((1, "", "unexpected EOF", False), M.NO_RESPONSE, None),
                 ((None, "", "", True), M.NO_RESPONSE, None),
                 ((1, "", "HTTP 502", False), M.UNTYPED, None),
                 ((0, "not json", "", False), M.UNTYPED, None),
                 ((0, json.dumps({"data": {}}), "", False), M.UNTYPED, None))
        for (rc, out, errtext, timed_out), want, kind in cases:
            with self.subTest(out=out[:40], err=errtext[:40]):
                res = M.classify_graphql(rc, out, errtext, timed_out)
                self.assertEqual((res["outcome"], res["kind"]), (want, kind))

    def test_whoami_reads_the_scope_header_and_never_a_token(self):
        t, calls = self.gh([(0, "HTTP/2.0 200 OK\nX-Oauth-Scopes: repo, workflow\n\n" + json.dumps(
            {"login": LOGIN, "id": UID_GH}), "", False)])
        self.assertEqual(t.whoami(), {"login": LOGIN, "id": UID_GH, "scopes": ["repo", "workflow"]})
        self.assertEqual(calls[0][0], ["/usr/local/bin/gh", "api", "--include", "user"])
        self.assertNotIn("GH_TOKEN", t.env)
        self.assertNotIn("GITHUB_TOKEN", t.env)

    def test_a_full_activity_page_is_incomplete(self):
        page = [{"id": n, "before": oid("B"), "after": oid("H"), "activity_type": "push"} for n in range(100)]
        t, _ = self.gh([(0, json.dumps(page), "", False), (0, json.dumps(page[:3]), "", False)])
        self.assertFalse(t.read_activity(REPO, "main")["complete"])
        self.assertTrue(t.read_activity(REPO, "main")["complete"])

    def test_gh_must_be_absolute(self):
        ok, _ = attempt(M.GhTransport, "gh", "/var/lib/ahcmerge")
        self.assertFalse(ok)


import tests.test_ahc_guard as TG  # noqa: E402


class DaemonGuardTests(TG._GuardFixture):
    """AC-13: the daemon's guard keeps refusing the sender's GraphQL call; only ahc-merge (another OS user) sends."""

    def test_the_daemon_guard_refuses_the_update_refs_argv(self):
        t = M.GhTransport(self.policy.exe["gh"], str(self.root))
        self.refuse_argv("gh", t.update_refs_argv(), name="gh")


# ---------------------------------------------------------------- static rules for the new module

class StaticTests(unittest.TestCase):
    SRC = (HOOKS / "ahc_merge.py").read_text(encoding="utf-8")

    def test_no_wall_clock_read(self):
        import ast
        bad = []
        for node in ast.walk(ast.parse(self.SRC)):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "time" \
                    and node.attr in ("time", "time_ns"):
                bad.append(node.lineno)
        self.assertEqual(bad, [], "AC-10: ahc_merge reads time only through the injected clocks")

    def test_no_stamp_waiver_or_merge_gate(self):
        import tests.test_ahc_core as TCORE
        self.assertEqual(TCORE.CoreTests.stamp_violations(None, {"ahc_merge": self.SRC})
                         if hasattr(TCORE, "CoreTests") else _stamp_violations(TCORE, self.SRC), [])

    def test_no_other_send_path(self):
        """NEG-19 / NEG-17: the module names no push, merge, force or update-branch send."""
        import ast
        tree = ast.parse(self.SRC)
        docs = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
                for bad in ("update-branch", "--force", "git push", "/merge", "mergePullRequest"):
                    self.assertNotIn(bad, node.value, "line %d" % node.lineno)
            if isinstance(node, ast.keyword) and node.arg == "force":
                self.assertTrue(isinstance(node.value, ast.Constant) and node.value.value is False,
                                "force is only ever the literal False (line %d)" % node.value.lineno)

    def test_no_path_write_outside_ahc_fs(self):
        import tests.test_ahc_fs as TFS
        self.assertEqual(TFS.path_writes(self.SRC, "ahc_merge"), [])

    def test_every_durable_write_is_listed_and_every_seam_has_both_calls(self):
        found = ahc_crash.inventory(self.SRC, "ahc_merge")
        problems = []
        for key, n in sorted(found.items()):
            if key not in M.MERGE_INVENTORY:
                problems.append("unlisted %s" % "/".join(key))
            elif M.MERGE_INVENTORY[key][0] != n:
                problems.append("count %s" % "/".join(key))
        for key, (_n, disposition) in M.MERGE_INVENTORY.items():
            kind, _, detail = disposition.partition(":")
            if key not in found:
                problems.append("stale %s" % "/".join(key))
            if kind == "seam" and detail not in M.MERGE_SEAMS or kind not in ("seam", "exempt") or not detail:
                problems.append("disposition %s" % "/".join(key))
        self.assertEqual(problems, [])
        self.assertEqual(ahc_crash.seam_calls(self.SRC),
                         {(s, wh): 1 for s in M.MERGE_SEAMS for wh in ("before", "after")})
        self.assertFalse(set(M.MERGE_SEAMS) & set(ahc_crash.SEAMS), "registration is a proposed diff")


def _stamp_violations(module, src):
    for obj in vars(module).values():
        if isinstance(obj, type) and hasattr(obj, "stamp_violations"):
            return obj.stamp_violations(None, {"ahc_merge": src})
    raise AssertionError("tests.test_ahc_core has no stamp_violations")


# ---------------------------------------------------------------- AC-18: the sender's crash seams

class CrashSeamTests(Base):
    """Each seam of the sender, crashed in a child process, then a restart over the same files."""

    def test_canary_record_seam(self):
        for when, recorded in (("before", False), ("after", True)):
            with self.subTest(when=when):
                w = self.world(files=True)
                key = w.build()
                os.unlink(str(w.canary._path(REPO)))
                died = run_child(w.root, "canary", key, seam="merge.canary_record:%s@1" % when)
                self.assertEqual(died.returncode, ahc_crash.CRASH_EXIT, died.stderr[-800:])
                self.assertEqual(w.canary.chk_cas(REPO, w.identity), recorded)
                again = run_child(w.root, "dispatch", key)
                self.assertEqual(again.returncode, 0, again.stderr[-800:])
                sent = [u for u in FakeGitHub(w.gh.path).load().updates() if u["ref"] == MAIN]
                self.assertEqual(len(sent), 1 if recorded else 0, "no CHK-CAS record, no send")

    def test_kill_epoch_seam(self):
        for when, written in (("before", False), ("after", True)):
            with self.subTest(when=when):
                w = self.world(files=True)
                key = w.build()
                died = run_child(w.root, "kill", key, seam="merge.kill_epoch:%s@1" % when)
                self.assertEqual(died.returncode, ahc_crash.CRASH_EXIT, died.stderr[-800:])
                self.assertEqual(w.kill.read()["on"], written)
                again = run_child(w.root, "dispatch", key)
                self.assertEqual(again.returncode, 0, again.stderr[-800:])
                sent = FakeGitHub(w.gh.path).load().updates()
                self.assertEqual(len(sent), 0 if written else 1,
                                 "a written epoch stops every later send; an unwritten one was never returned as "
                                 "a completed kill")


if __name__ == "__main__":
    unittest.main()
