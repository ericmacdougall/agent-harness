"""AC-18 crash-point coverage (goodqa#16049 spec ahc-m1-v2g7 AC-18, harvest idea 2) over the ledger code that exists
now: ahc_contracts and ahc_runner. Dispatch-side seams (C5) join when C5 is unheld.

CrashPointTests: for each scenario, a counting pass (no crash) records every seam occurrence and the durable state
digest at that instant. Then, for every crash point (seam, before|after, occurrence), a child process is re-executed
with that one point armed; it must die AT that point (exit code and marker; an unreached point fails). The state it
left must equal the counting pass's digest for that exact point, the ledger invariants must hold, and a restarted
child over the same files (clock advanced) must finish the scenario to the same final state as an uncrashed run.

Claim: process death at each point (contract-level and runner-ledger-level restart; contracts has no daemon caller
yet). Not power loss: SQLite synchronous=FULL and the authority log's fsync are relied on for that.

KNOWN_FAILURES lists crash points whose restart is known to diverge; they are asserted to still diverge (a stale
entry fails). AHC_CRASH_STRICT=1 turns every known failure into a test failure."""
import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_contracts as C  # noqa: E402
import ahc_core as core  # noqa: E402
import ahc_crash  # noqa: E402
import ahc_runner as runner  # noqa: E402

CHILD = "tests.test_ahc_crash.ChildScenario.test_run"
ENV_SCENARIO, ENV_DIR, ENV_PHASE = "AHC_CRASH_SCENARIO", "AHC_CRASH_DIR", "AHC_CRASH_PHASE"
STRICT = os.environ.get("AHC_CRASH_STRICT") == "1"
T0 = 1_800_000_000.0
RESUME_ADVANCE = 300.0
H1, H2, BASE, POLICY, KILL = "a" * 40, "b" * 40, "c" * 40, "policy-r1", 7
CHILD_TIMEOUT = 120

# Crash points whose restart is known to diverge from an uncrashed run, each with its reason. Found by this test.
KNOWN_FAILURES = {}


# ---------------------------------------------------------------- state digest (shared by child and parent)

_EPOCH = re.compile(r"\b1[0-9]{9}(?:\.[0-9]+)?\b|\b1[0-9]{18}\b")


_PHASE = re.compile(r'"phase": "[a-z]+"')


def live_db(root):
    """The live ledger file, where the production path (core.Paths) puts it."""
    return core.Paths(Path(root)).root / "ledger.sqlite3"


def committed_events(root):
    """The event rows durably committed at this instant: from the live ledger, or, when no live ledger exists (a
    crash in the middle of a restore), from the newest SQLite copy beside it (the verified backup or the moved-aside
    file), since that is where the committed rows then are."""
    live = live_db(root)
    candidates = [live] if live.exists() else sorted(
        (p for p in live.parent.glob("ledger.sqlite3*") if _is_sqlite(p)), key=lambda p: p.stat().st_mtime)[-1:]
    out = set()
    for path in candidates:
        db = sqlite3.connect("file:%s?mode=rw" % path, uri=True)
        try:
            names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            # append-only tables, rows compared whole (timestamps included): a restart that rebuilt them from
            # scratch on the advanced clock would not keep these exact rows
            if "events" in names:
                out |= {("events",) + tuple(r) for r in db.execute("SELECT item, event, at, data FROM events")}
            if "transitions" in names:
                out |= {("transitions",) + tuple(r) for r in db.execute(
                    "SELECT entity, id, from_state, to_state, event_id, actor, at, data FROM transitions")}
        finally:
            db.close()
    return out


def _db_dump(path):
    """A logical dump of a SQLite file's committed state, or a marker when it is absent or unreadable. Opened
    read-only by URI, so a missing file is never created."""
    if not path.exists():
        return "<absent>"
    try:
        db = sqlite3.connect("file:%s?mode=rw" % path, uri=True, timeout=5)
    except sqlite3.Error as error:
        return "<unopenable %s>" % type(error).__name__
    try:
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE "
                                           "'sqlite_%' ORDER BY name")]
        out = []
        for table in tables:
            rows = sorted(repr(tuple(r)) for r in db.execute('SELECT * FROM "%s"' % table))
            out.append("%s:%s" % (table, rows))
        return "\n".join(out)
    except sqlite3.Error as error:
        return "<unreadable %s>" % type(error).__name__
    finally:
        db.close()


def _is_sqlite(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def state(root, *, normalize_times=False, skip_backups=False):
    """{name: content digest} for the scenario directory: the live ledger as a logical dump, every other SQLite
    file (backups, moved-aside files) as a dump too, and every other file by bytes. Volatile digits in names
    (time_ns suffixes) are normalized. normalize_times also folds epoch timestamps inside contents, for comparing
    a resumed run (clock advanced) with an uncrashed one; skip_backups drops *.bak and moved-aside files."""
    root = Path(root)
    out = OrderedDict()
    live = live_db(root)
    dump = _db_dump(live)
    if normalize_times:
        dump = _PHASE.sub('"phase": P', _EPOCH.sub("T", dump))
    out["ledger.sqlite3"] = dump
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = str(path.relative_to(root))
        if path.name.startswith("ledger.sqlite3") and not (".bak" in path.name or ".failed-" in path.name):
            continue                                       # the live database and its -wal/-shm: dumped above
        if rel in ("counts.txt", "child.log") or rel.endswith((".lock",)):
            continue
        if skip_backups and (".bak" in rel or ".failed-" in rel):
            continue
        name = re.sub(r"\d{9,}", "N", rel)
        staged = re.search(r"\.ledger\.sqlite3\.[0-9a-f]{16}\.tmp$", path.name)
        if staged:
            # a restore's staged copy (PR 258 v4): its name is random by design, and opening it with SQLite here
            # would create -wal/-shm files beside it that outlive its rename, so it is compared by bytes only
            name = re.sub(r"\.[0-9a-f]{16}\.tmp$", ".H.tmp", name)
        if not staged and _is_sqlite(path):
            content = _db_dump(path)
        else:
            content = path.read_bytes().decode("utf-8", "replace")
        if normalize_times:
            content = _EPOCH.sub("T", content)
        key = name
        n = 2
        while key in out:
            key, n = "%s#%d" % (name, n), n + 1
        out[key] = hashlib.sha256(content.encode()).hexdigest()
    out["ledger.sqlite3"] = hashlib.sha256(out["ledger.sqlite3"].encode()).hexdigest() if dump not in (
        "<absent>",) else "<absent>"
    return out


def digest(root, **kw):
    return hashlib.sha256(json.dumps(state(root, **kw), sort_keys=True).encode()).hexdigest()


def invariants(root):
    """The AC-18 ledger invariants over a scenario directory's durable state; returns the list of violations."""
    problems = []
    live = live_db(root)
    if not live.exists():
        return problems
    db = sqlite3.connect("file:%s?mode=rw" % live, uri=True)
    try:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "operations" not in tables:
            return problems
        for key, count in db.execute("SELECT key, dispatch_count FROM operations"):
            sent = db.execute("SELECT COUNT(*) FROM transitions WHERE entity='operation' AND id=? AND "
                              "to_state='dispatched'", (key,)).fetchone()[0]
            if sent != count:
                problems.append("op %s: dispatch_count %d but %d dispatch transitions" % (key, count, sent))
            if count > 1:
                problems.append("op %s dispatched %d times" % (key, count))
        for key, state_, grant in db.execute("SELECT key, state, grant_id FROM operations"):
            if grant and not db.execute("SELECT 1 FROM grants WHERE id=?", (grant,)).fetchone():
                problems.append("op %s names a lost grant %s" % (key, grant))
            if state_ in ("dispatched", "outcome-unknown", "fenced", "held") and grant:
                g = db.execute("SELECT state FROM grants WHERE id=?", (grant,)).fetchone()
                if g is None or g[0] != "reserved":
                    problems.append("unsettled op %s has grant %s in %s (not reserved)" % (key, grant, g))
        for gid, held, st in db.execute("SELECT id, cap_held, state FROM grants"):
            if st in ("validated", "active", "reserved", "consumed") and held != 1:
                problems.append("grant %s in %s released its CAP1 slot" % (gid, st))
    finally:
        db.close()
    log = Path(root) / "authority.jsonl"
    if log.exists():
        rows = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        ids = [r["event_id"] for r in rows]
        if len(ids) != len(set(ids)):
            problems.append("authority log repeats an event id")
        if [r["seq"] for r in rows] != list(range(1, len(rows) + 1)):
            problems.append("authority log sequence is not contiguous")
    return problems


def cap_used(root):
    live = live_db(root)
    if not live.exists():
        return 0
    db = sqlite3.connect("file:%s?mode=rw" % live, uri=True)
    try:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='grants'").fetchone():
            return 0
        return db.execute("SELECT COUNT(*) FROM grants WHERE cap_held=1").fetchone()[0]
    finally:
        db.close()


# ---------------------------------------------------------------- the child scenarios

class _Clock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t


def _done(db, event_id):
    return db.execute("SELECT 1 FROM transitions WHERE event_id=?", (event_id,)).fetchone() is not None


def scenario_contracts(root, clock):
    """Two items through G1-G3, E1, E2 and E3; the second is left dispatched and reconciled (E5 restart, then E3 by
    readback), as a restarted ahc-core would. Every step is keyed by its event id, so a rerun resumes."""
    paths = core.Paths(root)
    led = runner.Ledger(paths)
    c = C.Contracts(led.db, C.AuthorityLog(Path(root) / "authority.jsonl"), now=clock)
    db = led.db
    for pr, head in ((5, H1), (6, H2)):
        scope = {"repo": "o/r", "pr": pr, "head": head, "base": BASE}
        params = {"repo": "o/r", "pr": pr, "head": head, "base": BASE, "policy_revision": POLICY,
                  "method": "fast-forward", "default_branch": "main"}

        def grant():
            return c._row("grants", "pr", pr)

        def op():
            r = db.execute("SELECT key FROM operations WHERE pr=?", (pr,)).fetchone()
            return c._row("operations", "key", r[0]) if r else None

        if not _done(db, "pr%d-g1" % pr):
            c.issue_grant("merge", "queue:fixture#6165f60532c0", "ahc-policy", scope, POLICY,
                          event_id="pr%d-g1" % pr, kill_epoch=KILL)
        if not _done(db, "pr%d-g2" % pr):
            g = grant()
            c.activate_grant(g["id"], expected_version=g["version"], event_id="pr%d-g2" % pr)
        if not _done(db, "pr%d-e1" % pr):
            c.intend(params, lease_ok=True, event_id="pr%d-e1" % pr)
        if not _done(db, "pr%d-g3" % pr):
            g = grant()
            c.reserve_grant(g["id"], op()["key"], expected_version=g["version"], event_id="pr%d-g3" % pr,
                            mirror_read_back=True, kill_epoch=KILL)
        if not _done(db, "pr%d-e2" % pr):
            o = op()
            obs = {"at": clock.t, "kill_switch": False, "kill_epoch": KILL, "pr_state": "OPEN", "pr_head": head,
                   "draft": False, "tip": BASE, "compare": "ahead", "checks_green": True}
            c.dispatch(o["key"], obs, expected_version=o["version"], event_id="pr%d-e2" % pr, lease_ok=True,
                       mirror_read_back=True)
        if pr == 6 and not _done(db, "pr6-e5"):
            o = op()
            c.unknown(o["key"], expected_version=o["version"], event_id="pr6-e5", restart=True)
        if not _done(db, "pr%d-e3" % pr):
            o = op()
            c.confirm(o["key"], {"at": clock.t, "tip": head, "pr_merged": True}, expected_version=o["version"],
                      event_id="pr%d-e3" % pr)
    led.close()


def scenario_files(root, clock):
    """The runner's durable file writes and a ledger transaction, each step idempotent the way the runner's own
    retry would be (state read back first)."""
    paths = core.Paths(root)
    led = runner.Ledger(paths)
    if led.db.execute("SELECT 1 FROM meta WHERE k='fence'").fetchone() is None:
        with led.tx():
            led.next_token()
            led.event("crash-item", "probe", clock.t)
    line = json.dumps({"event": "probe", "at": clock.t}, sort_keys=True)
    mirror = paths.items / "crash-item.jsonl"
    if not (mirror.exists() and '"event": "probe"' in mirror.read_text()):
        runner._mirror(paths, "crash-item", "probe", clock.t, {})
    runner._write_private(paths.root, paths.items / "status.json", '{"ok": true}\n')
    paths.inbox.mkdir(parents=True, exist_ok=True, mode=0o700)
    runner._write_inbox(paths.inbox, "owner1", "notice-1.md", "a notice\n")
    runner.stage_packet(paths, io.BytesIO(b"packet one\n"))
    # a queue entry is quarantined (the ingest path); a restart finds it still queued or already moved
    q = paths.queue / "ahc-q1.json"
    rejected = paths.root / "rejected" / "ahc-q1.json"
    if not rejected.exists():
        paths.queue.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not q.exists():
            q.write_text("{}\n")
        runner._quarantine(paths, q, "not a valid request")
    # a review attempt directory that failed the post-exit report checks is quarantined (PR 258 v3)
    attempt = paths.reports / "crash-item-a1"
    if not (paths.root / "rejected" / ("report-" + attempt.name)).exists():
        attempt.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(str(paths.reports), 0o700)
        (attempt / "extra.md").write_text("VERDICT: PASS\n")
        runner._quarantine_report_dir(paths, attempt, "the report directory holds entries other than report.md")
    old, sha = runner.stage_packet(paths, io.BytesIO(b"packet two, orphaned\n"))
    if old.exists():
        os.utime(str(old), (clock.t - 10 * runner.PACKET_RETENTION_SECONDS,) * 2)
    fake = types.SimpleNamespace(paths=paths, led=led, now=lambda: clock.t)
    runner.Worker.prune_packets(fake)
    del line, sha
    led.close()


def _downgraded_ledger(root):
    """A v4 ledger stepped back to schema 3 (so opening it runs the v4 step under backup), made once: the downgrade
    and its marker row commit together, so a restart reads whether it happened from the ledger itself. A pending
    restore intent also means it happened: the restart's Ledger open completes that restore first."""
    if Path(str(live_db(root)) + ".restore-intent").exists():
        return
    if live_db(root).exists():
        db = sqlite3.connect(str(live_db(root)))
        try:
            done = db.execute("SELECT 1 FROM sqlite_master WHERE name='events'").fetchone() and db.execute(
                "SELECT 1 FROM events WHERE event='before-migration'").fetchone()
        finally:
            db.close()
        if done:
            return
    paths = core.Paths(root)
    led = runner.Ledger(paths)
    with led.tx():
        # the row names the phase that wrote it, so a ledger rebuilt by a restart can never pass for the original
        led.event("crash-item", "before-migration", T0, phase=os.environ.get(ENV_PHASE, "first"))
        led.db.execute("UPDATE meta SET v='3' WHERE k='schema_version'")
    led.close()


def scenario_migrate(root, clock):
    _downgraded_ledger(root)
    runner.Ledger(core.Paths(root)).close()


def scenario_restore(root, clock):
    """A migration that fails: the verified backup is restored and the failed files moved aside."""
    _downgraded_ledger(root)

    def boom(db):
        raise RuntimeError("injected migration failure")
    runner.MIGRATIONS[4] = list(runner.MIGRATIONS[4]) + [boom]
    try:
        runner.Ledger(core.Paths(root)).close()
    except runner.SchemaError:
        pass


SCENARIOS = {"contracts": scenario_contracts, "files": scenario_files, "migrate": scenario_migrate,
             "restore": scenario_restore}


class ChildScenario(unittest.TestCase):
    """Runs one scenario in a re-executed child (skipped unless the parent set the environment)."""

    def test_run(self):
        name = os.environ.get(ENV_SCENARIO)
        if not name:
            self.skipTest("child entry point; run by CrashPointTests")
        root = Path(os.environ[ENV_DIR])
        clock = _Clock(T0 + (RESUME_ADVANCE if os.environ.get(ENV_PHASE) == "resume" else 0.0))
        counter = iter(range(10 ** 9))
        time.time = lambda: clock.t + next(counter) * 1e-3       # deterministic wall clock for the runner
        time.time_ns = lambda: int(time.time() * 1e9)
        ahc_crash.observe(lambda point, n: digest(root))
        SCENARIOS[name](root, clock)


# ---------------------------------------------------------------- the parent


def run_child(root, scenario, *, seam=None, count=False, phase="first", under_test=True, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AHC_CRASH_")}
    env.update({ENV_SCENARIO: scenario, ENV_DIR: str(root), ENV_PHASE: phase, "PYTHONDONTWRITEBYTECODE": "1"})
    if under_test:
        env[ahc_crash.ENV_UNDER_TEST] = "1"
    if seam:
        env[ahc_crash.ENV_SEAM] = seam
    if count:
        env[ahc_crash.ENV_COUNT] = str(Path(root) / "counts.txt")
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-B", "-m", "unittest", CHILD], cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=CHILD_TIMEOUT)


def counting_pass(root, scenario):
    done = run_child(root, scenario, count=True)
    if done.returncode != 0:
        raise AssertionError("counting pass failed for %s:\n%s" % (scenario, done.stderr[-3000:]))
    points = OrderedDict()
    for line in (Path(root) / "counts.txt").read_text().splitlines():
        point, dig = line.split("\t")
        points[point] = dig
    return points


class CrashPointTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def reference(self, scenario):
        root = self.base / ("ref-" + scenario)
        root.mkdir(mode=0o700)
        points = counting_pass(root, scenario)
        final = state(root, normalize_times=True, skip_backups=True)
        return points, final, root

    def test_every_seam_is_reached_and_every_crash_point_restarts_cleanly(self):
        reached, results, crash_points = set(), [], 0
        for scenario in SCENARIOS:
            points, final, ref_root = self.reference(scenario)
            self.assertEqual(invariants(ref_root), [], "uncrashed %s" % scenario)
            for point, expected in points.items():
                crash_points += 1
                name_when, _, k = point.rpartition("@")
                reached.add(name_when)
                root = self.base / ("%s-%d" % (scenario, crash_points))
                root.mkdir(mode=0o700)
                with self.subTest(scenario=scenario, point=point):
                    died = run_child(root, scenario, seam=point)
                    self.assertEqual(died.returncode, ahc_crash.CRASH_EXIT,
                                     "the child did not die at %s (unreached?):\n%s" % (point, died.stderr[-2000:]))
                    self.assertIn("%s %s" % (ahc_crash.MARKER, point), died.stderr)
                    self.assertEqual(digest(root), expected, "the state at the crash is exactly the durable state "
                                                             "the counting pass saw at %s" % point)
                    self.assertEqual(invariants(root), [], "invariants at the crash, %s" % point)
                    cap_at_crash = cap_used(root)
                    kept = committed_events(root)
                    resumed = run_child(root, scenario, phase="resume")
                    outcome = "ok"
                    if resumed.returncode != 0:
                        outcome = "restart failed: " + resumed.stderr.strip().splitlines()[-1][:200]
                    elif not kept <= committed_events(root):
                        outcome = "committed rows lost across the restart: %d of %d missing from the live ledger" % (
                            len(kept - committed_events(root)), len(kept))
                    elif state(root, normalize_times=True, skip_backups=True) != final:
                        outcome = "restart diverged from the uncrashed run"
                    elif invariants(root):
                        outcome = "invariants after restart: %s" % invariants(root)
                    elif cap_used(root) < cap_at_crash:
                        outcome = "CAP1 count went down across the restart"
                    results.append((scenario, point, outcome))
                    key = "%s/%s" % (scenario, point)
                    if key in KNOWN_FAILURES and not STRICT:
                        self.assertNotEqual(outcome, "ok", "stale known failure %s: it passes now" % key)
                    else:
                        self.assertEqual(outcome, "ok", "%s (%s)" % (key, KNOWN_FAILURES.get(key, "")))
        every = {"%s:%s" % (s, w) for s in ahc_crash.SEAMS for w in ("before", "after")}
        self.assertEqual(sorted(every - reached), [], "seams no scenario reaches")
        report = Path(os.environ.get("AHC_CRASH_REPORT", "")) if os.environ.get("AHC_CRASH_REPORT") else None
        if report:
            report.write_text(json.dumps({"seams": len(ahc_crash.SEAMS), "crash_points": crash_points,
                                          "results": results}, indent=1))
        self.assertGreaterEqual(crash_points, 2 * len(ahc_crash.SEAMS))

    def test_the_seam_is_not_honoured_outside_unittest(self):
        """The env var alone never arms a seam: a plain (non-unittest) process runs the scenario to the end."""
        root = self.base / "plain"
        root.mkdir(mode=0o700)
        env = {k: v for k, v in os.environ.items() if not k.startswith("AHC_CRASH_")}
        env.update({ahc_crash.ENV_SEAM: "contracts.commit:before@1", ahc_crash.ENV_UNDER_TEST: "1"})
        code = ("import sys; sys.path.insert(0, %r); import ahc_crash, sys; "
                "assert 'unittest' not in sys.modules; ahc_crash.crash_before('contracts.commit'); print('ran')"
                % str(HOOKS))
        done = subprocess.run([sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True,
                              timeout=CHILD_TIMEOUT)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "ran"), done.stderr)

    def test_under_unittest_without_the_test_flag_the_seam_is_not_honoured(self):
        root = self.base / "noflag"
        root.mkdir(mode=0o700)
        done = run_child(root, "contracts", seam="contracts.commit:before@1", under_test=False)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])

    def test_production_imports_do_not_load_unittest(self):
        code = ("import sys; sys.path.insert(0, %r); import ahc_runner, ahc_contracts, ahc_core, ahc_crash; "
                "print('unittest' in sys.modules)" % str(HOOKS))
        done = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.stdout.strip(), "False", done.stderr)


class RestoreIntentTests(unittest.TestCase):
    """The interrupted-restore record (found by the crash matrix) fails closed when it cannot be trusted."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = core.Paths(Path(tmp.name))
        self.paths.ensure()
        self.intent = self.paths.root / "ledger.sqlite3.restore-intent"

    def assert_refused(self, migrate=True):
        with self.assertRaises(runner.SchemaError):
            runner.Ledger(self.paths, migrate=migrate)
        self.assertFalse((self.paths.root / "ledger.sqlite3").exists(), "no empty ledger is created")

    def test_an_unreadable_record_refuses_to_open(self):
        self.intent.write_text("not json\n")
        self.assert_refused()

    def test_a_record_naming_a_path_outside_the_ledger_directory_refuses(self):
        outside = self.paths.home / "elsewhere.bak"
        outside.write_bytes(b"SQLite format 3\x00")
        self.intent.write_text(json.dumps({"backup": "../../elsewhere.bak", "suffix": ".failed-1"}))
        self.assert_refused()

    def test_a_record_naming_a_missing_backup_refuses(self):
        self.intent.write_text(json.dumps({"backup": "ledger.sqlite3.pre-v4.1.bak", "suffix": ".failed-1"}))
        self.assert_refused()

    def test_a_non_migrating_process_never_completes_a_restore(self):
        self.intent.write_text(json.dumps({"backup": "x.bak", "suffix": ".failed-1"}))
        self.assert_refused(migrate=False)

    def test_a_valid_record_completes_the_restore_and_keeps_the_rows(self):
        led = runner.Ledger(self.paths)
        with led.tx():
            led.event("i1", "kept", T0)
        copy = led.backup("pre-v4")
        led.close()
        live = self.paths.root / "ledger.sqlite3"
        for extra in ("", "-wal", "-shm"):
            if os.path.lexists(str(live) + extra):
                os.rename(str(live) + extra, str(live) + ".failed-5" + extra)
        self.intent.write_text(json.dumps({"backup": copy.name, "suffix": ".failed-6"}))
        led = runner.Ledger(self.paths)
        try:
            self.assertEqual(led.db.execute("SELECT event FROM events").fetchall()[0][0], "kept")
        finally:
            led.close()
        self.assertFalse(self.intent.exists())


class InventoryTests(unittest.TestCase):
    MODULES = ("ahc_contracts", "ahc_runner")

    def found(self, overrides=None):
        out = {}
        for m in self.MODULES:
            src = (overrides or {}).get(m) or (HOOKS / (m + ".py")).read_text()
            out.update(ahc_crash.inventory(src, m))
        return out

    def test_every_durable_write_is_listed_or_exempted_with_a_reason(self):
        self.assertEqual(ahc_crash.check_inventory(self.found()), [])

    def test_every_registered_seam_has_both_calls_and_nothing_else_is_a_seam(self):
        calls = {}
        for m in self.MODULES:
            calls.update(ahc_crash.seam_calls((HOOKS / (m + ".py")).read_text()))
        expected = {(s, w): 1 for s in ahc_crash.SEAMS for w in ("before", "after")}
        self.assertEqual(calls, expected)

    def test_a_planted_unlisted_write_fails(self):
        src = (HOOKS / "ahc_runner.py").read_text()
        planted = src.replace("def _short(", "def _planted(path):\n    os.rename(path, path + '.x')\n\n\ndef _short(",
                              1)
        self.assertNotEqual(planted, src)
        problems = ahc_crash.check_inventory(self.found({"ahc_runner": planted}))
        self.assertTrue(any("unlisted durable write ahc_runner/_planted/os.rename" in p for p in problems), problems)

    def test_a_planted_autocommit_sql_write_outside_any_transaction_fails(self):
        src = (HOOKS / "ahc_contracts.py").read_text()
        planted = src.replace("    def merging_off(self, repo):",
                              "    def planted(self):\n        self.db.execute(\"DELETE FROM grants\")\n\n"
                              "    def merging_off(self, repo):", 1)
        problems = ahc_crash.check_inventory(self.found({"ahc_contracts": planted}))
        self.assertTrue(any("Contracts.planted/sql:DELETE" in p for p in problems), problems)

    def test_a_changed_count_and_a_stale_entry_fail(self):
        found = self.found()
        key = ("ahc_runner", "_write_private", "fs.write_file")
        changed = dict(found)
        changed[key] = 2
        self.assertIn("count changed", " ".join(ahc_crash.check_inventory(changed)))
        del found[key]
        self.assertIn("stale inventory entry", " ".join(ahc_crash.check_inventory(found)))

    def test_known_failures_each_name_a_reason(self):
        for key, reason in KNOWN_FAILURES.items():
            self.assertTrue(reason, key)


if __name__ == "__main__":
    unittest.main()
