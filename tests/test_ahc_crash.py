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
import logging
import random
import re
import shutil
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
import ahc_fs  # noqa: E402
import ahc_runner as runner  # noqa: E402

CHILD = "tests.test_ahc_crash.ChildScenario.test_run"
ENV_SCENARIO, ENV_DIR, ENV_PHASE = "AHC_CRASH_SCENARIO", "AHC_CRASH_DIR", "AHC_CRASH_PHASE"
ENV_CHUNK = "AHC_CRASH_CHUNK"      # test-only: the child's restore copy chunk (ahc_fs.COPY_CHUNK)
STRICT = os.environ.get("AHC_CRASH_STRICT") == "1"
T0 = 1_800_000_000.0
RESUME_ADVANCE = 300.0
# The child's clock per phase. Names minted from time_ns (backups, .failed- suffixes) must not repeat across the
# processes that share one directory: "prep" builds a resume scenario's starting files, "first" runs the scenario,
# "resume" restarts it after the crash.
PHASE_OFFSETS = {"prep": -600.0, "first": 0.0, "resume": RESUME_ADVANCE}
H1, H2, BASE, POLICY, KILL = "a" * 40, "b" * 40, "c" * 40, "policy-r1", 7
CHILD_TIMEOUT = 120

# Crash points whose restart is known to diverge from an uncrashed run, each with its reason. Found by this test.
KNOWN_FAILURES = {}


# ---------------------------------------------------------------- state digest (shared by child and parent)

_EPOCH = re.compile(r"\b1[0-9]{9}(?:\.[0-9]+)?\b|\b1[0-9]{18}\b")


_PHASE = re.compile(r'"phase": "[a-z]+"')
# a restore's staged copy of the ledger, named by ahc_fs.temp_name: `.ledger.sqlite3.<16 random hex>.tmp`
STAGED_TEMP = re.compile(r"^\.ledger\.sqlite3\.[0-9a-f]{16}\.tmp$")
STAGED_KEY = ".ledger.sqlite3.H.tmp"


def live_db(root):
    """The live ledger file, where the production path (core.Paths) puts it."""
    return core.Paths(Path(root)).root / "ledger.sqlite3"


def committed_events(root):
    """The event rows durably committed at this instant: from the live ledger, or, when no live ledger exists (a
    crash in the middle of a restore), from the newest SQLite copy beside it (the verified backup or the moved-aside
    file), since that is where the committed rows then are."""
    live = live_db(root)
    # newest first; a copy SQLite cannot read (a backup cut short, PR 258 v5) holds no committed rows to keep
    candidates = [live] if live.exists() else sorted(
        (p for p in live.parent.glob("ledger.sqlite3*") if _is_sqlite(p)), key=lambda p: p.stat().st_mtime)[::-1]
    for path in candidates:
        out = set()
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
        except sqlite3.DatabaseError:
            if path == live:
                raise
            continue
        finally:
            db.close()
        return out
    return set()


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
        staged = STAGED_TEMP.match(path.name)
        if staged:
            # a restore's staged copy (PR 258 v4): its name is random by design, and opening it with SQLite here
            # would create -wal/-shm files beside it that outlive its rename, so it is compared by bytes only. The
            # random part is replaced BEFORE the digit normalization below: a hex name holding a run of 9 or more
            # decimal characters (about 5% of names) was otherwise cut by it first and kept a random key (the PR
            # 258 v5 load flake at restore_copy:after@1 and restore_move:before@1).
            rel = str(path.parent.relative_to(root) / STAGED_KEY)
        name = re.sub(r"\d{9,}", "N", rel)
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
        if "work_items" in tables:       # T3 and T6: one audit row per applied WorkItem row, never a doubled move
            for iid, version in db.execute("SELECT id, version FROM work_items"):
                n = db.execute("SELECT COUNT(*) FROM transitions WHERE entity='work_item' AND id=?",
                               (iid,)).fetchone()[0]
                if n != version:
                    problems.append("work item %s at version %d has %d audit rows" % (iid, version, n))
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
    # one fake clock drives the wall and monotonic stamps; a fixed boot id stands for one boot across the restarts
    # (the restarted children are new processes on the same boot)
    c = C.Contracts(led.db, C.AuthorityLog(Path(root) / "authority.jsonl"), now=clock, mono=clock,
                    boot_id="crash-boot")
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
            obs = {"at": clock.t, "mono": clock.t, "boot": "crash-boot", "kill_switch": False, "kill_epoch": KILL, "pr_state": "OPEN", "pr_head": head,
                   "draft": False, "tip": BASE, "compare": "ahead", "checks_green": True}
            c.dispatch(o["key"], obs, expected_version=o["version"], event_id="pr%d-e2" % pr, lease_ok=True,
                       mirror_read_back=True)
        if pr == 6 and not _done(db, "pr6-e5"):
            o = op()
            c.unknown(o["key"], expected_version=o["version"], event_id="pr6-e5", restart=True)
        if not _done(db, "pr%d-e3" % pr):
            o = op()
            c.confirm(o["key"], c.stamp({"tip": head, "pr_merged": True}), expected_version=o["version"],
                      event_id="pr%d-e3" % pr)
    # Slice 1 (a): one WorkItem through W1, W21, W2, W5 and W6. Each move is retried with the expected version it had
    # BEFORE it first ran, so after a crash past its COMMIT the retry carries a stale version and must land as the
    # T6 no-op; before the COMMIT it applies. admit_item is itself idempotent (NEG-11).
    item = c.admit_item("o/r", 7, H1, BASE, POLICY, "1" * 64, "d" * 64, event_id="wi-w1")
    db.execute("UPDATE reviews SET state='passed' WHERE item=? AND state='required'", (item["id"],))
    os.environ["AHC_W21_SEND"] = "1"          # AC-7: W21 is applied only with the flag and the policy field on
    obs = {"id": "obs-wi", "at": clock.t, "mono": clock.t, "boot": "crash-boot", "repo": "o/r", "pr": 7, "pr_state": "OPEN", "pr_head": H1, "tip": BASE,
           "draft": False, "compare": "ahead", "b_r_ancestors": {BASE: True}, "attached_core": "1" * 64,
           "open_findings": 0, "paths": ["lib/x.py"], "foreign_closing_keyword": False,
           "policy": {"revision": POLICY, "readable": True, "allowlisted": True, "enabled": True,
                      "checks_green": True, "w21": True},
           "kill_switch": False, "chk_cas": True, "canary_age": 60}
    # W21 first: the one WorkItem row that writes the authority log (seam contracts.authority) before its COMMIT.
    # A crash between the two must leave one log line and, on the retry, one recorded update.
    behind = dict(obs, compare="behind")
    w21 = dict(obs, queue={item["id"]: behind}, mergeable=True)
    for version, row, extra in ((1, "W21", w21), (2, "W2", {}), (3, "W5", {"kill_switch": True}), (4, "W6", {})):
        c.wi_move(item["id"], row, expected_version=version, event_id="wi-%s" % row.lower(), actor="ahc-core",
                  obs=dict(obs, **extra))
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


PARTIAL_BYTES = 65536      # what a "partial" backup keeps: whole pages, less than the scenario ledger's ~136 KiB
TABLE_CHUNK = 65536        # restore copy chunk where the mid-copy point matters: the ~136 KiB copy takes 3 chunks


def _damage_backups(root, how):
    """Damage the backups beside the ledger as a failure or an operator might. "missing" removes them with their
    sidecars. "partial" cuts them to their first PARTIAL_BYTES; the size is fixed, so repeating it changes nothing.
    "present" leaves them."""
    ahc = core.Paths(root).root
    for backup in sorted(ahc.glob("ledger.sqlite3.pre-v*.bak")):
        if how == "missing":
            for extra in ("", "-wal", "-shm"):
                if os.path.lexists(str(backup) + extra):
                    os.unlink(str(backup) + extra)
        elif how == "partial" and backup.stat().st_size > PARTIAL_BYTES:
            os.truncate(str(backup), PARTIAL_BYTES)


def _remove_live(root):
    for extra in ("",) + runner.SQLITE_SIDECARS:
        path = str(live_db(root)) + extra
        if os.path.lexists(path):
            os.unlink(path)


def _plant_foreign(path):
    """A SQLite file at the live name that is neither the original nor the restored copy (what a stray open would
    leave): mode 0600, owned by this uid, like any ahc file."""
    tmp = Path(str(path) + ".plant")
    db = sqlite3.connect(str(tmp))
    db.execute("CREATE TABLE stray(x)")
    db.commit()
    db.close()
    os.chmod(str(tmp), 0o600)
    os.rename(str(tmp), str(path))


def _failing_restore(root, damage="present"):
    _downgraded_ledger(root)

    def boom(db):
        _damage_backups(root, damage)
        raise RuntimeError("injected migration failure")
    runner.MIGRATIONS[4] = list(runner.MIGRATIONS[4]) + [boom]
    try:
        runner.Ledger(core.Paths(root)).close()
    except runner.SchemaError:
        pass


def scenario_restore(root, clock):
    """A migration that fails: the verified backup is restored and the failed files moved aside."""
    _failing_restore(root)


def scenario_restore_lost_backup(root, clock):
    """PR 258 v5 F1: the backup vanishes during the failed migration, so the restore cannot copy it. It abandons,
    leaving the never-moved live ledger in place. The crash point runner.restore_intent:after@1 of this scenario is
    the receipt's exact sequence, and its restart must keep the original ledger."""
    _failing_restore(root, "missing")


def scenario_restore_partial_backup(root, clock):
    """The backup is cut short during the failed migration. Its copy fails the digest check, and the restore
    abandons the same way, so a partial copy is never published."""
    _failing_restore(root, "partial")


def scenario_reopen(root, clock):
    """ahc-core's start over a prepared interrupted restore (PREPARED): the resume, then the normal migration."""
    try:
        runner.Ledger(core.Paths(root)).close()
    except runner.SchemaError:
        pass


def _prepare_interrupted(backup, live):
    """The starting files of a resume scenario: a real crash right after the restore intent was written (scenario
    restore at runner.restore_intent:after@1, on the "prep" clock so no later name collides), then the backup and
    the live ledger set as named. The parent builds it once and copies it for the counting pass and every crash."""
    def prepare(root):
        died = run_child(root, "restore", seam="runner.restore_intent:after@1", phase="prep")
        if died.returncode != ahc_crash.CRASH_EXIT:
            raise AssertionError("prepare: the restore did not stop after its intent:\n%s" % died.stderr[-2000:])
        _damage_backups(root, backup)
        if live == "absent":
            _remove_live(root)
    return prepare


SCENARIOS = {"contracts": scenario_contracts, "files": scenario_files, "migrate": scenario_migrate,
             "restore": scenario_restore, "restore_lost_backup": scenario_restore_lost_backup,
             "restore_partial_backup": scenario_restore_partial_backup}
NAMED_SCENARIOS = {}    # AC-4: scenarios for the named points only (never run against every seam)
PREPARED = {}           # scenario -> prepare(root): its starting files, built by the parent
CHUNKS = {}             # scenario -> the restore copy chunk the child uses (ahc_fs.COPY_CHUNK otherwise)
# What every crash point of a restore scenario must converge to, checked on the uncrashed run (each restart must
# equal it): the original ledger kept or restored ("original"), or a refusal that keeps the intent ("refused").
FINAL = {"restore": "original", "restore_lost_backup": "original", "restore_partial_backup": "original"}
# PR 258 v5: crash anywhere in the RESUME. Each starts from an interrupted restore with the backup present, missing
# or partial and the live ledger present or absent; scenario_reopen resumes it, so its counting pass enumerates the
# resume's own crash points (copy, chunks, move, publish, done, abandon) and those of the migration after it.
for _backup in ("present", "missing", "partial"):
    for _live in ("present", "absent"):
        _name = "resume-%s-%s" % (_backup, "live" if _live == "present" else "nolive")
        SCENARIOS[_name] = scenario_reopen
        PREPARED[_name] = _prepare_interrupted(_backup, _live)
        CHUNKS[_name] = TABLE_CHUNK
        FINAL[_name] = "migrated" if _backup == "present" or _live == "present" else "refused"


def unset(kept):
    """Whether the crash came inside the scenario's own setup, before its before-migration row committed (in the
    rows committed at the crash, `kept`). Only then may the restart's own row (phase "resume") stand in for it."""
    return not any(row[0] == "events" and row[2] == "before-migration" for row in kept)


def final_problems(root, expect, crashed=False):
    """Why a run's final files are not what FINAL says, or []. crashed=True only when unset() says the original
    before-migration row never committed: then the restart writes that row itself (phase "resume")."""
    live, intent = live_db(root), Path(str(live_db(root)) + ".restore-intent")
    if expect == "refused":
        out = [] if intent.exists() else ["the restore intent was dropped"]
        return out + (["a live ledger was created"] if os.path.lexists(str(live)) else [])
    if intent.exists():
        return ["the restore intent is still there"]
    if not live.exists():
        return ["no live ledger"]
    db = sqlite3.connect("file:%s?mode=ro" % live, uri=True)
    try:
        # AC-11: a restored original carries the v5 fence at its prior version 3; a migrated ledger is 5, unfenced
        version = runner.ahc_migrate.read_version(db)
        rows = [r[0] for r in db.execute("SELECT data FROM events WHERE event='before-migration'")]
    finally:
        db.close()
    want = ((3, True), ("first", "resume") if crashed else ("first",)) if expect == "original" else \
        ((runner.SCHEMA_VERSION, False), ("prep",))
    out = [] if version == want[0] else ["schema_version %r, not %r" % (version, want[0])]
    if len(rows) != 1 or not any('"phase": "%s"' % phase in rows[0] for phase in want[1]):
        out.append("the original before-migration row (phase %s) is not the one in the ledger: %r" % (want[1], rows))
    return out


class ChildScenario(unittest.TestCase):
    """Runs one scenario in a re-executed child (skipped unless the parent set the environment)."""

    def test_run(self):
        name = os.environ.get(ENV_SCENARIO)
        if not name:
            self.skipTest("child entry point; run by CrashPointTests")
        root = Path(os.environ[ENV_DIR])
        clock = _Clock(T0 + PHASE_OFFSETS[os.environ.get(ENV_PHASE, "first")])
        chunk = os.environ.get(ENV_CHUNK) or CHUNKS.get(name)
        if chunk:
            ahc_fs.COPY_CHUNK = int(chunk)
        counter = iter(range(10 ** 9))
        time.time = lambda: clock.t + next(counter) * 1e-3       # deterministic wall clock for the runner
        time.time_ns = lambda: int(time.time() * 1e9)
        ahc_crash.observe(lambda point, n: digest(root))
        (SCENARIOS.get(name) or NAMED_SCENARIOS[name])(root, clock)


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
        self.templates = {}

    def seed(self, scenario, root):
        """An empty scenario directory, or a byte copy of the scenario's prepared starting files (built once)."""
        if scenario not in PREPARED:
            root.mkdir(mode=0o700)
            return
        if scenario not in self.templates:
            template = self.base / ("template-" + scenario)
            template.mkdir(mode=0o700)
            PREPARED[scenario](template)
            self.templates[scenario] = template
        shutil.copytree(str(self.templates[scenario]), str(root), symlinks=True)

    def reference(self, scenario):
        root = self.base / ("ref-" + scenario)
        self.seed(scenario, root)
        points = counting_pass(root, scenario)
        final = state(root, normalize_times=True, skip_backups=True)
        if scenario in FINAL:
            self.assertEqual(final_problems(root, FINAL[scenario]), [], "the uncrashed %s run" % scenario)
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
                self.seed(scenario, root)
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
                    elif scenario in FINAL and final_problems(root, FINAL[scenario], crashed=unset(kept)):
                        outcome = "restart did not reach %s: %s" % (
                            FINAL[scenario], final_problems(root, FINAL[scenario], crashed=unset(kept)))
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


# ---------------------------------------------------------------- PR 258 v5 F1: the restore recovery table

# Each crash point of a restore, as the real code reaches it (scenario "restore", copy chunk TABLE_CHUNK), and the
# shape of the files it leaves. The shape is checked before a row is used, so a code version without the point
# (or with a different one under the same name) fails as "another state", never as a wrong outcome.
TABLE_POINTS = OrderedDict([
    ("before-intent", "runner.restore_intent:before@1"),
    ("after-intent", "runner.restore_intent:after@1"),
    ("mid-copy", "runner.restore_chunk:after@1"),
    ("after-fsync", "runner.restore_copy:after@1"),
    ("after-move", "runner.restore_move:after@1"),
    ("after-publish", "runner.restore_publish:after@1"),
    ("after-intent-removal", "runner.restore_done:after@1"),
])
SHAPES = {
    "before-intent": {"intent": False, "live": "original", "aside": 0, "temp": "none"},
    "after-intent": {"intent": True, "live": "original", "aside": 0, "temp": "none"},
    "mid-copy": {"intent": True, "live": "original", "aside": 0, "temp": "partial"},
    "after-fsync": {"intent": True, "live": "original", "aside": 0, "temp": "complete"},
    "after-move": {"intent": True, "live": "absent", "aside": 1, "temp": "complete"},
    "after-publish": {"intent": True, "live": "backup", "aside": 1, "temp": "none"},
    "after-intent-removal": {"intent": False, "live": "backup", "aside": 1, "temp": "none"},
}
# (crash point, backup, live) -> what the next ahc-core start must do. The backup is the crash's verified backup,
# then removed ("missing") or cut to PARTIAL_BYTES ("partial"). "present" keeps the live file the crash left;
# where it left none (after-move), a foreign SQLite file is planted there. "absent" removes the live file and its
# sidecars. Outcomes:
#   untouched  no restore was pending: an ordinary start, the ledger the crash left is migrated;
#   restored   the verified backup is published (a live original is first moved aside, once) and migrated;
#   complete   an earlier attempt had published it: the intent is dropped, nothing is moved again;
#   abandoned  the backup cannot be copied and the live ledger was never moved: the intent is dropped, that
#              ledger is kept and migrated, and the abandonment is logged;
#   refused    nothing can be restored and no intact live ledger exists: SchemaError at every start, the intent
#              and every file kept byte for byte, no ledger created;
#   fresh      no restore pending and no live ledger: the ordinary first start creates an empty ledger. This is
#              outside the restore protocol (someone removed a ledger no restore was touching); the backup and
#              moved-aside files stay untouched, so an operator can still recover them.
RECOVERY_TABLE = {
    ("before-intent", "present", "present"): "untouched",
    ("before-intent", "missing", "present"): "untouched",
    ("before-intent", "partial", "present"): "untouched",
    ("before-intent", "present", "absent"): "fresh",
    ("before-intent", "missing", "absent"): "fresh",
    ("before-intent", "partial", "absent"): "fresh",
    ("after-intent", "present", "present"): "restored",
    ("after-intent", "missing", "present"): "abandoned",       # receipt harness-pr258-v5 F1, the exact sequence
    ("after-intent", "partial", "present"): "abandoned",
    ("after-intent", "present", "absent"): "restored",
    ("after-intent", "missing", "absent"): "refused",
    ("after-intent", "partial", "absent"): "refused",
    ("mid-copy", "present", "present"): "restored",
    ("mid-copy", "missing", "present"): "abandoned",
    ("mid-copy", "partial", "present"): "abandoned",
    ("mid-copy", "present", "absent"): "restored",
    ("mid-copy", "missing", "absent"): "refused",
    ("mid-copy", "partial", "absent"): "refused",
    ("after-fsync", "present", "present"): "restored",
    ("after-fsync", "missing", "present"): "abandoned",
    ("after-fsync", "partial", "present"): "abandoned",
    ("after-fsync", "present", "absent"): "restored",
    ("after-fsync", "missing", "absent"): "refused",
    ("after-fsync", "partial", "absent"): "refused",
    ("after-move", "present", "present"): "refused",          # a foreign file where the original was moved from
    ("after-move", "missing", "present"): "refused",
    ("after-move", "partial", "present"): "refused",
    ("after-move", "present", "absent"): "restored",
    ("after-move", "missing", "absent"): "refused",
    ("after-move", "partial", "absent"): "refused",
    ("after-publish", "present", "present"): "complete",      # the v4 residual: never re-moved over .failed-
    ("after-publish", "missing", "present"): "complete",
    ("after-publish", "partial", "present"): "complete",
    ("after-publish", "present", "absent"): "restored",
    ("after-publish", "missing", "absent"): "refused",
    ("after-publish", "partial", "absent"): "refused",
    ("after-intent-removal", "present", "present"): "untouched",
    ("after-intent-removal", "missing", "present"): "untouched",
    ("after-intent-removal", "partial", "present"): "untouched",
    ("after-intent-removal", "present", "absent"): "fresh",
    ("after-intent-removal", "missing", "absent"): "fresh",
    ("after-intent-removal", "partial", "absent"): "fresh",
}
_ASIDE = re.compile(r"ledger\.sqlite3\.failed-\d+")


def _files(ahc):
    """{name: sha256 of its bytes} for every file directly in the ahc root. Bytes only: nothing is opened with
    SQLite, which on some platforms leaves -wal/-shm files behind."""
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(ahc.iterdir()) if p.is_file()}


def _shape(root):
    ahc = core.Paths(root).root
    live = ahc / "ledger.sqlite3"
    backups = sorted(ahc.glob("ledger.sqlite3.pre-v*.bak"))
    bak = backups[-1].read_bytes() if backups else None
    temps = [p.read_bytes() for p in ahc.iterdir() if STAGED_TEMP.match(p.name)]
    return {"intent": Path(str(live) + ".restore-intent").exists(),
            "live": "absent" if not live.exists() else "backup" if live.read_bytes() == bak else "original",
            "aside": sum(1 for p in ahc.iterdir() if _ASIDE.fullmatch(p.name)),
            "temp": "none" if not temps else "complete" if temps == [bak] else "partial"}


def _events_of(data):
    """The events rows of a SQLite file given as bytes (read from a scratch copy, so no sidecar lands anywhere)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "copy.sqlite3"
        path.write_bytes(data)
        db = sqlite3.connect(str(path))
        try:
            return [tuple(r) for r in db.execute("SELECT item, event, at, data FROM events ORDER BY rowid")]
        finally:
            db.close()


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class RestoreRecoveryTableTests(unittest.TestCase):
    """PR 258 v5 F1, table-driven: every crash point of a restore x backup present, missing or partial x live
    present or absent, then the next ahc-core start (an in-process Ledger with the normal migrations). Each crash
    state comes from a real crash child (os._exit at the seam). Crashes inside the resume itself are
    CrashPointTests' resume-* scenarios. Invariants on every row: a backup or moved-aside file that existed is
    byte-identical afterwards; no staged temp is left; the outcome is exactly the table's."""
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        cls.crashes = {}
        for label, seam in TABLE_POINTS.items():
            root = cls.base / ("crash-" + label)
            root.mkdir(mode=0o700)
            died = run_child(root, "restore", seam=seam, extra_env={ENV_CHUNK: str(TABLE_CHUNK)})
            original = None
            backups = sorted(core.Paths(root).root.glob("ledger.sqlite3.pre-v*.bak"))
            if backups:
                original = _events_of(backups[-1].read_bytes())
            cls.crashes[label] = (root, died, original)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_table_covers_every_point_backup_and_live_condition(self):
        want = {(p, b, l) for p in TABLE_POINTS for b in ("present", "missing", "partial")
                for l in ("present", "absent")}
        self.assertEqual(set(RECOVERY_TABLE), want)

    def test_every_row(self):
        for (label, backup, live), outcome in RECOVERY_TABLE.items():
            with self.subTest(point=label, backup=backup, live=live, outcome=outcome):
                self.run_row(label, backup, live, outcome)

    def run_row(self, label, backup, live, outcome):
        src, died, original = self.crashes[label]
        self.assertEqual(died.returncode, ahc_crash.CRASH_EXIT, "the child did not die at %s, so this code has no "
                         "such crash point:\n%s" % (TABLE_POINTS[label], died.stderr[-1500:]))
        self.assertEqual(_shape(src), SHAPES[label], "the crash at %s left another state" % TABLE_POINTS[label])
        self.assertTrue(original and any(r[1] == "before-migration" for r in original), original)
        root = self.base / ("row-%s-%s-%s" % (label, backup, live))
        shutil.copytree(str(src), str(root), symlinks=True)
        paths = core.Paths(root)
        ahc, led_path = paths.root, live_db(root)
        intent = Path(str(led_path) + ".restore-intent")
        _damage_backups(root, backup)
        if live == "absent":
            _remove_live(root)
        elif not led_path.exists():
            _plant_foreign(led_path)
        before = _files(ahc)
        live_before = led_path.read_bytes() if led_path.exists() else None
        record = json.loads(intent.read_text()) if intent.exists() else None
        asides_before = {n for n in before if _ASIDE.fullmatch(n)}

        records, log = _Records(), logging.getLogger("ahc")
        log.addHandler(records)
        self.addCleanup(log.removeHandler, records)
        refused, rows = None, None
        try:
            led = runner.Ledger(paths)
        except runner.SchemaError as error:
            refused = error
        else:
            try:
                version = int(led.db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0])
                check = led.db.execute("PRAGMA integrity_check").fetchone()[0]
                rows = [tuple(r) for r in led.db.execute("SELECT item, event, at, data FROM events ORDER BY rowid")]
            finally:
                led.close()
        after = _files(ahc)

        for name, sha in before.items():
            if ".bak" in name or _ASIDE.match(name):
                self.assertEqual(after.get(name), sha, "%s was changed or removed" % name)
        self.assertEqual([n for n in after if STAGED_TEMP.match(n)], [], "a staged copy was left behind")
        new_asides = {n for n in after if _ASIDE.fullmatch(n)} - asides_before

        if outcome == "refused":
            self.assertIsNotNone(refused, "the start opened a ledger (%s)" % records.messages)
            self.assertEqual(after, {n: s for n, s in before.items() if not STAGED_TEMP.match(n)},
                             "a refused start changed files other than removing its own staged copy")
            with self.assertRaises(runner.SchemaError):
                runner.Ledger(paths)                        # and every later start refuses the same way
            self.assertEqual(_files(ahc), after)
            return
        self.assertIsNone(refused, "the start refused: %s" % refused)
        self.assertFalse(intent.exists(), "the restore intent is still there")
        self.assertEqual((version, check), (runner.SCHEMA_VERSION, "ok"))
        if outcome == "fresh":
            self.assertEqual((rows, new_asides), ([], set()))
            return
        self.assertEqual(rows, original, "the ledger does not hold the original rows")
        if outcome == "restored" and live_before is not None and SHAPES[label]["live"] == "original":
            moved = "ledger.sqlite3" + record["suffix"]
            self.assertEqual(new_asides, {moved}, "the live original is moved aside once, under the suffix")
            self.assertEqual(after[moved], hashlib.sha256(live_before).hexdigest(), "moved aside unchanged")
        else:
            self.assertEqual(new_asides, set(), "nothing is moved aside")
        abandoned = any("abandoned the interrupted ledger restore" in m for m in records.messages)
        self.assertEqual(abandoned, outcome == "abandoned", records.messages)
        if outcome == "untouched":
            self.assertFalse(any("interrupted ledger restore" in m for m in records.messages), records.messages)
        runner.Ledger(paths).close()                        # the next start is an ordinary one


class RestoreIntentTests(unittest.TestCase):
    """The interrupted-restore record (found by the crash matrix) fails closed when it cannot be trusted."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = core.Paths(Path(tmp.name))
        self.paths.ensure()
        self.intent = self.paths.root / "ledger.sqlite3.restore-intent"

    SHA = "0" * 64      # a well-formed digest, so a refusal below is for the reason each test names

    def assert_refused(self, migrate=True, because=None):
        with self.assertRaises(runner.SchemaError) as caught:
            runner.Ledger(self.paths, migrate=migrate)
        self.assertFalse((self.paths.root / "ledger.sqlite3").exists(), "no empty ledger is created")
        if because:
            self.assertIn(because, str(caught.exception))
        self.assertTrue(self.intent.exists(), "a refused record is kept for the operator")

    def record(self, **fields):
        data = {"backup": "ledger.sqlite3.pre-v4.1.bak", "suffix": ".failed-1", "sha256": self.SHA}
        data.update(fields)
        self.intent.write_text(json.dumps({k: v for k, v in data.items() if v is not None}))

    def test_an_unreadable_record_refuses_to_open(self):
        self.intent.write_text("not json\n")
        self.assert_refused(because="unreadable")

    def test_a_record_naming_a_path_outside_the_ledger_directory_refuses(self):
        outside = self.paths.home / "elsewhere.bak"
        outside.write_bytes(b"SQLite format 3\x00")
        self.record(backup="../../elsewhere.bak")
        self.assert_refused(because="does not name a backup beside the ledger")
        for bad in ("", ".", "..", "a\x00b.bak", "x.bak\n", "sub\\x.bak", 7):   # a NUL would be a ValueError
            self.record(backup=bad)
            self.assert_refused(because="does not name a backup beside the ledger")

    def test_a_record_naming_a_missing_backup_refuses_while_the_live_ledger_is_absent(self):
        """The refusal PR 258 v5 keeps: a valid record, no backup and no live ledger, so nothing can be restored
        and nothing may be created. It refuses at every start."""
        self.record()
        self.assert_refused(because="the live database is absent")
        self.assert_refused(because="the live database is absent")

    def test_a_record_with_a_bad_sha256_refuses(self):
        for bad in ("A" * 64, "0" * 63, "0" * 64 + "\n", 7, None, ""):        # None is an explicit JSON null
            self.intent.write_text(json.dumps({"backup": "ledger.sqlite3.pre-v4.1.bak", "suffix": ".failed-1",
                                               "sha256": bad}))
            self.assert_refused(because="does not name a backup beside the ledger")

    def test_a_suffix_that_is_not_exactly_failed_digits_refuses(self):
        for bad in (".failed-1\n", ".failed-", "failed-1", ".failed-1/x", ".failed-1-wal", ".failed-١"):
            self.record(suffix=bad)
            self.assert_refused(because="does not name a backup beside the ledger")

    # --- an intent written before PR 258 v5 has no sha256 (the base branch writes {"backup", "suffix"} only)
    def undigested(self):
        """A v1-era ledger with a proven backup and an intent from an earlier ahc. Returns (live, backup)."""
        led = runner.Ledger(self.paths)
        with led.tx():
            led.event("i1", "kept", T0)
        copy = led.backup("pre-v4")
        led.close()
        self.record(backup=copy.name, sha256=None)                  # record() drops a None field: no "sha256" key
        self.assertNotIn("sha256", json.loads(self.intent.read_text()))
        return self.paths.root / "ledger.sqlite3", copy

    def test_an_undigested_record_keeps_a_live_ledger_that_was_never_moved(self):
        live, copy = self.undigested()
        os.truncate(str(copy), 4096)                                # even a partial backup is never published
        with self.assertLogs("ahc", "WARNING") as logs:
            runner.Ledger(self.paths).close()
        self.assertTrue(any("has no sha256" in line for line in logs.output), logs.output)
        self.assertFalse(self.intent.exists())
        led = runner.Ledger(self.paths)
        try:
            self.assertEqual(led.db.execute("SELECT event FROM events").fetchall()[0][0], "kept")
        finally:
            led.close()
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.failed-*")), "the live ledger was moved")

    def test_an_undigested_record_whose_backup_was_published_drops_the_intent(self):
        live, copy = self.undigested()
        os.rename(str(live), str(live) + ".failed-1")               # the earlier ahc moved it aside, then published
        for extra in ("-wal", "-shm"):
            if os.path.lexists(str(live) + extra):
                os.rename(str(live) + extra, str(live) + ".failed-1" + extra)
        live.write_bytes(copy.read_bytes())
        os.chmod(str(live), 0o600)
        kept = Path(str(live) + ".failed-1").read_bytes()
        runner.Ledger(self.paths).close()
        self.assertFalse(self.intent.exists())
        self.assertEqual(Path(str(live) + ".failed-1").read_bytes(), kept, "moved aside again")

    def test_an_undigested_record_with_the_ledger_moved_or_absent_refuses(self):
        live, copy = self.undigested()
        for extra in ("", "-wal", "-shm"):
            if os.path.lexists(str(live) + extra):
                os.rename(str(live) + extra, str(live) + ".failed-1" + extra)
        for _ in range(2):
            with self.assertRaises(runner.SchemaError) as caught:
                runner.Ledger(self.paths)
            self.assertIn("has no sha256", str(caught.exception))
        self.assertFalse(live.exists(), "the unverifiable backup was published or an empty ledger created")
        self.assertTrue(self.intent.exists())
        live.write_bytes(b"SQLite format 3\x00 but not the backup")    # a foreign file, the original moved aside
        with self.assertRaises(runner.SchemaError):
            runner.Ledger(self.paths)
        self.assertTrue(self.intent.exists())

    def test_a_non_migrating_process_never_completes_a_restore(self):
        self.record(backup="x.bak")
        self.assert_refused(migrate=False, because="ahc-core completes it")

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
        self.record(backup=copy.name, suffix=".failed-6", sha256=hashlib.sha256(copy.read_bytes()).hexdigest())
        led = runner.Ledger(self.paths)
        try:
            self.assertEqual(led.db.execute("SELECT event FROM events").fetchall()[0][0], "kept")
        finally:
            led.close()
        self.assertFalse(self.intent.exists())


class StateDigestTests(unittest.TestCase):
    """state() names a restore's staged copy by a fixed key whatever its random name (PR 258 v5 load flake: 64 of
    640 checks failed at restore_copy:after@1 and restore_move:before@1 on t2-dev, every one a temp name holding a
    run of 9 or more decimal characters)."""

    def scenario_dir(self, temp_name):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        ahc = core.Paths(root).root
        ahc.mkdir(parents=True, mode=0o700)
        (ahc / temp_name).write_bytes(b"the staged copy's bytes")
        (ahc / "ledger.sqlite3.pre-v4.1800000000123000000.bak").write_bytes(b"not sqlite")
        return root

    def test_a_staged_copy_has_one_key_whatever_its_random_name(self):
        plain = self.scenario_dir(".ledger.sqlite3.0123abcdef456789.tmp")
        for name in ("ab123456789cdef0", "6722194634013886", "fedcba9876543210", "3957310579c5d1bc"):
            with self.subTest(name=name):
                other = self.scenario_dir(".ledger.sqlite3.%s.tmp" % name)
                self.assertEqual(state(other), state(plain))
                self.assertIn(str(Path(".agent-harness") / "ahc" / STAGED_KEY), state(other))

    def test_random_names_never_change_the_digest(self):
        """Seeded (16049): 2,000 names from the same alphabet as secrets.token_hex(8). About 5% hold a 9-digit
        run, so the old normalization fails this within the first few dozen."""
        rng = random.Random(16049)
        want = digest(self.scenario_dir(".ledger.sqlite3.0123abcdef456789.tmp"))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        ahc = core.Paths(root).root
        ahc.mkdir(parents=True, mode=0o700)
        (ahc / "ledger.sqlite3.pre-v4.1800000000123000000.bak").write_bytes(b"not sqlite")
        current = None
        for _ in range(2000):
            name = ".ledger.sqlite3.%s.tmp" % "".join(rng.choice("0123456789abcdef") for _ in range(16))
            if current is not None:
                current.unlink()
            current = ahc / name
            current.write_bytes(b"the staged copy's bytes")
            self.assertEqual(digest(root), want, name)

    def test_other_names_still_fold_their_time_digits(self):
        a = self.scenario_dir(".ledger.sqlite3.0123abcdef456789.tmp")
        b = self.scenario_dir(".ledger.sqlite3.0123abcdef456789.tmp")
        os.rename(str(core.Paths(b).root / "ledger.sqlite3.pre-v4.1800000000123000000.bak"),
                  str(core.Paths(b).root / "ledger.sqlite3.pre-v4.1800000000999000000.bak"))
        self.assertEqual(state(a), state(b))


class InventoryTests(unittest.TestCase):
    MODULES = ("ahc_contracts", "ahc_runner", "ahc_clock", "ahc_migrate")

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



# ---------------------------------------------------------------- AC-4: the named crash points (ahc_crash.POINTS)
# goodqa#16049 slice 1 (b), spec r9 AC-4: a tick scenario drives each named point; a crash there and a restart keep
# the scenario's invariants (each move applied once by the CAS; a send at most once).

class _CrashProducer:
    """A deterministic producer for the shadow tick scenario: each read is stamped and persisted (ahc_observe's
    contract) and carries facts under which only W5 holds for a merge-ready item (the mirror is down)."""

    def __init__(self, c):
        self.c, self.incidents = c, []

    def observe(self, repo, pr, *, item=None, clone=None, snapshot_bases=(), base=None):
        stamp = self.c.first_read_stamp()
        row = self.c._row("work_items", "id", item)
        fields = dict(pr=pr, pr_head=row["head"], pr_state="OPEN", tip=row["base"], draft=False, compare="ahead",
                      b_r_ancestors={row["base"]: True}, attached_core=row["spec_core"], open_findings=0,
                      paths=["lib/x.py"], foreign_closing_keyword=False, mergeable=True, mergeable_state="clean",
                      policy={"revision": POLICY, "readable": True, "allowlisted": True, "enabled": True,
                              "checks_green": True},
                      kill_switch=False, chk_cas=True, canary_age=60, mirror_ok=False)
        self.c.record_observation(stamp, repo, pr, item, {"test": "crash"}, [], fields)
        return self.c.load_observation(stamp["id"])


def scenario_shadow_tick(root, clock):
    """One merge-ready WorkItem and one shadow tick (AC-4). The fixture steps are idempotent by event id, so a
    restart resumes; the tick itself re-observes and the version CAS lets W5 apply exactly once."""
    import ahc_shadow  # noqa: PLC0415
    os.environ["AHC_SHADOW"] = "1"
    led = runner.Ledger(core.Paths(root))
    c = C.Contracts(led.db, C.AuthorityLog(Path(root) / "authority.jsonl"), now=clock, mono=clock,
                    boot_id="crash-boot")
    item = c.admit_item("o/r", 7, H1, BASE, POLICY, "1" * 64, "d" * 64, event_id="sh-w1")
    if not _done(led.db, "sh-ready"):
        with c.tx():
            led.db.execute("UPDATE reviews SET state='passed' WHERE item=?", (item["id"],))
            led.db.execute("UPDATE work_items SET state='merge-ready', version=version+1 WHERE id=?", (item["id"],))
            led.db.execute("INSERT INTO transitions(entity, id, from_state, to_state, event_id, actor, at, data) "
                           "VALUES ('fixture', ?, 'pr-gate', 'merge-ready', 'sh-ready', 'test', ?, '{}')",
                           (item["id"], clock.t))
    ahc_shadow.ShadowTick(c, _CrashProducer(c), lambda repo, head, base: "/clone",
                          {"shadow_repos": ["o/r"]}).tick()
    led.close()


def check_shadow_tick(root):
    """The shadow scenario's restart invariants: W5 applied exactly once and the item in waiting-dep."""
    db = sqlite3.connect("file:%s?mode=ro" % live_db(root), uri=True)
    try:
        rows = [json.loads(d)["row"] for (d,) in db.execute(
            "SELECT data FROM transitions WHERE entity='work_item' ORDER BY seq")]
        state = db.execute("SELECT state FROM work_items").fetchone()[0]
    finally:
        db.close()
    out = [] if rows == ["W1", "W5"] else ["moves %r, not W1 then W5 once" % rows]
    return out + ([] if state == "waiting-dep" else ["state %s, not waiting-dep" % state])


NAMED_SCENARIOS["shadow_tick"] = scenario_shadow_tick
NAMED_POINTS = {"tick.observed": ("shadow_tick", check_shadow_tick)}


class NamedPointTests(unittest.TestCase):
    """AC-4: every named point is registered, counted by its tick scenario, and a crash there then a restart keeps
    the scenario's invariants."""

    def test_ac4_named_points_are_counted_and_a_crash_at_each_keeps_the_invariants(self):
        self.assertEqual(set(NAMED_POINTS), set(ahc_crash.POINTS), "every named point has a scenario")
        with tempfile.TemporaryDirectory() as tmp:
            for n, (point, (scenario, check)) in enumerate(sorted(NAMED_POINTS.items())):
                with self.subTest(point=point):
                    counted = Path(tmp) / ("count-%d" % n)
                    counted.mkdir(mode=0o700)
                    self.assertIn("%s:at@1" % point, counting_pass(counted, scenario), "the scenario reaches it")
                    root = Path(tmp) / ("crash-%d" % n)
                    root.mkdir(mode=0o700)
                    died = run_child(root, scenario, seam="%s:at@1" % point)
                    self.assertEqual(died.returncode, ahc_crash.CRASH_EXIT, died.stderr[-1500:])
                    self.assertIn("%s %s:at@1" % (ahc_crash.MARKER, point), died.stderr)
                    resumed = run_child(root, scenario, phase="resume")
                    self.assertEqual(resumed.returncode, 0, resumed.stderr[-1500:])
                    self.assertEqual(check(root), [])
                    self.assertEqual(check(counted), [], "the uncrashed run")



def scenario_w21_send(root, clock):
    """AC-7 / NEG-18: one W21 intent and one sender pass with the flag on. The fake gh appends each call to
    calls.txt; a restart runs reconciliation first, then the pass again, so a crash anywhere sends at most once."""
    import ahc_w21  # noqa: PLC0415
    os.environ["AHC_W21_SEND"] = "1"
    led = runner.Ledger(core.Paths(root))
    c = C.Contracts(led.db, C.AuthorityLog(Path(root) / "authority.jsonl"), now=clock, mono=clock,
                    boot_id="crash-boot")
    item = c.admit_item("o/r", 7, H1, BASE, POLICY, "1" * 64, "d" * 64, event_id="w21-w1")
    led.db.execute("UPDATE reviews SET state='passed' WHERE item=?", (item["id"],))
    calls = Path(root) / "calls.txt"

    def gh(args, timeout):
        with open(str(calls), "a", encoding="utf-8") as handle:     # test-only record of each gh call
            handle.write(" ".join(args) + "\n")
        return (0, "", "") if args[2] == "PUT" else (0, json.dumps({"head": {"sha": H1}}), "")
    sender = ahc_w21.Sender(c, gh, lambda args: None, lambda: {"on": False, "epoch": 1, "mono": clock.t,
                                                                "shared": True},
                            lambda repo: True, lambda args, cwd: (1, ""), lambda repo, head, base: "/clone")
    sender.reconcile()                  # startup reconciliation runs before any new W21
    if not _done(led.db, "w21-row"):
        item = c._row("work_items", "id", item["id"])
        o = {"at": clock.t, "mono": clock.t, "boot": "crash-boot", "repo": "o/r", "pr": 7, "pr_state": "OPEN",
             "pr_head": H1, "tip": BASE, "draft": False, "compare": "behind", "b_r_ancestors": {BASE: True},
             "attached_core": "1" * 64, "open_findings": 0, "paths": ["lib/x.py"], "foreign_closing_keyword": False,
             "policy": {"revision": POLICY, "readable": True, "allowlisted": True, "enabled": True,
                        "checks_green": True, "w21": True},
             "kill_switch": False, "chk_cas": True, "canary_age": 60}
        c.wi_move(item["id"], "W21", expected_version=item["version"], event_id="w21-row", actor="ahc-core",
                  obs=dict(o, queue={item["id"]: o}, mergeable=True))
    sender.pump()
    led.close()


def check_w21_send(root):
    """At most one update-branch call, one send row, and the row never cancelled once attempted."""
    calls = Path(root) / "calls.txt"
    puts = [l for l in calls.read_text().splitlines() if " PUT " in l] if calls.exists() else []
    db = sqlite3.connect("file:%s?mode=ro" % live_db(root), uri=True)
    try:
        rows = db.execute("SELECT state, attempted_at FROM w21_sends").fetchall()
    finally:
        db.close()
    out = [] if len(puts) <= 1 else ["%d update-branch calls" % len(puts)]
    out += [] if len(rows) == 1 else ["%d send rows" % len(rows)]
    out += ["an attempted row was cancelled" for state, at in rows if state == "cancelled" and at is not None]
    if puts and rows and rows[0][0] not in ("attempted", "readback-pending"):
        out.append("a sent row is %s" % rows[0][0])
    return out


NAMED_SCENARIOS["w21_send"] = scenario_w21_send
NAMED_POINTS["w21.before_send"] = ("w21_send", check_w21_send)
NAMED_POINTS["w21.after_send"] = ("w21_send", check_w21_send)



def scenario_r3_launch(root, clock):
    """AC-8 / NEG-36: one queued review row and one R3 launch through Launcher.for_test. The fake runner records each
    unit it starts in units.txt and each stop in stopped.txt. A restart runs startup reconciliation first (its units
    are the started ones not yet stopped), then launches again unless the row already runs."""
    import ahc_guard  # noqa: PLC0415
    import ahc_review  # noqa: PLC0415
    led = runner.Ledger(core.Paths(root))
    c = C.Contracts(led.db, C.AuthorityLog(Path(root) / "authority.jsonl"), now=clock, mono=clock,
                    boot_id="crash-boot")
    row = c.require_review("adversarial", "o/r", 7, H1, "d" * 64, POLICY, item="wi-crash", event_id="r3-req",
                           snapshot_base=BASE)
    if row["state"] == "required":
        row = c.review(row["id"], "queued", expected_version=row["version"], event_id="r3-queued")
    units, stopped = Path(root) / "units.txt", Path(root) / "stopped.txt"

    def lines(path):
        return path.read_text().splitlines() if path.exists() else []

    class FileRunner:
        def start(self, argv):
            with open(str(units), "a", encoding="utf-8") as handle:       # test-only record of each start
                handle.write([a for a in argv if a.startswith("--unit=")][0][len("--unit="):] + "\n")
            return 0, "", ""

        def uid(self, unit):
            return 4242

        def stop(self, unit):
            with open(str(stopped), "a", encoding="utf-8") as handle:     # test-only record of each stop
                handle.write(unit + "\n")
            return True

        def live(self):
            return [u for u in lines(units) if u not in set(lines(stopped))]

        def show(self, unit, props):
            return {"Slice": "ahc-review.slice", "ActiveState": "active" if unit in self.live() else "inactive"}

        def grant_output(self, out_dir, uid):
            pass

        def list_units(self):
            return self.live()
    stub = Path(root) / "systemd-run"
    if not stub.exists():
        stub.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(str(stub), 0o755)
    policy = ahc_guard.Policy.for_test(root, {"systemd-run": str(stub)}, trusted_dirs=(str(root),))
    fr = FileRunner()
    ahc_review.Reconciler(c, policy, fr, sleep=lambda s: None).run()
    if c._row("reviews", "id", row["id"])["state"] == "queued":
        ahc_review.Launcher.for_test(c, policy, "/opt/ahc/peer_review.py", fr, root).launch(row["id"],
                                                                                          sandbox_repo="o/r")
    led.close()


def check_r3_launch(root):
    """At most one live unit for the row; every intent charged exactly once; an intent without start_attempt that
    reconciliation saw is orphaned with its unit stopped."""
    units = (Path(root) / "units.txt").read_text().splitlines() if (Path(root) / "units.txt").exists() else []
    stopped = (Path(root) / "stopped.txt").read_text().splitlines() if (Path(root) / "stopped.txt").exists() else []
    live = [u for u in units if u not in set(stopped)]
    db = sqlite3.connect("file:%s?mode=ro" % live_db(root), uri=True)
    try:
        intents = db.execute("SELECT id, unit, state FROM launch_intents").fetchall()
        used = (db.execute("SELECT COALESCE(SUM(b33_used), 0) FROM lineage_budget").fetchone() or (0,))[0]
        running = db.execute("SELECT producer_unit FROM reviews WHERE state='running'").fetchall()
    finally:
        db.close()
    out = [] if len(live) <= 1 else ["%d live units for the row" % len(live)]
    out += [] if used == len(intents) else ["B33 used %d for %d intents" % (used, len(intents))]
    out += ["orphaned intent %s has a live unit" % i for i, u, s in intents if s == "orphaned" and u in live]
    out += ["running row bound to %s, not the live unit" % r for (r,) in running if live and r not in live]
    return out


NAMED_SCENARIOS["r3_launch"] = scenario_r3_launch
NAMED_POINTS["r3.unit_started"] = ("r3_launch", check_r3_launch)


if __name__ == "__main__":
    unittest.main()
