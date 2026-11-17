"""ahc ledger schema version 5 (goodqa#16049 slice 1 (b), AC-11 and AC-16): the maintenance lock, the read-only
preflight, the schema-version fence, the open-file check, the generic table rebuild and the layout detection.

The sequence itself runs in ahc_runner.Ledger (it owns the backup and the restore). Every helper here is pure or
takes its subprocess runner as an argument, so the tests drive each step without the real tools.
"""
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path

import ahc_fs as fs

SCHEMA_VERSION = 5
FENCE_PREFIX = "v5-migrating-from-"
FENCE_RE = re.compile(r"^v5-migrating-from-([0-9]+)$")
MAINT_NAME = "ledger.sqlite3.maint"   # inside old code's ROOT_PATTERNS ("ledger.sqlite3.*"), so a rollback can open the root
LEGACY_SUFFIX = "_v4_legacy"
ROLE_WAIT_SECONDS = 60.0          # how long the migrator waits for a role lock before refusing (NEG-27)
PROBE_TIMEOUT = 30.0
TRUSTED_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
RELEASE_LIST = "ahc_release.json"  # the v5 release's entry-point hashes: a data file, never an entry point (L-r4-1)


class SchemaError(RuntimeError):
    """The ledger's schema is unknown, newer than this code, fenced or not migratable; nothing was written."""


class MigrationPending(SchemaError):
    """A ledger only ahc-core can bring current (fenced by an interrupted or refused v5 migration, an older schema,
    or an interrupted restore), found by a process that does not migrate. The review role waits on it (PR 247 F2)."""


class MigrationRefused(SchemaError):
    """A named preflight or open-file refusal. The ledger's rows and schema_version are as they were."""


class StrayLedger(SchemaError):
    """The failure restore found a file at the ledger path that it did not publish; nothing replaced it."""


# ---------------------------------------------------------------- locks

def maint_lock(root, shared, timeout=None):
    """The ledger maintenance flock (AC-11): every ledger connection holds it shared while it is open; the migrator
    holds it exclusive over backup, migrate, restore and reopen. Blocking; with a timeout, None when not taken."""
    handle = os.fdopen(fs.open_file(root, Path(root) / MAINT_NAME, os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a")
    mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
    if timeout is None:
        fcntl.flock(handle.fileno(), mode)
        return handle
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
            return handle
        except OSError:
            if time.monotonic() >= deadline:
                handle.close()
                return None
            time.sleep(0.05)


def wait_role_lock(root, role, timeout):
    """A role lock taken by the migrator (core, then review), waiting at most `timeout` seconds."""
    handle = os.fdopen(fs.open_file(root, Path(root) / ("ahc-%s.lock" % role),
                                    os.O_WRONLY | os.O_CREAT | os.O_APPEND), "a")
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except OSError:
            if time.monotonic() >= deadline:
                handle.close()
                return None
            time.sleep(0.05)


# ---------------------------------------------------------------- version and fence

def read_version(db):
    """(version, fenced). version None: a fresh database (no meta and no items). fenced: the version is the prior
    n named by a `v5-migrating-from-n` fence. A value that is neither an integer nor a fence is a SchemaError."""
    has_meta = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
    if not has_meta:
        has_items = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'").fetchone()
        return (0 if has_items else None), False
    row = db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
    if row is None:
        return 0, False
    value = row[0]
    match = FENCE_RE.match(str(value))
    if match:
        return int(match.group(1)), True
    try:
        return int(value), False
    except (TypeError, ValueError):
        raise SchemaError("unreadable schema_version %r" % (value,)) from None


def set_fence(db, n):
    """Step 3: one BEGIN IMMEDIATE transaction writes `v5-migrating-from-n`; the prior version is never lost."""
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('schema_version', ?)", (FENCE_PREFIX + str(n),))
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


def clear_fence(db, n):
    """Back to n in one transaction; for n = 0 (a ledger with no schema_version row) the row is deleted again."""
    db.execute("BEGIN IMMEDIATE")
    try:
        if n == 0:
            db.execute("DELETE FROM meta WHERE k='schema_version'")
        else:
            db.execute("UPDATE meta SET v=? WHERE k='schema_version'", (str(n),))
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


# ---------------------------------------------------------------- the open-file probe (lsof, then fuser)

class ProbeError(RuntimeError):
    """The open-file tool could not give a clean answer: missing, denied, a timeout, a signal, unexpected stderr."""


def trusted_tool(name, dirs=TRUSTED_DIRS):
    """The tool's absolute path from a fixed trusted directory list (AC-13), refused when group- or other-writable
    or owned by anyone but root or this uid."""
    for directory in dirs:
        path = os.path.join(directory, name)
        try:
            info = os.stat(path)
        except OSError:
            continue
        if info.st_mode & 0o022 or info.st_uid not in (0, os.getuid()):
            continue
        if os.access(path, os.X_OK):
            return path
    return None


PROBE_ENV = {"PATH": ":".join(TRUSTED_DIRS), "LC_ALL": "C"}


def _lsof(tool, files, run):
    argv = [tool, "-w", "-F", "p", "--"] + [str(f) for f in files]
    proc = run(argv, PROBE_TIMEOUT)
    # lsof exits 1 when nothing holds a file: the exit status is never used, only the output (r8 probe on the Mac)
    if proc.returncode < 0 or proc.stderr.strip():
        raise ProbeError("lsof: rc %s, stderr %r" % (proc.returncode, proc.stderr.strip()[:200]))
    pids = set()
    for line in proc.stdout.splitlines():
        if not line:
            continue
        if re.fullmatch(r"f\S+", line):          # lsof always adds the descriptor field
            continue
        if not re.fullmatch(r"p[0-9]+", line):
            raise ProbeError("lsof: unexpected output line %r" % line[:80])
        pids.add(int(line[1:]))
    return pids


def _fuser(tool, files, run):
    argv = [tool] + [str(f) for f in files]
    proc = run(argv, PROBE_TIMEOUT)
    if proc.returncode < 0:
        raise ProbeError("fuser: killed by signal %s" % -proc.returncode)
    # fuser echoes each file name on stderr ("path:"; psmisc also prints access letters there); macOS fuser exits 0
    # either way. Anything else on stderr is an error.
    names = {str(f) for f in files}
    for line in proc.stderr.splitlines():
        text = line.strip()
        if not text:
            continue
        head = text.split(":", 1)[0]
        rest = text.split(":", 1)[1] if ":" in text else None
        if head not in names or rest is None or not re.fullmatch(r"[\sA-Za-z0-9]*", rest):
            raise ProbeError("fuser: unexpected stderr %r" % text[:120])
    pids = set()
    for token in proc.stdout.split():
        match = re.fullmatch(r"([0-9]+)[a-zA-Z]*", token)
        if not match:
            raise ProbeError("fuser: unexpected output %r" % token[:40])
        pids.add(int(match.group(1)))
    return pids


def open_file_holders(files, run, tools=None):
    """The pids holding any of `files` open, read from lsof, or fuser where lsof is absent. ProbeError otherwise."""
    tools = tools if tools is not None else {"lsof": trusted_tool("lsof"), "fuser": trusted_tool("fuser")}
    try:
        if tools.get("lsof"):
            return _lsof(tools["lsof"], files, run)
        if tools.get("fuser"):
            return _fuser(tools["fuser"], files, run)
    except ProbeError:
        raise
    except Exception as error:                      # a timeout, a denial, a vanished file: never "clear"
        raise ProbeError("open-file check failed: %s" % type(error).__name__) from None
    raise ProbeError("neither lsof nor fuser is installed in a trusted directory")


def default_run(argv, timeout):
    import subprocess  # noqa: PLC0415
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=dict(PROBE_ENV), cwd="/")


# ---------------------------------------------------------------- entry-point manifest (preflight)

def release_list(hooks_dir):
    """{file name: sha256} for every v5 entry-point module, shipped with the release and reviewed with the code."""
    with open(os.path.join(str(hooks_dir), RELEASE_LIST), encoding="utf-8") as handle:
        data = json.load(handle)
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict) or not files:
        raise MigrationRefused("preflight: the release list %s is malformed" % RELEASE_LIST)
    return files


def file_sha256(path):
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_entry_points(hooks_dir, extra=()):
    """Preflight: every installed entry point hashes to the release list; a leftover 4d45fe40 file mismatches.
    `extra` adds (path, expected sha256) pairs for installed wrappers and unit files."""
    problems = []
    for name, want in sorted(release_list(hooks_dir).items()):
        path = os.path.join(str(hooks_dir), name)
        try:
            got = file_sha256(path)
        except OSError as error:
            problems.append("%s unreadable (%s)" % (name, type(error).__name__))
            continue
        if got != want:
            problems.append("%s sha256 %s, release lists %s" % (name, got[:12], want[:12]))
    for path, want in extra:
        try:
            got = file_sha256(path)
        except OSError as error:
            problems.append("%s unreadable (%s)" % (path, type(error).__name__))
            continue
        if got != want:
            problems.append("%s does not match the v5 release" % path)
    if problems:
        raise MigrationRefused("preflight: installed entry points do not match the v5 release: %s"
                               % "; ".join(problems))


# ---------------------------------------------------------------- layouts and the generic rebuild

LAYOUT_MARKERS = ("snapshot_base", "spec_core", "round")


def columns(db, table):
    return [row[1] for row in db.execute("PRAGMA table_info(\"%s\")" % table)]


def detect_layout(db):
    """AC-11's normative detection on the reviews table's marker columns."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reviews'").fetchone():
        return "no-reviews"
    have = set(columns(db, "reviews"))
    markers = tuple(m for m in LAYOUT_MARKERS if m in have)
    return {("snapshot_base",): "pr258", ("snapshot_base", "spec_core"): "4d45fe40",
            ("snapshot_base", "spec_core", "round"): "v5", (): "early-v4"}.get(markers, "unknown")


def schema_objects(schema_sql):
    """{name: (type, table, sql)} of a fresh database built from `schema_sql` (SQLite's own normalized text)."""
    mem = sqlite3.connect(":memory:")
    try:
        for statement in [s.strip() for s in schema_sql.split(";") if s.strip()]:
            mem.execute(statement)
        return {name: (kind, table, sql) for kind, name, table, sql in mem.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    finally:
        mem.close()


def _counts_by_state(db, table, where=""):
    cols = columns(db, table)
    if "state" in cols:
        return sorted(tuple(r) for r in db.execute('SELECT state, COUNT(*) FROM "%s" %s GROUP BY state'
                                                    % (table, where)).fetchall())
    return [(None, db.execute('SELECT COUNT(*) FROM "%s" %s' % (table, where)).fetchone()[0])]


def rebuild_changed_tables(db, schema_sql, layout):
    """Every table whose v5 definition differs from the ledger's is renamed aside as {table}_v4_legacy, recreated
    from SCHEMA (never ADD COLUMN) and its rows copied, each new column at its stated default. A PR 258 ledger's
    spec rows are not copied (they carry no core) and stay only in reviews_v4_legacy. The copy is checked by row
    count and per-state counts before the caller commits. Renamed tables are never dropped. Returns the names."""
    want = schema_objects(schema_sql)
    have = {name: (kind, table, sql) for kind, name, table, sql in db.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    rebuilt = []
    for name, (kind, _table, sql) in sorted(want.items()):
        if kind != "table" or name not in have or have[name][2] == sql:
            continue
        legacy = name + LEGACY_SUFFIX
        if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (legacy,)).fetchone():
            raise SchemaError("a %s table already exists; refusing to rebuild %s" % (legacy, name))
        for (index,) in db.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT "
                                   "NULL", (name,)).fetchall():
            db.execute('DROP INDEX "%s"' % index)       # an index name would collide with the recreated one's
        db.execute('ALTER TABLE "%s" RENAME TO "%s"' % (name, legacy))
        db.execute(sql)
        for other_name, (other_kind, other_table, other_sql) in want.items():
            if other_kind == "index" and other_table == name:
                db.execute(other_sql)
        new_cols = columns(db, name)
        common = [c for c in columns(db, legacy) if c in new_cols]
        where = "WHERE kind != 'spec'" if (name == "reviews" and layout == "pr258") else ""
        db.execute('INSERT INTO "%s"(%s) SELECT %s FROM "%s" %s' % (
            name, ", ".join('"%s"' % c for c in common), ", ".join('"%s"' % c for c in common), legacy, where))
        if _counts_by_state(db, name) != _counts_by_state(db, legacy, where):
            raise SchemaError("rebuilt %s does not hold the rows it was meant to copy" % name)
        rebuilt.append(name)
    return rebuilt


def legacy_tables(db):
    return sorted(name for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND "
                                                 "(name LIKE '%\\_v3\\_legacy' ESCAPE '\\' OR "
                                                 "name LIKE '%\\_v4\\_legacy' ESCAPE '\\')"))
