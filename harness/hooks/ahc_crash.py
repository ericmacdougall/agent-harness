#!/usr/bin/env python3
"""AC-18 crash-point seams and the durable-write inventory (goodqa#16049 spec ahc-m1-v2g7 AC-18, harvest idea 2).

Seams: `crash_before(name)` and `crash_after(name)` sit around every durable write of the ledger code that exists
now (ahc_contracts and ahc_runner). Unarmed, they cost one dict lookup. A seam is armed only when the environment
names it (AHC_CRASH_SEAM=<name>:<before|after>@<occurrence>) AND the process runs under unittest (the `unittest`
module is loaded and AHC_CRASH_UNDER_TEST=1): a production process never honours the variable. An armed seam kills
the process with os._exit(CRASH_EXIT) after writing one marker line to stderr, so no `finally`, ROLLBACK or atexit
runs: that is a crash, not an exception. With AHC_CRASH_COUNT=<file>, every seam reached appends its name to the
file instead (the counting pass that enumerates crash points).

Coverage claim: process death at each listed point. Not power loss (SQLite's FULL synchronous mode and the
authority log's fsync are relied on for that, untested here).

Inventory: `inventory(source, module)` parses a module with `ast` and returns every durable-write call site, keyed
(module, function, op). The test compares it with INVENTORY: an unlisted site, a count that changed or a stale entry
fails. Dispatch-side seams (C5) join when C5 is unheld.
"""

from __future__ import annotations

import ast
import os
import sys
from collections import Counter

ENV_SEAM = "AHC_CRASH_SEAM"
ENV_UNDER_TEST = "AHC_CRASH_UNDER_TEST"
ENV_COUNT = "AHC_CRASH_COUNT"
CRASH_EXIT = 86
MARKER = "AHC_CRASH_SEAM_HIT"

_seen = Counter()
_observers = []          # test-only: callables(point, occurrence) run at each seam during the counting pass

# Every seam, each with a crash_before and a crash_after call around its durable write.
SEAMS = (
    "contracts.commit",        # Contracts.tx: the COMMIT of every ledger transition
    "contracts.authority",     # AuthorityLog.append: the fsynced authority-log line (written before its COMMIT)
    "runner.commit",           # runner _Tx.__exit__: the COMMIT of every runner ledger transaction
    "runner.append_private",   # _append_private: the item journal mirror line
    "runner.write_private",    # _write_private: tmp write + atomic replace (status, reason files)
    "runner.inbox",            # _write_inbox: the owner notice rename into place
    "runner.stage_packet",     # stage_packet: the staged packet file
    "runner.quarantine",       # _quarantine: the queue entry rename into rejected/
    "runner.prune",            # Worker.prune_packets: a staged packet removal
    "runner.backup",           # Ledger.backup: the verified pre-migration copy
    "runner.restore_intent",   # Ledger.restore: the durable interrupted-restore record written first
    "runner.restore_move",     # Ledger.restore: the failed database files renamed aside
    "runner.restore_copy",     # Ledger.restore: the verified backup copied back into place
)


def observe(fn):
    """Test-only: call fn(point, occurrence) at every seam the counting pass reaches."""
    _observers.append(fn)


def _armed():
    """The armed (name, when, occurrence), or None. Honoured only under unittest (both conditions)."""
    spec = os.environ.get(ENV_SEAM)
    if not spec or os.environ.get(ENV_UNDER_TEST) != "1" or "unittest" not in sys.modules:
        return None
    try:
        point, occurrence = spec.rsplit("@", 1)
        name, when = point.rsplit(":", 1)
        return name, when, int(occurrence)
    except ValueError:
        return None


def _seam(name, when):
    if not os.environ.get(ENV_SEAM) and not os.environ.get(ENV_COUNT):
        return
    if os.environ.get(ENV_UNDER_TEST) != "1" or "unittest" not in sys.modules:
        return
    point = "%s:%s" % (name, when)
    _seen[point] += 1
    count_file = os.environ.get(ENV_COUNT)
    if count_file:
        extra = [str(fn(point, _seen[point])) for fn in _observers]
        with open(count_file, "a", encoding="utf-8") as handle:     # test-only: the counting pass
            handle.write("\t".join(["%s@%d" % (point, _seen[point])] + extra) + "\n")
    armed = _armed()
    if armed and armed[0] == name and armed[1] == when and armed[2] == _seen[point]:
        sys.stderr.write("%s %s@%d\n" % (MARKER, point, _seen[point]))
        sys.stderr.flush()
        os._exit(CRASH_EXIT)


def crash_before(name):
    _seam(name, "before")


def crash_after(name):
    _seam(name, "after")


# ---------------------------------------------------------------- inventory

SQL_READS = ("SELECT", "BEGIN", "ROLLBACK", "SAVEPOINT", "RELEASE", "EXPLAIN", "WITH")
FILE_OPS = {
    ("os", "write"), ("os", "rename"), ("os", "replace"), ("os", "remove"), ("os", "unlink"), ("os", "rmdir"),
    ("os", "makedirs"), ("os", "mkdir"), ("os", "chmod"), ("os", "fsync"), ("os", "truncate"), ("os", "link"),
    ("os", "symlink"), ("shutil", "copyfile"), ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "move"),
    ("shutil", "rmtree"), ("sqlite3", "connect"),
}
PATH_OPS = ("write_text", "write_bytes", "unlink", "rename", "replace", "touch", "mkdir", "rmdir", "chmod")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")


def _sql_text(node):
    """The leading literal text of an execute() argument, or None when it is built at run time."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
        return node.left.value                                       # "... %s ..." % args
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        return node.values[0].value
    if isinstance(node, ast.IfExp):
        a, b = _sql_text(node.body), _sql_text(node.orelse)
        return a if a is not None and b is not None and _verb(a) == _verb(b) else None
    return None


def _verb(text):
    words = text.strip().split(None, 1)
    return words[0].upper() if words else ""


def _sql_op(call):
    if not call.args:
        return "sql:DYNAMIC"
    text = _sql_text(call.args[0])
    if text is None:
        return "sql:DYNAMIC"
    verb = _verb(text)
    if verb == "PRAGMA" and "=" not in text:
        return None                                                  # a read pragma (table_info, integrity_check)
    if verb in SQL_READS:
        return None
    return "sql:" + verb


def _flags_write(node):
    return any(isinstance(n, ast.Attribute) and n.attr in WRITE_FLAGS for n in ast.walk(node)) or \
        any(isinstance(n, ast.Name) and n.id in WRITE_FLAGS for n in ast.walk(node))


def _op(call):
    """The durable-write kind of one call, or None."""
    f = call.func
    if isinstance(f, ast.Attribute):
        if f.attr in ("execute", "executemany", "executescript"):
            return _sql_op(call) if f.attr == "execute" else "sql:" + f.attr
        if f.attr == "commit" and not call.args:
            return "sql:commit()"
        if f.attr == "backup":
            return "sqlite.backup"
        if isinstance(f.value, ast.Name) and (f.value.id, f.attr) in FILE_OPS:
            return "%s.%s" % (f.value.id, f.attr)
        if isinstance(f.value, ast.Name) and f.value.id == "os" and f.attr == "open":
            return "os.open(write)" if any(_flags_write(a) for a in call.args[1:2]) else None
        if f.attr in PATH_OPS and not (isinstance(f.value, ast.Name) and f.value.id in ("os", "shutil", "re")):
            if f.attr == "replace" and len(call.args) == 2:
                return None                     # str.replace(old, new); Path.replace takes one target
            return "path." + f.attr
        if f.attr == "write" and not (isinstance(f.value, ast.Attribute) and f.value.attr in ("stderr", "stdout")):
            return "handle.write"
    if isinstance(f, ast.Name) and f.id == "open":
        mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+"):
            return "open(write)"
        if mode is not None and not isinstance(mode, ast.Constant):
            return "open(dynamic)"
    return None


def _is_tx(item):
    e = item.context_expr
    return isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "tx"


class _Walker(ast.NodeVisitor):
    def __init__(self, module):
        self.module, self.stack, self.tx_depth, self.sites = module, [], 0, Counter()
        self.calls = {}         # callee short name -> [(caller qualname, lexically in a tx)]
        self.raw = []           # (qualname, op, lexically in a tx)

    def _scope(self, node):
        self.stack.append(node.name)
        saved, self.tx_depth = self.tx_depth, 0
        self.generic_visit(node)
        self.tx_depth = saved
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

    def visit_With(self, node):
        tx = any(_is_tx(i) for i in node.items)
        for i in node.items:
            self.visit(i)
        self.tx_depth += tx
        for stmt in node.body:
            self.visit(stmt)
        self.tx_depth -= tx

    def visit_Call(self, node):
        where = ".".join(self.stack) or "<module>"
        callee = node.func.attr if isinstance(node.func, ast.Attribute) else \
            node.func.id if isinstance(node.func, ast.Name) else None
        if callee:
            self.calls.setdefault(callee, []).append((where, self.tx_depth > 0))
        op = _op(node)
        if op:
            self.raw.append((where, op, self.tx_depth > 0))
        self.generic_visit(node)


def _covered(calls, defined):
    """Functions whose every call site in the module is inside a tx block, or inside a covered function
    (fixpoint). A function with no call site in the module is not covered (its callers are unknown)."""
    covered = set()
    changed = True
    while changed:
        changed = False
        for qual in defined:
            short = qual.rsplit(".", 1)[-1]
            sites = calls.get(short, [])
            if qual not in covered and sites and all(in_tx or caller in covered for caller, in_tx in sites):
                covered.add(qual)
                changed = True
    return covered


def inventory(source, module):
    """{(module, function qualname, op): count} for every durable-write call site in `source`. A SQL write is
    tagged '@tx' when it is lexically inside a `with ... .tx():` block, and '@caller-tx' when its function is only
    ever called from inside one (transitively, by short name within the module): either way it is durable only at
    that transaction's COMMIT seam. Everything else is untagged and must be listed with a seam or a reason."""
    walker = _Walker(module)
    tree = ast.parse(source)
    walker.visit(tree)
    defined = {q for q, _, _ in walker.raw} | {q for sites in walker.calls.values() for q, _ in sites}
    covered = _covered(walker.calls, defined)
    sites = Counter()
    for where, op, in_tx in walker.raw:
        sql_write = op.startswith("sql:") and op not in ("sql:COMMIT", "sql:commit()")
        tag = "@tx" if sql_write and in_tx else "@caller-tx" if sql_write and where in covered else ""
        sites[(module, where, op + tag)] += 1
    return dict(sites)


def seam_calls(source):
    """{(seam name, 'before'|'after'): count} of literal crash_before/crash_after calls in `source`."""
    out = Counter()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
                node.func.id in ("crash_before", "crash_after") and node.args and \
                isinstance(node.args[0], ast.Constant):
            out[(node.args[0].value, node.func.id.split("_")[1])] += 1
    return dict(out)


# Every durable-write site of the two modules that is not a SQL write inside a transaction, with its disposition:
# "seam:<name>" (crash points before and after it), or "exempt:<reason>". SQL writes tagged @tx / @caller-tx are
# covered by their module's commit seam (TX_SEAM) and are checked by count, not listed one by one.
TX_SEAM = {"ahc_contracts": "contracts.commit", "ahc_runner": "runner.commit"}
_DIR = "exempt:directory creation, idempotent, before the seam; no state"
_MIG = "exempt:a MIGRATIONS step, run only inside Ledger._schema's transaction; durable at runner.commit"
INVENTORY = {
    ("ahc_contracts", "AuthorityLog.append", "os.open(write)"): (1, "seam:contracts.authority"),
    ("ahc_contracts", "AuthorityLog.append", "os.write"): (1, "seam:contracts.authority"),
    ("ahc_contracts", "AuthorityLog.append", "os.fsync"): (1, "seam:contracts.authority"),
    ("ahc_contracts", "AuthorityLog.append", "os.makedirs"): (1, _DIR),
    ("ahc_contracts", "Contracts.tx", "sql:COMMIT"): (1, "seam:contracts.commit"),
    ("ahc_contracts", "Contracts.set_merging.write", "sql:INSERT"): (
        1, "exempt:runs only inside a transaction: set_merging's own `with self.tx()`, or a caller's when "
           "_in_tx=True (late_apply and watch_confirm, both inside tx bodies); durable at contracts.commit"),
    ("ahc_contracts", "apply_schema", "sql:DYNAMIC"): (
        1, "exempt:idempotent DDL (CREATE ... IF NOT EXISTS, INSERT OR IGNORE), re-run at every open; no data"),
    # connect_nofollow (PR 258 v1 BLOCK) is the one sqlite open for the ledger, its pre-migration backup and the
    # reopen after a restore: the file is opened or created by an O_NOFOLLOW descriptor and fchmod'ed first.
    ("ahc_runner", "connect_nofollow", "sqlite3.connect"): (
        1, "exempt:opens or creates a database file (ledger: first rows commit at runner.commit; backup: inside the "
           "runner.backup seam; restore reopen: after the runner.restore_copy seam)"),
    ("ahc_runner", "Ledger.__init__", "sql:PRAGMA"): (
        2, "exempt:connection settings (journal_mode=WAL, synchronous=FULL), re-applied at every open"),
    ("ahc_runner", "Ledger._schema", "sqlite.backup"): (1, "exempt:a call to Ledger.backup (seam runner.backup)"),
    ("ahc_runner", "Ledger.backup", "sqlite.backup"): (1, "seam:runner.backup"),
    ("ahc_runner", "Ledger.restore", "handle.write"): (1, "seam:runner.restore_intent"),
    ("ahc_runner", "Ledger.restore", "os.fsync"): (1, "seam:runner.restore_intent"),
    ("ahc_runner", "Ledger.restore", "os.replace"): (1, "seam:runner.restore_intent"),
    ("ahc_runner", "Ledger._finish_restore", "os.rename"): (1, "seam:runner.restore_move"),
    ("ahc_runner", "Ledger._finish_restore", "handle.write"): (1, "seam:runner.restore_copy"),
    ("ahc_runner", "Ledger._finish_restore", "os.fsync"): (1, "seam:runner.restore_copy"),
    ("ahc_runner", "Ledger._finish_restore", "os.replace"): (1, "seam:runner.restore_copy"),
    ("ahc_runner", "Ledger._finish_restore", "os.unlink"): (1, "seam:runner.restore_copy"),
    ("ahc_runner", "_Tx.__exit__", "sql:COMMIT"): (1, "seam:runner.commit"),
    ("ahc_runner", "_migrate_v2", "sql:ALTER"): (1, _MIG),
    ("ahc_runner", "_migrate_v2", "sql:UPDATE"): (1, _MIG),
    ("ahc_runner", "_migrate_v3", "sql:ALTER"): (1, _MIG),
    ("ahc_runner", "_migrate_v3", "sql:DYNAMIC"): (1, _MIG),
    ("ahc_runner", "_migrate_v4", "sql:ALTER"): (1, _MIG),
    ("ahc_runner", "_migrate_v4", "sql:DROP"): (1, _MIG),
    ("ahc_runner", "_migrate_v4", "sql:DYNAMIC"): (1, _MIG),
    ("ahc_runner", "Worker.prune_packets", "os.unlink"): (1, "seam:runner.prune"),
    ("ahc_runner", "_append_private", "handle.write"): (1, "seam:runner.append_private"),
    ("ahc_runner", "_append_private", "os.fsync"): (1, "seam:runner.append_private"),
    ("ahc_runner", "_append_private", "path.mkdir"): (1, _DIR),
    ("ahc_runner", "_write_private", "handle.write"): (1, "seam:runner.write_private"),
    ("ahc_runner", "_write_private", "os.fsync"): (1, "seam:runner.write_private"),
    ("ahc_runner", "_write_private", "os.replace"): (1, "seam:runner.write_private"),
    ("ahc_runner", "_write_private", "path.mkdir"): (1, _DIR),
    ("ahc_runner", "_write_inbox", "os.open(write)"): (1, "seam:runner.inbox"),
    ("ahc_runner", "_write_inbox", "handle.write"): (1, "seam:runner.inbox"),
    ("ahc_runner", "_write_inbox", "os.fsync"): (1, "seam:runner.inbox"),
    ("ahc_runner", "_write_inbox", "os.rename"): (1, "seam:runner.inbox"),
    ("ahc_runner", "_write_inbox", "os.unlink"): (
        1, "exempt:removes a stale temp file before the write; never the notice itself"),
    ("ahc_runner", "_write_inbox", "os.mkdir"): (1, _DIR),
    ("ahc_runner", "stage_packet", "os.open(write)"): (1, "seam:runner.stage_packet"),
    ("ahc_runner", "stage_packet", "handle.write"): (1, "seam:runner.stage_packet"),
    ("ahc_runner", "stage_packet", "os.fsync"): (1, "seam:runner.stage_packet"),
    ("ahc_runner", "stage_packet", "path.mkdir"): (1, _DIR),
    ("ahc_runner", "stage_packet", "os.chmod"): (1, "exempt:permission metadata on the staging directory"),
    ("ahc_runner", "_quarantine", "os.rename"): (1, "seam:runner.quarantine"),
    ("ahc_runner", "_quarantine", "path.mkdir"): (1, _DIR),
    ("ahc_runner", "_setup_logging", "path.mkdir"): (1, "exempt:the log directory; logs are not ledger state"),
}


def check_inventory(found):
    """Problems comparing an inventory() result with INVENTORY: unlisted sites, changed counts, stale entries and
    dispositions naming no registered seam or no reason. Empty when the code matches."""
    problems = []
    for key, n in sorted(found.items()):
        if key[2].endswith(("@tx", "@caller-tx")):
            continue                                   # covered by TX_SEAM[module]
        if key not in INVENTORY:
            problems.append("unlisted durable write %s x%d" % ("/".join(key), n))
        elif INVENTORY[key][0] != n:
            problems.append("count changed for %s: listed %d, found %d" % ("/".join(key), INVENTORY[key][0], n))
    modules = {k[0] for k in found}
    for key, (n, disposition) in sorted(INVENTORY.items()):
        if key[0] in modules and key not in found:
            problems.append("stale inventory entry %s" % "/".join(key))
        kind, _, detail = disposition.partition(":")
        if kind == "seam" and detail not in SEAMS:
            problems.append("%s names no registered seam %r" % ("/".join(key), detail))
        if kind not in ("seam", "exempt") or not detail:
            problems.append("%s has no seam or reason" % "/".join(key))
    return problems
