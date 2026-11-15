"""Failing-first controls for ahc's root ownership (goodqa#16049 slice 1; PR 258 and its v1 BLOCK repair).

Each variant applies an exact, unique text swap to one source file, runs the root tests, and restores the source
from a `.vs.bak` copy in `finally`. Every variant must make the tests fail; the summary names any that did not.
Run from the repo root: `python3 -B tests/variants/ahc_root_variants.py [output-file]`. It mutates tracked files
while it runs, so do not commit or run other suites at the same time. Not collected by unittest (no test_ prefix).
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, ".ahc-local", "variants_root.out")
SRC = "harness/hooks/ahc_core.py"
RUNNER = "harness/hooks/ahc_runner.py"
T = ["tests.test_ahc_core.RootOwnershipTests", "tests.test_ahc_clone.CloneLinkTests"]
V = [
    ("the root ownership check dropped (ensure only makes directories)", [
        ("    def ensure(self):\n        self.claim_root()\n", "    def ensure(self):\n        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)\n")]),
    ("root back at ~/.agent-harness/coordinator", [
        ('ROOT_DIRNAME = "ahc"\n', 'ROOT_DIRNAME = "coordinator"\n')]),
    ("an unmarked non-empty root is claimed", [
        ("            if others:\n                raise ForeignRoot", "            if False:\n                raise ForeignRoot")]),
    ("no foreign-entry check inside a marked root", [
        ("        foreign = [name for name in os.listdir(str(root)) if not _ahc_root_name(name)]\n",
         "        foreign = []\n")]),
    ("marker content not verified", [("        self._verify_marker()\n", "")]),
    ("symlinked root followed", [
        ("        info = os.lstat(str(root))\n", "        info = os.stat(str(root))\n")]),
    # Since the v1 BLOCK repair a symlinked marker is caught by two layers: the O_NOFOLLOW open in _verify_marker
    # and the lstat type check of every top-level entry. Dropping only one leaves the other (a run on the repair
    # showed the O_NOFOLLOW-only variant surviving), so this variant drops both.
    ("symlinked marker accepted (marker opened following links and exempt from the type check)", [
        ('            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))\n',
         '            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))\n'),
        ("            problem = _entry_problem(root / name, name in ROOT_DIRS)\n",
         "            problem = None if name == ROOT_MARKER else _entry_problem(root / name, name in ROOT_DIRS)\n")]),
    ("an interrupted claim's temp marker is not tolerated", [
        ("            others = [name for name in entries if not fnmatch.fnmatchcase(name, ROOT_MARKER_TEMP)]\n",
         "            others = list(entries)\n")]),
    ("the marker is written in place (no temp and link)", [
        ('        temp = root / (".ahc-root.%d.%d.tmp" % (os.getpid(), time.time_ns()))\n',
         "        temp = root / ROOT_MARKER\n"),
        ("            try:\n                os.link(str(temp), str(root / ROOT_MARKER))\n"
         "            except FileExistsError:\n                pass                                   # a concurrent claim won; its marker is verified next\n"
         "        finally:\n            os.unlink(str(temp))\n",
         "        finally:\n            pass\n")]),
    ("main does not claim the root before the subcommand (foreign root crashes or restarts)", [
        ("        paths.claim_root()        # before reading anything under the root, for every subcommand\n",
         "        pass\n")], "harness/hooks/ahc_runner.py"),
    # PR 258 v1 BLOCK repair (a marked root checked by name only)
    ("v1 BLOCK: top-level entries checked by name only (no lstat type check)", [
        ("            problem = _entry_problem(root / name, name in ROOT_DIRS)\n", "            problem = None\n")]),
    ("v1 BLOCK: entry check follows links (stat, not lstat)", [
        ("        info = os.lstat(str(path))\n    except FileNotFoundError:\n        return None\n",
         "        info = os.stat(str(path))\n    except FileNotFoundError:\n        return None\n")]),
    ("v1 BLOCK: state directories not walked (no nested check)", [
        ("                bad.extend(_tree_problems(root / name, clones=(name == \"clones\")))\n",
         "                pass\n")]),
    ("v1 BLOCK: no strict tree (items/ and clones/ contents unchecked)", [
        ('STRICT_TREES = frozenset(("items", "clones"))\n', "STRICT_TREES = frozenset()\n")]),
    ("v1 BLOCK: shared directories walked strictly (a submitter's link halts ahc)", [
        ('STRICT_TREES = frozenset(("items", "clones"))\n', "STRICT_TREES = ROOT_DIRS\n")]),
    ("v1 BLOCK: a clone's .git not checked", [
        ("            for path, want_dir in ((directory / name, True), (directory / name / \".git\", True)):\n",
         "            for path, want_dir in ((directory / name, True),):\n")]),
    ("v1 BLOCK: ledger opened by plain sqlite3.connect (no nofollow descriptor, no inode compare)", [
        ("        self.db = connect_nofollow(self.path, timeout=30, isolation_level=None)\n        self.db.row_factory"
         " = sqlite3.Row\n        try:\n            self.db.execute(\"PRAGMA journal_mode=WAL\")\n",
         "        self.db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)\n        self.db.row_factory"
         " = sqlite3.Row\n        try:\n            self.db.execute(\"PRAGMA journal_mode=WAL\")\n")], RUNNER),
    ("v1 BLOCK: no device/inode compare after sqlite opens", [
        ("        if after is None or stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != (info.st_dev, "
         "info.st_ino):\n", "        if False:\n")], RUNNER),
    ("v1 BLOCK: clone prepare follows a linked clone directory", [
        ("    for real in (Path(root), path, path / \".git\"):     # git must never write through a link (PR 258 v1 "
         "BLOCK)\n", "    for real in ():\n")], "harness/hooks/ahc_clone.py"),
]
out, survivors = [], []
for entry in V:
    name, swaps = entry[0], entry[1]
    src = os.path.join(ROOT, entry[2] if len(entry) > 2 else SRC)
    bak = src + ".vs.bak"
    shutil.copyfile(src, bak)
    try:
        text = open(bak).read()
        for old, new in swaps:
            if text.count(old) != 1:
                sys.exit("anchor not unique for %s (%d): %r" % (name, text.count(old), old[:70]))
            text = text.replace(old, new)
        open(src, "w").write(text)
        proc = subprocess.run([sys.executable, "-B", "-m", "unittest"] + T, cwd=ROOT, capture_output=True, text=True,
                              timeout=600)
        lines = [l for l in proc.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED", "OK"))]
        out.append("== variant %s rc=%d\n%s" % (name, proc.returncode, "\n".join(lines)))
        if proc.returncode == 0:
            survivors.append(name)
    finally:
        shutil.copyfile(bak, src)
        os.remove(bak)
out.append("SUMMARY: %d variants, %d did not fail: %s" % (len(V), len(survivors), survivors))
open(OUT, "w").write("\n".join(out) + "\n")
print("\n".join(out))
