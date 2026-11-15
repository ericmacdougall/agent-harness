"""Failing-first controls for ahc's root ownership (goodqa#16049 slice 1; PR 258 v1, v2 and v3 repairs).

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
FS = "harness/hooks/ahc_fs.py"
CLONE = "harness/hooks/ahc_clone.py"
T = ["tests.test_ahc_core.RootOwnershipTests", "tests.test_ahc_clone", "tests.test_ahc_fs",
     "tests.test_ahc_runner.IngestValidationTests",
     "tests.test_ahc_runner.UntrustedReadTests", "tests.test_ahc_runner.FileTransportOptInTests",
     "tests.test_ahc_runner.SchemaTests"]
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
    # A symlinked root is caught by two layers since PR 258 v3 (the lstat type check and the O_NOFOLLOW descriptor
    # check of fs.open_root in claim_root), so this variant drops both.
    ("symlinked root followed (lstat and the descriptor check both dropped)", [
        ("        info = os.lstat(str(root))\n", "        info = os.stat(str(root))\n"),
        ("            os.close(fs.open_root(root))              # owned by this uid, mode exactly 0700, existing or new\n",
         "            pass\n")]),
    # A symlinked marker is caught by two layers (the O_NOFOLLOW open in _verify_marker and the lstat type check of
    # every top-level entry), so this variant drops both.
    ("symlinked marker accepted (marker opened following links and exempt from the type check)", [
        ('            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))\n',
         '            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))\n'),
        ("            problem = _entry_problem(root / name, name in ROOT_DIRS)\n",
         "            problem = None if name == ROOT_MARKER else _entry_problem(root / name, name in ROOT_DIRS)\n")]),
    ("an interrupted claim's temp marker is not tolerated", [
        ("            others = [name for name in entries if not fnmatch.fnmatchcase(name, ROOT_MARKER_TEMP)]\n",
         "            others = list(entries)\n")]),
    ("the marker is written in place by path (no temp, no descriptor-relative link)", [
        ("            fs.write_file(self.root, self.root / ROOT_MARKER, ROOT_MARKER_TEXT, exclusive=True)\n",
         "            fd = os.open(str(self.root / ROOT_MARKER), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
         "            os.write(fd, ROOT_MARKER_TEXT.encode())\n            os.close(fd)\n")]),
    ("main does not claim the root before the subcommand (foreign root crashes or restarts)", [
        ("        paths.claim_root()        # before reading anything under the root, for every subcommand\n",
         "        pass\n")], RUNNER),
    # PR 258 v1 BLOCK repair (a marked root checked by name only)
    ("v1: top-level entries checked by name only (no lstat type check)", [
        ("            problem = _entry_problem(root / name, name in ROOT_DIRS)\n", "            problem = None\n")]),
    ("v1: entry check follows links (stat, not lstat)", [
        ("        info = os.lstat(str(path))\n    except FileNotFoundError:\n        return None\n",
         "        info = os.stat(str(path))\n    except FileNotFoundError:\n        return None\n")]),
    ("v1: state directories not walked (no nested check)", [
        ("                bad.extend(_tree_problems(root / name, clones=(name == \"clones\")))\n",
         "                pass\n")]),
    ("v1: no strict tree (items/ and clones/ contents unchecked)", [
        ('STRICT_TREES = frozenset(("items", "clones"))\n', "STRICT_TREES = frozenset()\n")]),
    ("v1: shared directories walked strictly (a submitter's link halts ahc)", [
        ('STRICT_TREES = frozenset(("items", "clones"))\n', "STRICT_TREES = ROOT_DIRS\n")]),
    ("v1: a clone's .git not checked at start", [
        ("            for path, want_dir in ((directory / name, True), (directory / name / \".git\", True)):\n",
         "            for path, want_dir in ((directory / name, True),):\n")]),
    ("v1: ledger opened by plain sqlite3.connect (no nofollow descriptor, no inode compare)", [
        ("        self.db = connect_nofollow(self.paths.root, self.path, timeout=30, isolation_level=None)\n"
         "        self.db.row_factory = sqlite3.Row\n        try:\n            self.db.execute(\"PRAGMA journal_mode=WAL\")\n",
         "        self.db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)\n"
         "        self.db.row_factory = sqlite3.Row\n        try:\n            self.db.execute(\"PRAGMA journal_mode=WAL\")\n")],
     RUNNER),
    ("v1: no device/inode compare after sqlite opens", [
        ("        if after is None or stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != (info.st_dev, "
         "info.st_ino):\n", "        if False:\n")], RUNNER),
    # PR 258 v2: the shared directories are checked per operation
    ("v2: a taken report name in a shared dir is not refused at its operation", [
        ("            report_dir_id = list(fs.make_fresh_dir(self.paths.root, report_dir, reuse_empty=True))\n",
         "            report_dir_id = [0, 0]\n")], RUNNER),
    # PR 258 v3 F2: owner and mode of the root and every ahc directory; ancestors
    ("v3 F2: a directory's mode is not checked", [
        ('    if stat.S_IMODE(info.st_mode) != DIR_MODE:\n        return "mode %04o, not 0700" % stat.S_IMODE(info.st_mode)\n',
         "")], FS),
    ("v3 F2: a directory's owner is not checked", [
        ('    if info.st_uid != _uid():\n        return "owned by uid %d, not %d" % (info.st_uid, _uid())\n', "")], FS),
    ("v3 F2: claim_root does not check the root's descriptor (owner, mode)", [
        ("            os.close(fs.open_root(root))              # owned by this uid, mode exactly 0700, existing or new\n",
         "            pass\n")]),
    ("v3 F2: ancestors other users can change are not refused", [
        ("        loose = fs.ancestor_problems(root)\n", "        loose = []\n")]),
    ("v3 F2: a foreign-owned file at an ahc name is accepted", [
        ('    if info.st_uid != os.geteuid():\n        return "owned by uid %d" % info.st_uid\n', "")]),
    # PR 258 v3 F1 class: every write under the root through ahc_fs
    ("v3 F1: temp files are opened without O_EXCL|O_NOFOLLOW (truncating, following a link)", [
        ("    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | NONBLOCK, mode, dir_fd=dfd)\n",
         "    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | NONBLOCK, mode, dir_fd=dfd)\n")], FS),
    ("v3 F1: temp names are predictable", [
        ('    return "%s%s.%s.tmp" % ("" if name.startswith(".") else ".", name, secrets.token_hex(8))\n',
         '    return "%s%s.tmp" % ("" if name.startswith(".") else ".", name)\n')], FS),
    ("v3 F1: the directory walk follows links", [
        ("            nxt = os.open(name, DIR_FLAGS, dir_fd=fd)\n",
         "            nxt = os.open(name, os.O_RDONLY, dir_fd=fd)\n")], FS),
    ("v3 F1: the clone config is written by path again (old _canonical_config)", [
        ('    fs.write_file(ahc_root, Path(path) / ".git" / "config", canonical_config_text(url))\n',
         '    tmp = Path(path) / ".git" / "config.ahc-tmp"\n    tmp.write_text(canonical_config_text(url))\n'
         '    os.chmod(tmp, 0o600)\n    os.replace(tmp, Path(path) / ".git" / "config")\n')], CLONE),
    # PR 258 v3: the reused clone (D4 ruling): allowlist walk, bounds, quarantine, rewrite, hardened git
    ("v3 clone: the .git allowlist is not applied", [
        ("            if not _allowed(rel, is_dir):\n", "            if False:\n")], CLONE),
    # A link is refused by name (S_ISLNK) and again as "not a directory or regular file", so this drops both.
    ("v3 clone: a link inside .git is accepted (both the link and the special-file checks dropped)", [
        ('            if stat.S_ISLNK(info.st_mode):\n                return "%s is a symlink" % where\n', ""),
        ("            if not is_dir and not stat.S_ISREG(info.st_mode):\n",
         "            if not is_dir and not stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):\n")], CLONE),
    ("v3 clone: a foreign-owned entry inside .git is accepted", [
        ('            if info.st_uid != uid:\n                return "%s is owned by uid %d" % (where, info.st_uid)\n',
         "")], CLONE),
    ("v3 clone: the entry bound is not enforced", [
        ("            if count > max_entries:\n", "            if False:\n")], CLONE),
    ("v3 clone: the depth bound is not enforced", [
        ("            if len(rel) > max_depth:\n", "            if False:\n")], CLONE),
    ("v3 clone: the config is not rewritten (old lines survive)", [
        ("            _canonical_config(ahc_root, path, url)\n", "            pass\n")], CLONE),
    ("v3 clone: git runs with system and global config", [
        ('GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}\n',
         "GIT_ENV = {}\n")], CLONE),
    ("v3 clone: git runs under the inherited umask", [
        ("    old_umask = os.umask(0o077)\n", "    old_umask = os.umask(0o022)\n")], CLONE),
    ("v3 clone: the clone directory is not checked to be private", [
        ("                with fs.directory(ahc_root, path):          # the clone directory itself: ours, 0700, not a link\n",
         "                with open(os.devnull):\n")], CLONE),
    ("v3 clone: every transport allowed", [
        ('        "-c", "core.logAllRefUpdates=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",\n',
         '        "-c", "core.logAllRefUpdates=false", "-c", "protocol.allow=always",\n')], CLONE),
    # PR 258 v3: the review report is read only through the attempt directory ahc created
    ("v3 report: the attempt directory's inode is not compared", [
        ("                if [info.st_dev, info.st_ino] != list(want):\n", "                if False:\n")], RUNNER),
    # Spec owner's conditions on the report-directory deviation
    ("v3 report: entries beside the report are allowed", [
        ("                if names != [report.name]:\n", "                if report.name not in names:\n")], RUNNER),
    ("v3 report: a hard-linked report is accepted", [
        ("                if entry.st_nlink != 1:\n", "                if False:\n")], RUNNER),
    ("v3 report: the size cap is not checked before the read", [
        ("                if entry.st_size > core.REPORT_MAX_BYTES:\n", "                if False:\n"),
        ("                    return core.read_regular(report.name, core.REPORT_MAX_BYTES, dir_fd=dfd), None\n",
         "                    return core.read_regular(report.name, 1 << 40, dir_fd=dfd), None\n")], RUNNER),
    ("v3 report: a failed attempt directory is not quarantined", [
        ("            moved = _quarantine_report_dir(self.paths, Path(str(data.get(\"report\"))).parent, problem)\n",
         "            moved = None\n")], RUNNER),
    ("v3 clone: the file transport opt-in is honoured for the production root", [
        ("        if allow_file and file_transport_refused(self.paths):\n", "        if False:\n")], RUNNER),
    # PR 258 v4 F1: the restore streams the backup and never moves the live database aside before the copy
    ("v4 restore: the copy reads the whole backup at once", [
        ("                    block = os.read(ifd, chunk)\n", "                    block = os.read(ifd, max_bytes + 1)\n")],
     FS),
    ("v4 restore: the live database is moved aside before the copy", [
        ("        fs.remove_temps(self.paths.root, self.path)                 # an earlier attempt's unpublished copy\n",
         "        for extra in (\"\", \"-wal\", \"-shm\"):\n"
         "            if os.path.lexists(str(self.path) + extra):\n"
         "                fs.rename(self.paths.root, Path(str(self.path) + extra), Path(str(self.path) + suffix + extra))\n"
         "        fs.remove_temps(self.paths.root, self.path)\n")], RUNNER),
    ("v4 restore: the intent is kept after a copy failure with the live file in place", [
        ("                fs.unlink(self.paths.root, self._intent_path(), missing_ok=True)\n", "                pass\n")],
     RUNNER),
    ("v4 restore: no size check before the migration", [
        ("        if size > RESTORE_MAX_BYTES:\n", "        if False:\n")], RUNNER),
    ("v4 restore: an interrupted copy's partial temp is not removed", [
        ("        fs.remove_temps(self.paths.root, self.path)                 # an earlier attempt's unpublished copy\n",
         "        pass\n")], RUNNER),
    ("v4 fs: copy_to_temp enforces no cap (both the descriptor and the running checks dropped)", [
        ("            if info.st_size > max_bytes:\n", "            if False:\n"),
        ("                    if total > max_bytes:\n", "                    if False:\n")], FS),
    ("v4 fs: remove_temps matches any name", [
        ("            if pattern.match(entry):\n", "            if entry.endswith(\".tmp\"):\n")], FS),
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
        try:
            proc = subprocess.run([sys.executable, "-B", "-m", "unittest"] + T, cwd=ROOT, capture_output=True,
                                  text=True, timeout=900)
        except subprocess.TimeoutExpired:   # a hang is recorded and the run goes on; it is not a survivor
            out.append("== variant %s rc=timeout (tests did not finish in 900 s)" % name)
            continue
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
