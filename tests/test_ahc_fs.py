"""ahc writes under its root only through ahc_fs (goodqa#16049, PR 258 v3 class fix).

PathWriteScanTests walks the syntax tree of every ahc module and fails on any path-based write outside ahc_fs.
That covers a write by file name, a chmod by name, a rename or link by name, a mkdir, a path-opened write
descriptor, a temp file, a sqlite open and a file log handler. The only exceptions are the sites in ALLOWED, each
with its reason: they write outside the root, or they are the one sqlite open that ahc_fs pre-opens and the
connect_nofollow inode compare binds. The scanner does not import ahc_fs, so it runs against any revision.

RootFsTests pins ahc_fs itself (imported lazily). It checks link refusal at every level, the owner and mode
checks, unpredictable O_EXCL temp names and descriptor-relative rename.
"""
import ast
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
MODULES = ("ahc_core", "ahc_runner", "ahc_contracts", "ahc_clone", "ahc_install", "ahc_packet", "ahc_scan",
           "ahc_crash")
OS_WRITES = {"chmod", "lchmod", "chown", "lchown", "replace", "rename", "renames", "link", "symlink", "unlink",
             "remove", "rmdir", "removedirs", "mkdir", "makedirs", "mkfifo", "mknod", "truncate", "utime"}
SHUTIL_WRITES = {"copy", "copy2", "copyfile", "copytree", "move", "rmtree", "copymode", "copystat", "chown"}
TEMPFILE_WRITES = {"mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile",
                   "TemporaryDirectory"}
PATH_WRITES = {"write_text", "write_bytes", "touch", "mkdir", "chmod", "lchmod", "unlink", "rename", "symlink_to",
               "hardlink_to", "link_to", "rmdir"}
WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"}
LOG_HANDLERS = {"FileHandler", "RotatingFileHandler", "TimedRotatingFileHandler", "WatchedFileHandler"}

# (module, function qualname, op): reason. A site here writes OUTSIDE the ahc root, or is the sqlite open that
# connect_nofollow binds to an ahc_fs descriptor. Anything under the root must use ahc_fs instead.
ALLOWED = {
    ("ahc_core", "Paths.claim_root", "path.mkdir"): (
        "creates the root's parent (~/.agent-harness), which is outside the root; ancestor_problems then refuses "
        "an ancestor another user can change"),
    ("ahc_core", "Paths.claim_root", "os.mkdir"): (
        "creates the root directory itself, exclusively, at 0700; ahc_fs.open_root then checks the descriptor "
        "(this uid, mode 0700, not a link) before anything is written inside it"),
    ("ahc_runner", "connect_nofollow", "sqlite3.connect"): (
        "sqlite takes only a path. The file was opened or created first through ahc_fs.open_file, and the path's "
        "dev and inode are compared with that descriptor right after the connect, before any statement"),
    ("ahc_runner", "_setup_logging", "path.mkdir"): "~/.agent-harness/logs: outside the root",
    ("ahc_runner", "_setup_logging", "logging.RotatingFileHandler"): "~/.agent-harness/logs/ahc.log: outside the root",
    ("ahc_contracts", "AuthorityLog.append", "os.makedirs"): (
        "the authority log's own directory, given by its caller (no production caller is wired yet); the append "
        "goes through ahc_fs with that directory as its root, so it must be ours at 0700"),
    ("ahc_install", "_write_private", "path.mkdir"): "systemd user unit or ~/.local/bin wrapper: outside the root",
    ("ahc_install", "_write_private", "os.open(write)"): "systemd user unit or ~/.local/bin wrapper: outside the root",
    ("ahc_install", "_write_private", "os.chmod"): "systemd user unit or ~/.local/bin wrapper: outside the root",
    ("ahc_install", "_write_private", "os.replace"): "systemd user unit or ~/.local/bin wrapper: outside the root",
    ("ahc_install", "install", "shutil.copy2"): "copies an existing systemd unit aside: outside the root",
    ("ahc_install", "uninstall", "path.unlink"): "removes a systemd unit or the ~/.local/bin wrapper: outside the root",
    ("ahc_packet", "main", "path.write_text"): "the packet CLI's --output, a path the caller names: not ahc state",
    ("ahc_crash", "_seam", "open(write)"): (
        "the crash-harness counting file named by an environment variable, honoured only under unittest with the "
        "test flag set; never reached in production"),
}


def _names(node):
    return {n.id if isinstance(n, ast.Name) else n.attr for n in ast.walk(node)
            if isinstance(n, (ast.Name, ast.Attribute))}


class _Scanner(ast.NodeVisitor):
    def __init__(self, module):
        self.module, self.stack, self.found = module, [], []
        self.assigned = [{}]

    def _scope(self, node):
        self.stack.append(node.name)
        self.assigned.append({})
        self.generic_visit(node)
        self.assigned.pop()
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assigned[-1].setdefault(target.id, []).append(node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            self.assigned[-1].setdefault(node.target.id, []).append(node.value)
        self.generic_visit(node)

    def _flag_names(self, expr):
        names = _names(expr)
        for name in list(names):
            for scope in self.assigned:
                for value in scope.get(name, []):
                    names |= _names(value)
        return names

    def _op(self, call):
        f = call.func
        if isinstance(f, ast.Attribute):
            owner = f.value.id if isinstance(f.value, ast.Name) else None
            if owner == "os":
                if f.attr == "open":
                    flags = call.args[1] if len(call.args) > 1 else None
                    return "os.open(write)" if flags is not None and self._flag_names(flags) & WRITE_FLAGS else None
                return "os." + f.attr if f.attr in OS_WRITES else None
            if owner == "shutil":
                return "shutil." + f.attr if f.attr in SHUTIL_WRITES else None
            if owner == "tempfile":
                return "tempfile." + f.attr if f.attr in TEMPFILE_WRITES else None
            if owner == "sqlite3" and f.attr == "connect":
                return "sqlite3.connect"
            if f.attr in LOG_HANDLERS:
                return "logging." + f.attr
            if owner in ("fs", "re", "str", "self") and f.attr in ("replace",):
                return None
            if f.attr in PATH_WRITES and owner not in ("fs",):
                return "path." + f.attr
            if f.attr == "replace" and len(call.args) == 1 and not call.keywords:
                return "path.replace"              # Path.replace(target); str.replace takes two arguments
        if isinstance(f, ast.Name) and f.id == "open":
            mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"),
                                                                None)
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax+"):
                return "open(write)"
            if mode is not None and not isinstance(mode, ast.Constant):
                return "open(dynamic)"
        return None

    def visit_Call(self, node):
        op = self._op(node)
        if op:
            self.found.append((self.module, ".".join(self.stack) or "<module>", op, node.lineno))
        self.generic_visit(node)


def path_writes(source, module):
    scanner = _Scanner(module)
    scanner.visit(ast.parse(source))
    return scanner.found


def scan_all():
    out = []
    for module in MODULES:
        path = HOOKS / ("%s.py" % module)
        if path.exists():
            out.extend(path_writes(path.read_text(encoding="utf-8"), module))
    return out


class PathWriteScanTests(unittest.TestCase):
    def test_no_path_based_write_under_the_root_outside_ahc_fs(self):
        found = scan_all()
        bad = ["%s.py:%d %s %s" % (m, line, where, op) for m, where, op, line in found
               if (m, where, op) not in ALLOWED]
        self.assertEqual(bad, [], "path-based writes outside ahc_fs (use ahc_fs, or allowlist a site that writes "
                                  "outside the root, with its reason)")

    def test_every_allowlisted_site_still_exists_and_has_a_reason(self):
        present = {(m, where, op) for m, where, op, _line in scan_all()}
        self.assertEqual(sorted(set(ALLOWED) - present), [], "stale allowlist entries")
        for key, reason in ALLOWED.items():
            self.assertTrue(len(reason) > 20, key)

    def test_the_scanner_catches_each_kind_of_path_write(self):
        """Non-vacuous: each banned shape, planted in a snippet, is found."""
        snippets = {
            "path.write_text": "def f(p):\n    p.write_text('x')\n",
            "os.chmod": "import os\ndef f(p):\n    os.chmod(p, 0o600)\n",
            "os.replace": "import os\ndef f(a, b):\n    os.replace(a, b)\n",
            "os.rename": "import os\ndef f(a, b):\n    os.rename(a, b, src_dir_fd=3)\n",
            "os.open(write)": "import os\ndef f(p):\n    flags = os.O_WRONLY | os.O_CREAT\n    os.open(p, flags)\n",
            "os.mkdir": "import os\ndef f(p):\n    os.mkdir(p)\n",
            "path.mkdir": "def f(p):\n    p.mkdir()\n",
            "open(write)": "def f(p):\n    open(p, 'w')\n",
            "tempfile.mkstemp": "import tempfile\ndef f():\n    tempfile.mkstemp()\n",
            "shutil.copyfile": "import shutil\ndef f(a, b):\n    shutil.copyfile(a, b)\n",
            "sqlite3.connect": "import sqlite3\ndef f(p):\n    sqlite3.connect(p)\n",
            "path.replace": "def f(p, q):\n    p.replace(q)\n",
        }
        for op, source in snippets.items():
            with self.subTest(op=op):
                self.assertIn(op, [o for _m, _w, o, _l in path_writes(source, "x")])
        reads = "import os\ndef f(p):\n    os.open(p, os.O_RDONLY)\n    p.read_text()\n    'a'.replace('a', 'b')\n"
        self.assertEqual(path_writes(reads, "x"), [], "a read or str.replace is not a write")


class RootFsTests(unittest.TestCase):
    """ahc_fs itself: nothing is ever written through a link, and only private directories of this uid are used."""

    def setUp(self):
        sys.path.insert(0, str(HOOKS))
        import ahc_fs
        self.fs = ahc_fs
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "root"
        self.root.mkdir(mode=0o700)
        self.outside = Path(self.tmp.name) / "outside"
        self.outside.write_bytes(b"external bytes\n")
        os.chmod(str(self.outside), 0o644)

    def tearDown(self):
        self.tmp.cleanup()

    def external_unchanged(self):
        self.assertEqual(self.outside.read_bytes(), b"external bytes\n")
        self.assertEqual(stat.S_IMODE(os.stat(str(self.outside)).st_mode), 0o644)

    def test_a_link_at_the_predicted_temp_name_is_never_written_through(self):
        target = self.root / "config.json"
        with mock.patch.object(self.fs.secrets, "token_hex", return_value="feedface"):
            os.symlink(str(self.outside), str(self.root / self.fs.temp_name("config.json")))
            with self.assertRaises(FileExistsError):
                self.fs.write_file(self.root, target, "ours\n")
        self.external_unchanged()
        self.assertFalse(os.path.lexists(str(target)))

    def test_temp_names_are_unpredictable(self):
        names = {self.fs.temp_name("config.json") for _ in range(50)}
        self.assertEqual(len(names), 50)
        self.assertTrue(all(n.startswith(".config.json.") and n.endswith(".tmp") for n in names))

    def test_a_link_at_the_target_name_is_replaced_as_a_name_not_followed(self):
        target = self.root / "config.json"
        os.symlink(str(self.outside), str(target))
        self.fs.write_file(self.root, target, "ours\n")
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_text(), "ours\n")
        self.assertEqual(stat.S_IMODE(os.lstat(str(target)).st_mode), 0o600)
        self.external_unchanged()

    def test_exclusive_refuses_a_taken_name_including_a_link(self):
        target = self.root / "marker"
        os.symlink(str(self.outside), str(target))
        with self.assertRaises(FileExistsError):
            self.fs.write_file(self.root, target, "ours\n", exclusive=True)
        self.assertTrue(target.is_symlink())
        self.external_unchanged()
        self.assertEqual([n for n in os.listdir(str(self.root)) if n.endswith(".tmp")], [], "temp left behind")

    def test_a_linked_directory_anywhere_on_the_way_is_refused(self):
        real = Path(self.tmp.name) / "real"
        real.mkdir(mode=0o700)
        os.symlink(str(real), str(self.root / "sub"))
        for call in (lambda: self.fs.write_file(self.root, self.root / "sub" / "x", "y"),
                     lambda: self.fs.append_file(self.root, self.root / "sub" / "x", "y"),
                     lambda: self.fs.make_dirs(self.root, self.root / "sub" / "deeper"),
                     lambda: self.fs.unlink(self.root, self.root / "sub" / "x", missing_ok=True)):
            with self.assertRaises(self.fs.UnsafePath):
                call()
        self.assertEqual(os.listdir(str(real)), [])

    def test_a_linked_root_is_refused(self):
        link = Path(self.tmp.name) / "linkroot"
        os.symlink(str(self.root), str(link))
        with self.assertRaises(self.fs.UnsafePath):
            self.fs.write_file(link, link / "x", "y")

    def test_a_loose_or_foreign_directory_is_refused(self):
        sub = self.root / "sub"
        sub.mkdir(mode=0o700)
        for mode in (0o755, 0o770, 0o777, 0o711):
            with self.subTest(mode=oct(mode)):
                os.chmod(str(sub), mode)
                with self.assertRaises(self.fs.UnsafePath):
                    self.fs.write_file(self.root, sub / "x", "y")
                self.assertEqual(os.listdir(str(sub)), [])
        os.chmod(str(sub), 0o700)
        with mock.patch.object(self.fs, "_uid", return_value=os.geteuid() + 1):
            with self.assertRaises(self.fs.UnsafePath):
                self.fs.write_file(self.root, sub / "x", "y")
        os.chmod(str(self.root), 0o755)
        with self.assertRaises(self.fs.UnsafePath):
            self.fs.write_file(self.root, self.root / "x", "y")

    def test_append_and_open_refuse_a_link_and_a_fifo(self):
        os.symlink(str(self.outside), str(self.root / "digest.md"))
        with self.assertRaises(OSError):
            self.fs.append_file(self.root, self.root / "digest.md", "line\n")
        os.mkfifo(str(self.root / "fifo"))
        with self.assertRaises(OSError):
            self.fs.append_file(self.root, self.root / "fifo", "line\n")
        self.external_unchanged()

    def test_rename_moves_a_link_as_a_link(self):
        os.symlink(str(self.outside), str(self.root / "q.json"))
        (self.root / "rejected").mkdir(mode=0o700)
        self.fs.rename(self.root, self.root / "q.json", self.root / "rejected" / "q.json")
        self.assertTrue((self.root / "rejected" / "q.json").is_symlink())
        self.external_unchanged()

    def test_paths_outside_the_root_are_refused(self):
        for path in (Path(self.tmp.name) / "x", self.root / ".." / "x", Path("/etc/x")):
            with self.subTest(path=str(path)):
                with self.assertRaises(self.fs.UnsafePath):
                    self.fs.write_file(self.root, path, "y")

    def test_make_fresh_dir_is_exclusive_and_reuses_only_an_empty_private_dir(self):
        target = self.root / "attempt"
        first = self.fs.make_fresh_dir(self.root, target)
        with self.assertRaises(FileExistsError):
            self.fs.make_fresh_dir(self.root, target)
        self.assertEqual(self.fs.make_fresh_dir(self.root, target, reuse_empty=True), first)
        (target / "report.md").write_text("x")
        with self.assertRaises(FileExistsError):
            self.fs.make_fresh_dir(self.root, target, reuse_empty=True)
        os.symlink(str(self.tmp.name), str(self.root / "linked"))
        with self.assertRaises(FileExistsError):
            self.fs.make_fresh_dir(self.root, self.root / "linked", reuse_empty=True)

    def test_copy_to_temp_streams_in_chunks_and_publishes_nothing_itself(self):
        """PR 258 v4 F1: the restore copy reads in fixed chunks, never the whole file, and leaves `dst` alone."""
        src, dst = self.root / "src.bak", self.root / "live.db"
        body = os.urandom(3 * 4096 + 17)
        src.write_bytes(body)
        dst.write_bytes(b"live\n")
        reads = []
        real_read = os.read

        def counted(fd, n):
            reads.append(n)
            return real_read(fd, n)
        with mock.patch.object(self.fs.os, "read", counted):
            staged = self.fs.copy_to_temp(self.root, src, dst, max_bytes=1 << 20, chunk=4096)
        self.assertEqual(max(reads), 4096, "a read asked for more than one chunk")
        self.assertEqual(staged.read_bytes(), body)
        self.assertEqual(stat.S_IMODE(os.stat(str(staged)).st_mode), 0o600)
        self.assertEqual(dst.read_bytes(), b"live\n", "copy_to_temp must not publish")
        self.assertRegex(staged.name, r"^\.live\.db\.[0-9a-f]{16}\.tmp$")

    def test_copy_to_temp_refuses_an_oversized_or_linked_source_and_leaves_no_temp(self):
        src, dst = self.root / "src.bak", self.root / "live.db"
        src.write_bytes(b"x" * 100)
        dst.write_bytes(b"live\n")
        with self.assertRaises(self.fs.TooLarge):
            self.fs.copy_to_temp(self.root, src, dst, max_bytes=99)
        linked = self.root / "linked.bak"
        os.symlink(str(self.outside), str(linked))
        with self.assertRaises(self.fs.UnsafePath):
            self.fs.copy_to_temp(self.root, linked, dst, max_bytes=1 << 20)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["linked.bak", "live.db", "src.bak"],
                         "a refused copy left a temp file behind")
        self.assertEqual(dst.read_bytes(), b"live\n")
        self.external_unchanged()

    def test_copy_to_temp_stops_a_source_that_grows_past_the_cap(self):
        src, dst = self.root / "src.bak", self.root / "live.db"
        src.write_bytes(b"x" * 10)
        real_read = os.read

        def growing(fd, n):
            return real_read(fd, n) or (b"y" * n)        # the file keeps producing bytes after its fstat size
        with mock.patch.object(self.fs.os, "read", growing):
            with self.assertRaises(self.fs.TooLarge):
                self.fs.copy_to_temp(self.root, src, dst, max_bytes=64, chunk=16)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["src.bak"])

    def test_remove_temps_removes_only_unpublished_temps_of_that_name(self):
        dst = self.root / "live.db"
        keep = ["live.db", "live.db-wal", ".live.db.short.tmp", ".other.0123456789abcdef.tmp"]
        gone = [".live.db.0123456789abcdef.tmp", ".live.db.fedcba9876543210.tmp"]
        for name in keep + gone:
            (self.root / name).write_bytes(b"")
        os.symlink(str(self.outside), str(self.root / ".live.db.aaaaaaaaaaaaaaaa.tmp"))
        removed = self.fs.remove_temps(self.root, dst)
        self.assertEqual(sorted(removed), sorted(gone + [".live.db.aaaaaaaaaaaaaaaa.tmp"]))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), sorted(keep))
        self.external_unchanged()

    def test_ancestor_rule(self):
        base = Path(self.tmp.name) / "anc"
        (base / "home").mkdir(parents=True, mode=0o700)
        os.chmod(str(base), 0o700)
        root = base / "home" / "ahc"
        self.assertEqual(self.fs.ancestor_problems(root), [])
        os.chmod(str(base / "home"), 0o777)
        self.assertTrue(self.fs.ancestor_problems(root), "a world-writable parent without the sticky bit")
        os.chmod(str(base / "home"), 0o1777)
        self.assertEqual(self.fs.ancestor_problems(root), [], "a sticky world-writable parent (like /tmp) is fine")
        os.chmod(str(base / "home"), 0o770)
        self.assertTrue(self.fs.ancestor_problems(root), "a group-writable parent")


if __name__ == "__main__":
    unittest.main()
