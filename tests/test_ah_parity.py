"""ah_parity: installed hooks versus canonical main (self-serve spec AC-11, AC-12, AC-13 doctor side, AC-14; NEG-11, NEG-12).

Fixtures only: a local bare repository stands in for the canonical URL, every HOME is a temp directory, and the
"remote host" is the same constant program run through a fake ssh runner under another temp HOME. No network, no ssh.
Set AH_PARITY_MUTANT_DIR to run the suite against a broken copy of the module (failing-first evidence).
"""
import atexit
import hashlib
import inspect
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.environ.get("AH_PARITY_MUTANT_DIR") or str(ROOT / "harness" / "hooks"))
import ah_parity  # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
CLAUDE_NAMES = ("ah.py", "merge_gate.py", "ah_parity.py")
CODEX_NAMES = ("ah.py", "merge_gate.py")
FILES = {"ah.py": b"print('ah')\n", "merge_gate.py": b"print('gate')\n", "ah_parity.py": b"print('parity')\n"}
EXTRA_SHIPPED = {"extra_tool.py": b"print('shipped but not installed by name')\n"}  # in the tree, in neither name list
TIP_FILES = dict(FILES, **{"ah.py": b"print('ah v2')\n"})
# What install_codex.install() writes besides DELIVERY_HELPERS: dest name -> (repository path, bytes). The Codex wal.py is
# codex/hooks/wal.py, a different file from harness/hooks/wal.py.
CODEX_ELSEWHERE = {"wal.py": ("codex/hooks/wal.py", b"print('codex wal')\n"),
                   "ops_watch.py": ("harness/hooks/ops_watch.py", b"print('ops watch')\n"),
                   "watch-tests.py": ("harness/tools/watch-tests.py", b"print('watch tests')\n")}
CODEX_ALL = CODEX_NAMES + tuple(CODEX_ELSEWHERE)
PROBE_RULE = "Bash(python3 ~/.claude/hooks/ah.py ops *)"  # the literal scripts/enable-agent-ops.py (L5) writes
DOCTOR_REPORT = json.dumps({"hosts": {"mac": {"status": "CLEAN"}}, "ok": True})


def git(cwd, *args):
    env = dict(os.environ, **GIT_ENV)
    return subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, capture_output=True, text=True, env=env).stdout.strip()


def sha1(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def synth_snapshot():
    """The canonical data without git: the tip's blobs, for tests of judge and collect alone."""
    blobs = {n: sha1(b) for n, b in dict(TIP_FILES, **EXTRA_SHIPPED).items()}
    blobs["ops_watch.py"] = sha1(CODEX_ELSEWHERE["ops_watch.py"][1])
    codex_blobs = {n: blobs[n] for n in CODEX_NAMES}
    codex_blobs.update({n: sha1(b) for n, (_, b) in CODEX_ELSEWHERE.items()})
    return {"sha": "0" * 40, "tip": "0" * 40, "claude": CLAUDE_NAMES, "codex": CODEX_ALL, "blobs": blobs,
            "codex_blobs": codex_blobs, "not_in_ref": []}


class Installed:
    """Writes an installed tree (hook files, settings.json guard registrations, Codex hooks.json and trust) with no git."""

    def __init__(self, test, files=TIP_FILES):
        self.tmp = Path(tempfile.mkdtemp(prefix="parity-home-"))
        test.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.files = files

    def install(self, home, codex=True, registrations=True):
        for rel, names in ((ah_parity.CLAUDE_DIR, CLAUDE_NAMES), (ah_parity.CODEX_DIR, CODEX_NAMES)):
            if rel == ah_parity.CODEX_DIR and not codex:
                continue  # no Codex on this host at all
            d = home.joinpath(*rel)
            d.mkdir(parents=True, exist_ok=True)
            for n in names:
                (d / n).write_bytes(self.files[n])
            if rel == ah_parity.CODEX_DIR:
                for n, (_, data) in CODEX_ELSEWHERE.items():
                    (d / n).write_bytes(data)
        if registrations:
            self.write_settings(home)
        if codex:
            self.write_codex(home)
        return home

    def write_settings(self, home, drop=(), mutate=None, extra=None):
        """settings.json with every guard the installer registers; `drop` names scripts to leave out."""
        hooks = {}
        hdir = str(home.joinpath(*ah_parity.CLAUDE_DIR))
        for event, matcher, script, args in ah_parity.GUARD_REGISTRATIONS:
            if script in drop:
                continue
            handler = {"type": "command", "command": "python3", "args": [hdir + "/" + script] + list(args), "timeout": 10,
                       "onFailure": "block"}
            if mutate:
                mutate(script, handler)
            group = {"hooks": [handler]}
            if matcher:
                group["matcher"] = matcher
            hooks.setdefault(event, []).append(group)
        data = {"hooks": hooks}
        data.update(extra or {})
        (home / ".claude").mkdir(parents=True, exist_ok=True)
        (home / ".claude" / "settings.json").write_text(json.dumps(data))

    def write_codex(self, home, extra=(), drop=()):
        """hooks.json and config.toml. Test handlers in `extra` come first as (command, state) with state one of
        trusted, changed, untrusted; the guard handlers follow, all trusted (unless dropped)."""
        hooks_path = home / ".codex" / "hooks.json"
        cdir = str(home.joinpath(*ah_parity.CODEX_DIR))
        groups, trust = [], []
        entries = [(c, s) for c, s in extra]
        for event, script in ah_parity.CODEX_GUARDS:
            if script not in drop:
                entries.append(("python3 '%s/%s' hook" % (cdir, script), "trusted"))
        for i, (cmd, state) in enumerate(entries):
            handler = {"type": "command", "command": cmd, "timeout": 5}
            groups.append({"hooks": [handler]})
            h = ah_parity.codex_hook_hash("pre_tool_use", None, handler)
            if state == "changed":
                h = "sha256:old"
            if state != "untrusted":
                trust.append('[hooks.state."%s:pre_tool_use:%d:0"]\ntrusted_hash = "%s"\n' % (hooks_path, i, h))
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        hooks_path.write_text(json.dumps({"hooks": {"PreToolUse": groups}}))
        (home / ".codex" / "config.toml").write_text("\n".join(trust))
        return hooks_path

    def claude(self, home, name):
        return home.joinpath(*ah_parity.CLAUDE_DIR, name)

    def judge(self, home, snapshot=None):
        snap = snapshot or synth_snapshot()
        return ah_parity.judge(snap, ah_parity.collect(home, snap["claude"], snap["codex"]))


_CANON = {}
_SNAPSHOTS = {}


def build_canonical(tmp, variant=None):
    """A canonical work repo and its bare clone. variant: None, 'no-hooks-dir', 'ghost-name' or 'no-codex-wal'."""
    work = tmp / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    (work / "harness" / "hooks").mkdir(parents=True)
    claude = CLAUDE_NAMES + (("ghost.py",) if variant == "ghost-name" else ())
    (work / "install.py").write_text("HOOKS = %r\n" % (claude,))
    (work / "install_codex.py").write_text("DELIVERY_HELPERS = %r\n" % (CODEX_NAMES,))
    for n, b in dict(FILES, **EXTRA_SHIPPED).items():
        (work / "harness" / "hooks" / n).write_bytes(b)
    for dest, (path, data) in CODEX_ELSEWHERE.items():
        if variant == "no-codex-wal" and dest == "wal.py":
            continue
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_bytes(data)
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "first")
    first = git(work, "rev-parse", "HEAD")
    (work / "harness" / "hooks" / "ah.py").write_bytes(TIP_FILES["ah.py"])
    git(work, "commit", "-q", "-am", "second")
    if variant == "no-hooks-dir":
        git(work, "mv", "harness/hooks", "harness/hooks-moved")
        git(work, "commit", "-q", "-am", "the hooks directory was renamed")
    second = git(work, "rev-parse", "HEAD")
    bare = tmp / "canonical.git"
    git(tmp, "clone", "-q", "--bare", str(work), str(bare))
    return {"work": work, "bare": bare, "url": "file://" + str(bare), "first": first, "second": second}


def shared_canonical():
    if "c" not in _CANON:
        tmp = Path(tempfile.mkdtemp(prefix="parity-canon-"))
        atexit.register(shutil.rmtree, str(tmp), True)
        _CANON["c"] = build_canonical(tmp)
    return _CANON["c"]


class Fixture(Installed):
    """A canonical bare repo plus an installed Claude and Codex tree under a temp HOME."""

    def __init__(self, test, variant=None, fresh=False):
        Installed.__init__(self, test, TIP_FILES)
        if variant is None and not fresh:
            canon = shared_canonical()
        else:
            canon = build_canonical(self.tmp, variant)
        self.canon = canon
        self.work, self.bare, self.url = canon["work"], canon["bare"], canon["url"]
        self.first, self.second = canon["first"], canon["second"]
        self.home = self.install(self.tmp / "home-mac")
        self.remote_home = self.install(self.tmp / "home-remote")
        ah_parity.ALLOW_FILE = True
        test.addCleanup(setattr, ah_parity, "ALLOW_FILE", False)
        # Speed: one real fetch per (ref, url) per process. Failures are never cached, so every test that expects a
        # canonical failure (empty tree, unknown name, bad ref, missing repository) still runs the real code.
        real = ah_parity.canonical_snapshot
        cache = _SNAPSHOTS

        def cached(ref=None, url=None):
            key = (ref, url)
            if key not in cache:
                cache[key] = real(ref, url)
            return cache[key]
        ah_parity.canonical_snapshot = cached
        test.addCleanup(setattr, ah_parity, "canonical_snapshot", real)

    def runner(self, home=None, rc=0, record=None):
        """A fake ssh: run the piped program with `python3 -I -` under another HOME, exactly what ssh would run."""
        home = home or self.remote_home

        def run(argv, stdin=None, timeout=None):
            if record is not None:
                record.append((list(argv), stdin))
            if rc:
                return rc, "", "Connection refused"
            assert argv[0] == "ssh" and argv[-3:] == ["python3", "-I", "-"], argv
            p = subprocess.run([sys.executable, "-I", "-"], input=stdin, capture_output=True, text=True,
                               env={"HOME": str(home), "PATH": os.environ.get("PATH", "")})
            return p.returncode, p.stdout, p.stderr
        return run

    def verify(self, hosts=("mac",), ref=None, runner=None):
        return ah_parity.verify(hosts, ref, self.home, runner or self.runner(), self.url)

    def gate(self, pinned=None, runner=None):
        return ah_parity.verify_gate(pinned, self.home, runner or self.runner(), self.url)

    def install_at(self, home, files):
        for rel, names in ((ah_parity.CLAUDE_DIR, CLAUDE_NAMES), (ah_parity.CODEX_DIR, CODEX_NAMES)):
            for n in names:
                home.joinpath(*rel, n).write_bytes(files[n])


class Drift(unittest.TestCase):
    def test_clean_mac_is_clean(self):
        f = Fixture(self)
        r = f.verify()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        self.assertEqual(r["hosts"]["mac"]["claude"]["ok"], 3)  # non-vacuous: the hooks were really compared
        self.assertEqual(r["hosts"]["mac"]["codex"]["ok"], 5)  # 2 helpers + the three files install_codex writes elsewhere
        self.assertEqual(r["ref"], f.second)
        self.assertTrue(r["ref_is_tip"])

    def test_edited_installed_hook_is_reported_ac11(self):
        f = Fixture(self)
        f.claude(f.home, "merge_gate.py").write_bytes(b"print('tampered')\n")
        r = f.verify()
        self.assertFalse(r["ok"])
        v = r["hosts"]["mac"]
        self.assertEqual(v["status"], "DRIFT")
        self.assertEqual(v["claude"]["differ"], ["merge_gate.py"])
        self.assertEqual(ah_parity.exit_code(r), 1)

    def test_missing_hook_and_symlink_are_drift(self):
        f = Fixture(self)
        f.claude(f.home, "ah_parity.py").unlink()
        gate = f.claude(f.home, "merge_gate.py")
        gate.unlink()
        gate.symlink_to(f.work / "harness" / "hooks" / "merge_gate.py")  # right bytes, but a symlink
        v = f.verify()["hosts"]["mac"]
        self.assertEqual(v["claude"]["missing"], ["ah_parity.py"])
        self.assertEqual(v["claude"]["differ"], ["merge_gate.py"])

    def test_codex_copy_is_checked_and_absent_codex_is_not_drift(self):
        f = Fixture(self)
        f.home.joinpath(*ah_parity.CODEX_DIR, "ah.py").write_bytes(b"old\n")
        self.assertEqual(f.verify()["hosts"]["mac"]["codex"]["differ"], ["ah.py"])
        f2 = Fixture(self)
        subprocess.run(["rm", "-rf", str(f2.home.joinpath(*ah_parity.CODEX_DIR))])
        v = f2.verify()["hosts"]["mac"]
        self.assertEqual(v["status"], "CLEAN")
        self.assertFalse(v["codex"]["present"])

    def test_older_ancestor_ref_compares_against_that_commit(self):
        f = Fixture(self)
        r = f.verify(ref=f.first)
        self.assertEqual(r["hosts"]["mac"]["claude"]["differ"], ["ah.py"])  # installed is v2
        self.assertFalse(r["ref_is_tip"])

    def test_ref_not_on_main_is_unknown_not_clean(self):
        f = Fixture(self, fresh=True)
        stray = git(f.work, "commit-tree", "-m", "x", f.second + "^{tree}")
        git(f.work, "update-ref", "refs/heads/stray", stray)
        git(f.bare, "fetch", "-q", str(f.work), "stray:refs/heads/stray")
        r = f.verify(ref=stray)
        self.assertFalse(r["ok"])
        self.assertEqual(r["hosts"]["mac"]["status"], "UNKNOWN")
        self.assertEqual(ah_parity.exit_code(r), 3)
        self.assertEqual(f.verify(ref="HEAD")["hosts"]["mac"]["status"], "UNKNOWN")

    def test_canonical_unavailable_is_unknown_never_clean(self):
        f = Fixture(self)
        r = ah_parity.verify(("mac",), None, f.home, f.runner(), "file://" + str(f.tmp / "nope.git"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["hosts"]["mac"]["status"], "UNKNOWN")
        self.assertEqual(ah_parity.exit_code(r), 3)


class FailOpen(unittest.TestCase):
    """Class: a comparison that compared nothing must never read as CLEAN (one validator, check_snapshot)."""

    def test_empty_canonical_tree_is_unknown_not_clean(self):
        f = Fixture(self, variant="no-hooks-dir")
        with self.assertRaises(ah_parity.ParityError):
            ah_parity.canonical_snapshot(None, f.url)
        r = f.verify()
        self.assertFalse(r["ok"], r)
        self.assertEqual(r["hosts"]["mac"]["status"], "UNKNOWN")
        self.assertEqual(ah_parity.exit_code(r), 3)
        self.assertFalse(f.gate()["ok"])

    def test_listed_name_the_commit_does_not_ship_is_unknown(self):
        f = Fixture(self, variant="ghost-name")
        with self.assertRaises(ah_parity.ParityError) as ctx:
            ah_parity.canonical_snapshot(None, f.url)
        self.assertIn("ghost.py", str(ctx.exception))
        r = f.verify()
        self.assertFalse(r["ok"], r)
        self.assertEqual(r["hosts"]["mac"]["status"], "UNKNOWN")

    def test_missing_codex_source_the_installer_copies_is_unknown(self):
        f = Fixture(self, variant="no-codex-wal")
        with self.assertRaises(ah_parity.ParityError) as ctx:
            ah_parity.canonical_snapshot(None, f.url)
        self.assertIn("wal.py", str(ctx.exception))
        self.assertEqual(f.verify()["hosts"]["mac"]["status"], "UNKNOWN")

    def test_judge_itself_refuses_a_stub_snapshot(self):
        # The choke point is judge, not only canonical_snapshot: a caller that builds its own snapshot gets no CLEAN either.
        h = Installed(self)
        home = h.install(h.tmp / "home")
        info = ah_parity.collect(home, CLAUDE_NAMES, CODEX_ALL)
        for bad in (dict(synth_snapshot(), blobs={}),
                    dict(synth_snapshot(), claude=(), codex=()),
                    dict(synth_snapshot(), claude=CLAUDE_NAMES + ("ghost.py",)),
                    dict(synth_snapshot(), codex=CODEX_ALL + ("ghost.py",)),
                    dict(synth_snapshot(), codex_blobs={}),
                    dict(synth_snapshot(), blobs={"ah.py": "not-a-sha"})):
            with self.assertRaises(ah_parity.ParityError, msg=repr(bad)):
                ah_parity.judge(bad, info)

    def test_every_listed_name_is_compared_on_a_clean_verdict(self):
        h = Installed(self)
        home = h.install(h.tmp / "home")
        v = h.judge(home)
        self.assertEqual(v["status"], "CLEAN")
        self.assertEqual((v["claude"]["ok"], v["codex"]["ok"]), (len(CLAUDE_NAMES), len(CODEX_ALL)))


class RefGate(unittest.TestCase):
    """Class: the gate compares the tip of canonical main, or the one SHA the user typed; --ref is doctor only."""

    def old_install(self, f):
        f.install_at(f.home, FILES)  # an older, valid canonical set (the first commit)

    def test_doctor_accepts_an_older_ancestor_but_says_it_is_not_the_tip(self):
        f = Fixture(self)
        self.old_install(f)
        r = f.verify(ref=f.first)
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["ref_is_tip"])

    def test_gate_without_a_pin_compares_the_tip_and_refuses_an_older_install(self):
        f = Fixture(self)
        self.old_install(f)
        g = f.gate()
        self.assertFalse(g["ok"], g)
        self.assertEqual(g["hosts"]["mac"]["claude"]["differ"], ["ah.py"])
        self.assertTrue(g["ref_is_tip"])
        self.assertFalse(g["pinned"])

    def test_gate_accepts_the_users_pin_only_as_a_canonical_ancestor(self):
        f = Fixture(self)
        self.old_install(f)
        f.install_at(f.remote_home, FILES)  # the gate checks both hosts
        g = f.gate(pinned=f.first)  # the user typed this release SHA: allowed, and labelled as pinned and not the tip
        self.assertTrue(g["ok"], g)
        self.assertTrue(g["pinned"])
        self.assertFalse(g["ref_is_tip"])
        self.assertEqual(g["ref"], f.first)
        self.assertFalse(f.gate(pinned=f.second)["ok"])  # a pin is the comparison, not a bypass: the install is not the tip's
        stray = Fixture(self, fresh=True)
        bad = git(stray.work, "commit-tree", "-m", "x", stray.second + "^{tree}")
        git(stray.work, "update-ref", "refs/heads/stray", bad)
        git(stray.bare, "fetch", "-q", str(stray.work), "stray:refs/heads/stray")
        g = stray.gate(pinned=bad)  # a commit that is not on canonical main
        self.assertFalse(g["ok"], g)
        self.assertEqual(g["hosts"]["mac"]["status"], "UNKNOWN")

    def test_gate_accepts_the_tip_with_or_without_the_pin(self):
        f = Fixture(self)
        self.assertTrue(f.gate()["ok"])
        self.assertTrue(f.gate(pinned=f.second)["ok"])
        self.assertTrue(f.gate(pinned=f.second)["ref_is_tip"])

    def test_malformed_pin_is_refused_and_the_gate_never_raises(self):
        f = Fixture(self)
        for pin in ("HEAD", "x;rm -rf /", f.second[:12], 5):
            self.assertFalse(f.gate(pinned=pin)["ok"], pin)
        r = ah_parity.verify_gate(None, f.home, f.runner(), "file://" + str(f.tmp / "nope.git"))
        self.assertFalse(r["ok"])

    def test_gate_has_no_ref_or_host_parameter(self):
        # Guard test: adding a free ref or a host subset to the gate must fail here. The only selector is pinned_sha.
        self.assertEqual(list(inspect.signature(ah_parity.verify_gate).parameters), ["pinned_sha", "home", "runner", "url"])

    def test_verify_parity_cli_has_no_ref_and_refuses_an_old_install(self):
        f = Fixture(self)
        self.old_install(f)
        self.assertEqual(ah_parity.main(["verify-parity", "--host", "mac", "--ref", f.first], f.home, f.runner(), io.StringIO()), 2)
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        self.assertEqual(ah_parity.main(["verify-parity", "--host", "mac"], f.home, f.runner(), io.StringIO()), 1)

    def test_gate_is_strict_about_untrusted_codex_hooks(self):
        f = Fixture(self)
        f.write_codex(f.home, extra=[("python3 /x/a.py hook", "untrusted")])
        self.assertTrue(f.verify()["ok"])  # the doctor lists them without failing
        g = f.gate()
        self.assertFalse(g["ok"], g)
        self.assertTrue(any("Codex will skip" in x for x in g["gate"]))
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        self.assertEqual(ah_parity.main(["verify-parity", "--host", "mac"], f.home, f.runner(), io.StringIO()), 1)


class Scope(unittest.TestCase):
    """Class: CLEAN covers what the guards load and how they are registered, not only the listed bytes."""

    def home(self, **kw):
        h = Installed(self)
        return h, h.install(h.tmp / "home", **kw)

    def test_planted_importable_file_or_package_is_a_named_warning_not_drift(self):  # goodqa#16810
        for planted in ("json.py", "sitecustomize.py", "typing.cpython-39-darwin.so", "os.pyc"):
            h, home = self.home()
            h.claude(home, planted).write_bytes(b"import os\n")
            v = h.judge(home)
            self.assertEqual(v["status"], "CLEAN", planted)
            self.assertEqual(v["claude"]["unexpected"], [planted])
            self.assertEqual(v["warnings"], ["claude: unexpected importable file or package " + planted])
        h, home = self.home()
        pkg = home.joinpath(*ah_parity.CLAUDE_DIR, "re")
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        self.assertEqual(h.judge(home)["claude"]["unexpected"], ["re"])
        h, home = self.home()
        home.joinpath(*ah_parity.CODEX_DIR, "json.py").write_text("x = 1\n")
        self.assertEqual(h.judge(home)["codex"]["unexpected"], ["json.py"])
        h, home = self.home()  # the Codex wal.py is not harness/hooks/wal.py: its own bytes are checked, not exempted
        self.assertEqual(h.judge(home)["status"], "CLEAN")
        home.joinpath(*ah_parity.CODEX_DIR, "wal.py").write_bytes(b"print('tampered')\n")
        self.assertEqual(h.judge(home)["codex"]["differ"], ["wal.py"])

    def test_harmless_extras_are_not_flagged(self):
        h, home = self.home()
        d = home.joinpath(*ah_parity.CLAUDE_DIR)
        (d / "notes.txt").write_text("n")
        (d / "watch-tests.py").write_text("not importable: a dash is not an identifier")
        (d / "ah.py.bak-pre-1").write_text("old")
        (d / "__pycache__").mkdir()
        (d / "__pycache__" / "ah.cpython-39.pyc").write_bytes(b"x")
        (d / "extra_tool.py").write_bytes(EXTRA_SHIPPED["extra_tool.py"])  # shipped by canonical, same bytes
        self.assertEqual(h.judge(home)["status"], "CLEAN")
        (d / "extra_tool.py").write_bytes(b"tampered\n")  # shipped by canonical, different bytes: byte drift, a FAIL
        v = h.judge(home)
        self.assertEqual((v["status"], v["claude"]["differ"], v["claude"]["unexpected"]), ("DRIFT", ["extra_tool.py"], []))

    def test_oversized_listing_fails_closed(self):
        h, home = self.home()
        d = home.joinpath(*ah_parity.CLAUDE_DIR)
        orig = ah_parity.MAX_ENTRIES
        ah_parity.MAX_ENTRIES = 5
        self.addCleanup(setattr, ah_parity, "MAX_ENTRIES", orig)
        for i in range(8):
            (d / ("n%d.txt" % i)).write_text("x")
        v = h.judge(home)
        self.assertEqual(v["status"], "DRIFT")  # a directory that cannot be listed fails closed
        self.assertIn("__too_many_entries__", v["claude"]["differ"])

    def test_unregistered_or_weakened_guard_is_drift(self):
        h, home = self.home()
        h.write_settings(home, drop=("command_guard_hook.py",))
        v = h.judge(home)
        self.assertEqual(v["status"], "DRIFT")
        self.assertEqual(v["claude"]["registrations"], ["PreToolUse command_guard_hook.py hook"])

        def fail_open(script, handler):
            if script == "merge_gate.py":
                del handler["onFailure"]
        h.write_settings(home, mutate=fail_open)
        self.assertEqual(h.judge(home)["claude"]["registrations"], ["PreToolUse merge_gate.py hook"])

        def redirect(script, handler):
            if script == "kill_guard.py":
                handler["args"][0] = "/tmp/elsewhere/kill_guard.py"
        h.write_settings(home, mutate=redirect)
        self.assertEqual(h.judge(home)["claude"]["registrations"], ["PreToolUse kill_guard.py hook"])

    def test_hooks_switched_off_or_unreadable_settings_are_drift(self):
        h, home = self.home()
        h.write_settings(home, extra={"disableAllHooks": True})
        self.assertIn("disableAllHooks is set", h.judge(home)["claude"]["registrations"])
        h.write_settings(home)
        (home / ".claude" / "settings.local.json").write_text(json.dumps({"disableAllHooks": True}))
        self.assertIn("disableAllHooks is set", h.judge(home)["claude"]["registrations"])
        (home / ".claude" / "settings.local.json").unlink()
        (home / ".claude" / "settings.json").write_text("{not json")
        v = h.judge(home)
        self.assertEqual(v["status"], "DRIFT")
        self.assertTrue(any("not readable" in x for x in v["claude"]["registrations"]))
        (home / ".claude" / "settings.json").unlink()
        self.assertEqual(h.judge(home)["status"], "DRIFT")

    def test_codex_guard_command_missing_is_drift(self):
        h, home = self.home()
        h.write_codex(home, drop=("kill_guard.py",))
        v = h.judge(home)
        self.assertEqual(v["status"], "DRIFT")
        self.assertEqual(v["codex"]["registrations"], ["PreToolUse kill_guard.py"])
        h2, home2 = self.home(codex=False)
        self.assertEqual(h2.judge(home2)["status"], "CLEAN")  # no Codex on the host: not drift

    def test_remote_extras_and_settings_travel_through_the_piped_program(self):
        f = Fixture(self)
        f.claude(f.remote_home, "json.py").write_text("x = 1\n")
        r = f.verify(("t2-dev",))
        self.assertEqual(r["hosts"]["t2-dev"]["claude"]["unexpected"], ["json.py"])
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "CLEAN")
        f.claude(f.remote_home, "json.py").unlink()
        f.write_settings(f.remote_home, drop=("tier_gate.py",))
        self.assertEqual(f.verify(("t2-dev",))["hosts"]["t2-dev"]["claude"]["registrations"], ["PreToolUse tier_gate.py hook"])
        old_shape = lambda a, s=None, t=None: (0, json.dumps({"claude": {"hashes": {}}, "codex": {"hashes": {}}, "trust": {}}) + "\n", "")
        self.assertEqual(f.verify(("t2-dev",), runner=old_shape)["hosts"]["t2-dev"]["status"], "UNKNOWN")


class Contract(unittest.TestCase):
    """The pinned guard table must equal what the installers really write, so a change there fails CI here."""

    def test_guard_registrations_equal_the_claude_installer(self):
        sys.path.insert(0, str(ROOT))
        import install
        managed = install.managed_hooks(Path("/H/.claude"))
        want = set()
        for event, groups in managed.items():
            for group in groups:
                for handler in group.get("hooks", []):
                    if handler.get("onFailure") == "block":
                        script = handler["args"][0]
                        self.assertEqual(os.path.dirname(script), "/H/.claude/hooks")
                        want.add((event, group.get("matcher"), os.path.basename(script), tuple(handler["args"][1:])))
        self.assertEqual(set(ah_parity.GUARD_REGISTRATIONS), want)
        self.assertEqual(len(ah_parity.GUARD_REGISTRATIONS), len(set(ah_parity.GUARD_REGISTRATIONS)))

    def test_codex_guards_appear_in_the_codex_installer_output(self):
        sys.path.insert(0, str(ROOT))
        import install_codex
        merged = install_codex.merge_hooks({}, Path("/H/.codex"))["hooks"]
        for event, script in ah_parity.CODEX_GUARDS:
            cmds = [h["command"] for g in merged[event] for h in g["hooks"]]
            self.assertTrue(any("/agent-harness/%s" % script in c for c in cmds), (event, script))


    def working_tree(self):
        """{repository path: blob sha} for every file under TREE_DIRS of this checkout (what canonical_snapshot reads from git)."""
        tree = {}
        for d in ah_parity.TREE_DIRS:
            for root, _dirs, files in os.walk(str(ROOT / d)):
                for name in files:
                    path = os.path.join(root, name)
                    with open(path, "rb") as fh:
                        tree[os.path.relpath(path, str(ROOT))] = sha1(fh.read())
        return tree

    def test_a_tree_the_real_installers_write_has_no_differing_missing_or_unexpected_file(self):
        # The class guard for "the expected set equals what the installers write": run the REAL installers (files only,
        # temp HOME) and judge the result against the snapshot built from this checkout's own tree.
        sys.path.insert(0, str(ROOT))
        import install
        import install_codex
        home = Path(tempfile.mkdtemp(prefix="parity-real-install-"))
        self.addCleanup(shutil.rmtree, str(home), True)
        install.install(home, True, hooks_only=True)
        install_codex.install(home, True, hooks_only=True)
        snap = ah_parity.build_snapshot("0" * 40, "0" * 40, (ROOT / "install.py").read_text(), (ROOT / "install_codex.py").read_text(),
                                        self.working_tree())
        v = ah_parity.judge(snap, ah_parity.collect(home, snap["claude"], snap["codex"]))
        for flavor in ("claude", "codex"):
            self.assertEqual((v[flavor]["differ"], v[flavor]["missing"], v[flavor]["unexpected"]), ([], [], []), flavor)
        self.assertEqual(v["claude"]["ok"], len(set(snap["claude"])))
        self.assertEqual(v["codex"]["ok"], len(set(snap["codex"])))
        self.assertGreater(v["codex"]["ok"], len(install_codex.DELIVERY_HELPERS) - 1)  # wal.py, ops_watch.py, watch-tests.py counted
        # and a stray file the installers do not write is only a named warning
        before = v["status"]  # (no settings.json in this temp home, so the registrations decide it; the stray file must not)
        (home / ".codex" / "agent-harness" / "planted.py").write_text("x = 1\n")
        v = ah_parity.judge(snap, ah_parity.collect(home, snap["claude"], snap["codex"]))
        self.assertEqual((v["codex"]["unexpected"], v["status"]), (["planted.py"], before))

    def test_allow_rule_literal_matches_the_enabler(self):
        self.assertTrue(ah_parity.is_exact_allow_rule(PROBE_RULE, Path("/H")))
        enabler = ROOT / "scripts" / "enable-agent-ops.py"
        if enabler.is_file():  # lane L5's file: its literal must be the rule the probe demands
            import re as _re
            found = _re.search(r'"ops": "(Bash\(python3 [^"]+\))"', enabler.read_text())
            self.assertIsNotNone(found)
            self.assertEqual(found.group(1), PROBE_RULE)


class Remote(unittest.TestCase):
    def test_remote_clean_and_drift(self):
        f = Fixture(self)
        self.assertTrue(f.verify(("mac", "t2-dev"))["ok"])
        f.claude(f.remote_home, "ah.py").write_bytes(b"stale\n")
        r = f.verify(("mac", "t2-dev"))
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        self.assertEqual(r["hosts"]["t2-dev"]["claude"]["differ"], ["ah.py"])
        self.assertFalse(r["ok"])

    def test_unreachable_remote_is_unknown_and_never_falls_back_to_local_neg12(self):
        f = Fixture(self)
        r = f.verify(("mac", "t2-dev"), runner=f.runner(rc=255))
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "UNKNOWN")
        self.assertFalse(r["ok"])
        self.assertEqual(ah_parity.exit_code(r), 3)

    def test_garbage_remote_output_is_unknown(self):
        f = Fixture(self)
        r = f.verify(("t2-dev",), runner=lambda a, s=None, t=None: (0, "not json\n", ""))
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "UNKNOWN")
        r = f.verify(("t2-dev",), runner=lambda a, s=None, t=None: (0, json.dumps({"claude": {}}) + "\n", ""))
        self.assertEqual(r["hosts"]["t2-dev"]["status"], "UNKNOWN")

    def test_ssh_command_is_constant_and_names_travel_as_data(self):
        f = Fixture(self)
        rec = []
        f.verify(("t2-dev",), runner=f.runner(record=rec))
        argv, stdin = rec[0]
        self.assertEqual(argv, ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "t2-dev", "python3", "-I", "-"])
        self.assertTrue(all("merge_gate" not in a for a in argv))
        self.assertIn("merge_gate.py", stdin)
        self.assertEqual(ah_parity.main(["doctor", "--host", "mac", "--ref", "x;rm -rf /"], f.home, f.runner(), io.StringIO()), 3)

    def test_unknown_host_name_refused(self):
        f = Fixture(self)
        with self.assertRaises(ah_parity.ParityError):
            ah_parity.remote_collect("evil;host", {"claude": (), "codex": ()}, f.runner())


class Trust(unittest.TestCase):
    def codex_files(self, f):
        cmds = ["python3 /x/a.py hook", "python3 /x/b.py hook", "python3 /x/c.py hook"]
        return f.write_codex(f.home, extra=[(cmds[0], "trusted"), (cmds[1], "changed"), (cmds[2], "untrusted")])

    def test_untrusted_and_changed_hooks_are_listed_ac12(self):
        f = Fixture(self)
        self.codex_files(f)
        t = f.verify()["hosts"]["mac"]["trust"]
        self.assertEqual(t["untrusted"], ["pre_tool_use:2:0"])
        self.assertEqual(t["changed"], ["pre_tool_use:1:0"])
        self.assertEqual(ah_parity.exit_code(f.verify()), 0)
        self.assertEqual(ah_parity.exit_code(f.verify(), strict_trust=True), 1)

    def test_doctor_writes_nothing_neg11(self):
        f = Fixture(self)
        self.codex_files(f)

        def snapshot():
            return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in f.home.rglob("*") if p.is_file()}
        before = snapshot()
        ah_parity.main(["doctor", "--host", "mac"], f.home, f.runner(), io.StringIO())
        ah_parity.verify_gate(None, f.home, f.runner(), f.url)
        self.assertEqual(before, snapshot())
        src = Path(ah_parity.__file__).read_text()
        self.assertNotIn('"w"', src.replace('"w"),', ''))  # no write-mode open anywhere in the module

    def test_hash_algorithm_matches_ops_watch(self):
        sys.path.insert(0, str(ROOT / "harness" / "hooks"))
        import ops_watch
        for matcher, handler in ((None, {"type": "command", "command": "c", "timeout": 3}),
                                 ("Bash", {"type": "command", "command": "d", "async": True, "extra": 1})):
            self.assertEqual(ah_parity.codex_hook_hash("stop", matcher, handler), ops_watch.codex_hook_hash("stop", matcher, handler))


class Rules(unittest.TestCase):
    def test_rule_matcher_table(self):
        cmd = "python3 ~/.claude/hooks/ah.py ops doctor --host mac --json"
        yes = ["Bash", "Bash(*)", "Bash(python3 *)", "Bash(python3:*)", PROBE_RULE, "Bash(python3 ~/.claude/hooks/ah.py ops doctor:*)",
               "Bash(" + cmd + ")"]
        no = ["Bash(rm *)", "Bash(echo python3 *)", "Bash(python3 /evil/ah.py ops *)", "Bash(python3x:*)", "Read(*)", "Edit", "", None, 7]
        for r in yes:
            self.assertTrue(ah_parity.rule_matches(r, cmd), r)
        for r in no:
            self.assertFalse(ah_parity.rule_matches(r, cmd), r)

    def test_exact_allow_rule_is_only_the_installed_ah_ops_prefix(self):
        home = Path("/H")
        ok = [PROBE_RULE, "Bash(python3 /H/.claude/hooks/ah.py ops *)", "Bash(python3 ~/.claude/hooks/ah.py ops:*)"]
        bad = ["Bash(echo ah.py ops *)", "Bash(python3 *)", "Bash(python3 /evil/ah.py ops *)", "Bash(python3 ~/.claude/hooks/ah.py ops)",
               "Bash(python3 ~/.claude/hooks/ah.py *)", "Bash(python3 -I ~/.claude/hooks/ah.py ops *)",
               "Bash(python3 ~/.claude/hooks/ah.py ops * ; rm -rf x)", "Bash", "Read(python3 ~/.claude/hooks/ah.py ops *)"]
        for r in ok:
            self.assertTrue(ah_parity.is_exact_allow_rule(r, home), r)
        for r in bad:
            self.assertFalse(ah_parity.is_exact_allow_rule(r, home), r)


class Probe(unittest.TestCase):
    PLAN = "import sys; print(%r); sys.exit(0)\n" % DOCTOR_REPORT

    def setup_home(self, f, rule=True, ah_body=PLAN, allow=None, deny=(), ask=(), local_deny=()):
        (f.home / ".claude").mkdir(exist_ok=True)
        settings = json.loads((f.home / ".claude" / "settings.json").read_text())
        rules = allow if allow is not None else ([PROBE_RULE] if rule else ["Bash(ls *)"])
        settings["permissions"] = {"allow": rules, "deny": list(deny), "ask": list(ask)}
        (f.home / ".claude" / "settings.json").write_text(json.dumps(settings))
        local = f.home / ".claude" / "settings.local.json"
        if local_deny:
            local.write_text(json.dumps({"permissions": {"deny": list(local_deny)}}))
        elif local.exists():
            local.unlink()
        f.claude(f.home, "ah.py").write_text(ah_body)

    @staticmethod
    def local(argv, stdin=None, timeout=None):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout, p.stderr

    def test_probe_passes_when_recipe_runs_and_says_what_it_proves(self):
        f = Fixture(self)
        self.setup_home(f)
        r = ah_parity.probe(f.home, self.local)
        self.assertEqual(r["status"], "PASS", r)
        self.assertEqual(r["scope"], "rule-present-and-recipe-runs")
        self.assertIn("allow rule present and recipe runs", r["reason"])
        self.assertIn("click-test", r["reason"])

    def test_recipe_is_read_only_argument_free_and_not_l3_repair(self):
        # `ops repair --check` needs --ref (exit 2 without it) and journals under work/self-serve: not usable as a probe.
        self.assertEqual(ah_parity.PROBE_RECIPE[:2], ("ops", "doctor"))
        for word in ("repair", "merge", "--apply", "--resume", "central-decisions"):
            self.assertNotIn(word, ah_parity.PROBE_RECIPE)
        self.assertTrue(all(c.startswith("python3 ") and " ops doctor " in c for c in ah_parity.probe_commands(Path("/H"))))

    def test_missing_allow_rule_is_a_limitation_with_p0_ticket_ac14(self):
        f = Fixture(self)
        self.setup_home(f, rule=False)
        r = ah_parity.probe(f.home, self.local)
        self.assertEqual(r["status"], "LIMITATION")
        self.assertEqual(r["ticket"]["priority"], "P0")

    def test_look_alike_allow_rules_are_not_a_pass(self):
        # Before the fix: any rule containing "ah.py ops" and ending in * passed (e.g. an echo rule).
        f = Fixture(self)
        for rule in ("Bash(echo ah.py ops *)", "Bash(python3 *)", "Bash(python3 /evil/ah.py ops *)",
                     "Bash(python3 ~/.claude/hooks/ah.py ops)", "Bash(python3 -I ~/.claude/hooks/ah.py ops *)"):
            self.setup_home(f, allow=[rule])
            r = ah_parity.probe(f.home, self.local)
            self.assertEqual(r["status"], "LIMITATION", rule)
            self.assertIn("exact-prefix", r["reason"])

    def test_deny_or_ask_rule_that_shadows_the_allow_is_not_a_pass(self):
        f = Fixture(self)
        for kwargs in ({"deny": ["Bash(python3 *)"]}, {"deny": ["Bash"]}, {"ask": ["Bash(python3 ~/.claude/hooks/ah.py ops doctor:*)"]},
                       {"local_deny": ["Bash(python3 -I *)"]}):
            self.setup_home(f, **kwargs)
            r = ah_parity.probe(f.home, self.local)
            self.assertEqual(r["status"], "LIMITATION", kwargs)
            self.assertIn("shadows", r["reason"])
        self.setup_home(f, deny=["Bash(rm *)"], ask=["Bash(git push *)"])
        self.assertEqual(ah_parity.probe(f.home, self.local)["status"], "PASS")  # unrelated deny and ask rules are fine

    def test_silent_or_wrong_output_is_not_a_pass(self):
        f = Fixture(self)
        for body in ("import sys; sys.exit(0)\n", "print('ok')\n", "print('{}')\n", "print('{\"hosts\": {}}')\n"):
            self.setup_home(f, ah_body=body)
            r = ah_parity.probe(f.home, self.local)
            self.assertEqual(r["status"], "LIMITATION", body)
            self.assertIn("did not print", r["reason"])

    def test_a_drift_exit_still_counts_as_the_recipe_running(self):
        f = Fixture(self)
        self.setup_home(f, ah_body="import sys; print(%r); sys.exit(1)\n" % DOCTOR_REPORT)
        self.assertEqual(ah_parity.probe(f.home, self.local)["status"], "PASS")
        self.setup_home(f, ah_body="import sys; print(%r); sys.exit(2)\n" % DOCTOR_REPORT)
        self.assertEqual(ah_parity.probe(f.home, self.local)["status"], "LIMITATION")  # exit 2 is a usage error, not a run

    def test_non_canonical_ah_py_is_not_a_pass(self):
        f = Fixture(self)
        self.setup_home(f)
        r = ah_parity.probe(f.home, self.local, ah_clean=False)
        self.assertEqual(r["status"], "LIMITATION")
        self.assertIn("canonical", r["reason"])
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        buf = io.StringIO()
        ah_parity.main(["doctor", "--host", "mac", "--probe", "--json"], f.home, self.local, buf)
        self.assertEqual(json.loads(buf.getvalue())["probe"]["status"], "LIMITATION")  # ah.py is the stub, not canonical

    def test_denied_recipe_is_a_limitation_not_a_pass(self):
        f = Fixture(self)
        self.setup_home(f, ah_body="import sys; sys.stderr.write('command_guard BLOCKED: x'); sys.exit(2)\n")
        r = ah_parity.probe(f.home, self.local)
        self.assertEqual(r["status"], "LIMITATION")
        self.assertIn("denied", r["reason"])

    def test_recipe_not_installed_yet_is_reported(self):
        f = Fixture(self)
        for body in ("import sys; sys.stderr.write('invalid choice: ops'); sys.exit(2)\n",
                     "import sys; sys.stderr.write('`ah ops doctor` comes with ah_parity.py, which is not installed here'); sys.exit(2)\n"):
            self.setup_home(f, ah_body=body)
            self.assertIn("not installed", ah_parity.probe(f.home, self.local)["reason"])

    def test_probe_runs_only_the_read_only_recipe(self):
        f = Fixture(self)
        self.setup_home(f)
        seen = []
        ah_parity.probe(f.home, lambda a, s=None, t=None: (seen.append(a) or (0, DOCTOR_REPORT + "\n", "")))
        self.assertEqual(tuple(seen[0][-5:]), ah_parity.PROBE_RECIPE)
        self.assertEqual(len(seen), 1)

    def test_cli_probe_files_ticket_on_request(self):
        f = Fixture(self)
        self.setup_home(f, rule=False)
        calls = []
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)

        def runner(argv, stdin=None, timeout=None):
            calls.append(argv)
            if "ticket" in argv:
                return 0, "{}", ""
            return 0, DOCTOR_REPORT + "\n", ""
        buf = io.StringIO()
        code = ah_parity.main(["doctor", "--host", "mac", "--probe", "--file-ticket", "--json"], f.home, runner, buf)
        self.assertEqual(code, 1)  # ah.py is the stub here, so the host is not clean either; the probe limitation also fails
        ticket_calls = [c for c in calls if "ticket" in c]
        self.assertEqual(len(ticket_calls), 1)
        self.assertEqual(ticket_calls[0][ticket_calls[0].index("--priority") + 1], "P0")
        self.assertTrue(json.loads(buf.getvalue())["probe"]["ticket_filed"])


class Cli(unittest.TestCase):
    def test_json_and_text_output_and_usage(self):
        f = Fixture(self)
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        buf = io.StringIO()
        self.assertEqual(ah_parity.main(["verify-parity", "--host", "mac", "--json"], f.home, f.runner(), buf), 0)
        self.assertEqual(json.loads(buf.getvalue())["hosts"]["mac"]["status"], "CLEAN")
        f.claude(f.home, "ah.py").write_bytes(b"x")
        f.claude(f.home, "json.py").write_bytes(b"x")
        buf = io.StringIO()
        self.assertEqual(ah_parity.main(["doctor", "--host", "mac"], f.home, f.runner(), buf), 1)
        self.assertIn("DIFFERS ah.py", buf.getvalue())
        self.assertIn("WARN unexpected importable file or package (not shipped by canonical main, not a failure): json.py", buf.getvalue())
        self.assertEqual(ah_parity.main(["nonsense"], f.home, f.runner(), io.StringIO()), 2)

    def test_doctor_entry_for_ah_py_returns_the_report_dict(self):
        # ah.py's `ops doctor` imports ah_parity and calls doctor(rest, home) expecting a dict (self-serve lane L3).
        f = Fixture(self)
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        r = ah_parity.doctor(["--host", "mac"], f.home)
        self.assertEqual((r["ok"], r["exit_code"]), (True, 0))
        self.assertEqual(r["hosts"]["mac"]["status"], "CLEAN")
        f.claude(f.home, "ah.py").write_bytes(b"x")
        r = ah_parity.doctor(["--host", "mac", "--json"], f.home)
        self.assertEqual((r["ok"], r["exit_code"]), (False, 1))
        self.assertEqual(ah_parity.doctor(["--bogus"], f.home)["exit_code"], 2)

    def test_verify_parity_entry_for_ah_py_is_the_gate_form(self):
        # ah.py dispatches `ops verify-parity` to ah_parity.verify_parity(rest, home) (self-serve integration, X5).
        f = Fixture(self)
        orig = ah_parity.CANONICAL_URL
        ah_parity.CANONICAL_URL = f.url
        self.addCleanup(setattr, ah_parity, "CANONICAL_URL", orig)
        r = ah_parity.verify_parity(["--host", "mac"], f.home)
        self.assertEqual((r["ok"], r["exit_code"]), (True, 0))
        f.claude(f.home, "ah.py").write_bytes(b"x")
        r = ah_parity.verify_parity(["--host", "mac"], f.home)
        self.assertEqual((r["ok"], r["exit_code"]), (False, 1))
        self.assertEqual(ah_parity.verify_parity(["--ref", "a" * 40], f.home)["exit_code"], 2, "the gate form has no --ref")


if __name__ == "__main__":
    unittest.main()
