"""ahc_clone: daemon-owned full clones, fetched to the exact head, never shallow, with hooks and fsmonitor disabled
(GoodQA goodqa#16034 AC-3, NEG-3). Local bare-repo fixtures only; no network."""
import inspect
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_clone  # noqa: E402

# Local fixture remotes need the file transport, which prepare() opts into since PR 258 v3. The keyword is passed
# only where it exists so the same tests can run against an older revision for the failing-first log.
CLONE_KW = {"allow_file": True} if "allow_file" in inspect.signature(ahc_clone.prepare).parameters else {}

ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, check=True, capture_output=True, text=True).stdout.strip()


class CloneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.marker = root / "PWNED"
        work = root / "src"
        git("init", "-q", "-b", "main", str(work))
        (work / "a.txt").write_text("one\n")
        git("add", "a.txt", cwd=work)
        git("commit", "-qm", "one", cwd=work)
        self.base = git("rev-parse", "HEAD", cwd=work)
        git("checkout", "-qb", "feature", cwd=work)
        (work / "a.txt").write_text("two\n")
        git("commit", "-qam", "two", cwd=work)
        self.head = git("rev-parse", "HEAD", cwd=work)
        self.remote = root / "remote.git"
        git("clone", "-q", "--bare", str(work), str(self.remote))
        # Hostile remote-side config cannot travel through a clone, but a hostile *local* config could if the daemon
        # ever reused an owner checkout. Plant both kinds of trap: a hook in the bare repo and, after cloning, an
        # fsmonitor and hooksPath pointing at a marker-writing script inside the daemon clone's own config.
        trap = root / "trap.sh"
        trap.write_text(f"#!/bin/sh\ntouch {self.marker}\n")
        trap.chmod(0o755)
        for name in ("post-checkout", "post-merge", "reference-transaction"):
            hook = self.remote / "hooks" / name
            hook.write_text(trap.read_text())
            hook.chmod(0o755)
        self.trap = trap
        self.clones = root / "clones"

    def tearDown(self):
        self.tmp.cleanup()

    def test_clone_local_config_disables_hooks_for_plain_git(self):
        # D2: peer_review runs its own git in the clone without our -c flags, so the local config must carry them.
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)
        self.assertEqual(git("config", "--local", "core.hooksPath", cwd=path), "/dev/null")
        self.assertEqual(git("config", "--local", "core.fsmonitor", cwd=path), "false")
        (Path(path) / ".git" / "hooks").mkdir(exist_ok=True)
        hook = Path(path) / ".git" / "hooks" / "post-checkout"
        hook.write_text(self.trap.read_text())
        hook.chmod(0o755)
        git("checkout", "-q", "--detach", self.base, cwd=path)  # plain git, no -c flags
        self.assertFalse(self.marker.exists(), "a hook ran under plain git in the daemon clone")

    def test_full_clone_at_exact_head_runs_no_hook(self):
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)
        self.assertEqual(git("rev-parse", "HEAD", cwd=path), self.head)
        self.assertEqual(git("rev-parse", "--is-shallow-repository", cwd=path), "false")
        self.assertEqual(git("status", "--porcelain", cwd=path), "")
        self.assertFalse(self.marker.exists())

    def test_planted_local_fsmonitor_and_hookspath_never_run(self):
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.base, self.base, env=ENV, **CLONE_KW)
        git("config", "core.fsmonitor", str(self.trap), cwd=path)
        git("config", "core.hooksPath", str(self.trap.parent), cwd=path)
        (Path(self.trap.parent) / "post-checkout").write_text(self.trap.read_text())
        (Path(self.trap.parent) / "post-checkout").chmod(0o755)
        ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)
        self.assertFalse(self.marker.exists(), "a planted fsmonitor or hooksPath ran under daemon authority")
        self.assertEqual(git("rev-parse", "HEAD", cwd=path), self.head)

    def test_unknown_head_is_refused(self):
        with self.assertRaises(ahc_clone.CloneError):
            ahc_clone.prepare(self.clones, "o/n", str(self.remote), "f" * 40, self.base, env=ENV, **CLONE_KW)

    def test_dirty_clone_is_reset_to_head(self):
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)
        (Path(path) / "a.txt").write_text("tampered\n")
        (Path(path) / "junk.txt").write_text("x\n")
        ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)
        self.assertEqual(git("status", "--porcelain", cwd=path), "")

    def test_repo_slug_cannot_escape_clone_root(self):
        with self.assertRaises(ahc_clone.CloneError):
            ahc_clone.prepare(self.clones, "../evil", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)


class CloneLinkTests(CloneTests):
    """PR 258 v1 BLOCK: git must never write through a link placed at the clones root, the clone directory or its
    .git; each is refused before any git command runs, and the link's target is left untouched."""

    def test_a_linked_clone_root_or_clone_dir_is_refused(self):
        outside = Path(self.tmp.name) / "other-program"
        for where in ("root", "clone"):
            with self.subTest(where=where):
                target = outside / where
                target.mkdir(parents=True)
                clones = Path(self.tmp.name) / ("clones-" + where)
                if where == "root":
                    os.symlink(str(target), str(clones))
                else:
                    clones.mkdir(mode=0o700)
                    os.symlink(str(target), str(ahc_clone.clone_dir(clones, "o/n")))
                with self.assertRaises(ahc_clone.CloneError):
                    ahc_clone.prepare(clones, "o/n", str(self.remote), self.head, self.base, env=ENV, **CLONE_KW)
                self.assertEqual(os.listdir(str(target)), [], "nothing was written through the link")

    def test_a_linked_git_dir_quarantines_the_clone_without_following_it(self):
        """PR 258 v3 ruling: a .git that is not git's own is never repaired in place. The clone is moved aside into
        rejected/ (the link moved as a link) and a fresh clone is made."""
        target = Path(self.tmp.name) / "other-program"
        target.mkdir()
        self.clones.mkdir(mode=0o700)
        clone = ahc_clone.clone_dir(self.clones, "o/n")
        clone.mkdir(mode=0o700)
        os.symlink(str(target), str(clone / ".git"))
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV,
                                 **CLONE_KW)
        self.assertEqual(os.listdir(str(target)), [], "nothing was written through the link")
        self.assertFalse((Path(path) / ".git").is_symlink())
        self.assertEqual(git("rev-parse", "HEAD", cwd=path), self.head)


class CloneReuseHardeningTests(CloneTests):
    """PR 258 v3 (F1, and the spec owner's D4 ruling). A reused clone carries state from earlier reviews. Before
    every use, .git is walked against an allowlist, bounded and without following links. Anything git would not
    keep quarantines the clone (moved to rejected/, never repaired in place) and a fresh clone is made. The config
    is rewritten whole. Nothing planted ever runs, and nothing outside the clone is ever written."""

    def quarantined(self):
        rejected = self.clones.parent / "rejected"
        return sorted(p.name for p in rejected.iterdir() if p.is_dir() and not p.is_symlink()) \
            if rejected.is_dir() else []

    def fresh(self):
        return ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV,
                                 **CLONE_KW)

    def assert_quarantined_and_fresh(self, path):
        self.assertEqual(len(self.quarantined()), 1, "the clone was not quarantined")
        self.assertEqual(git("rev-parse", "HEAD", cwd=path), self.head)
        self.assertEqual(git("status", "--porcelain", cwd=path), "")
        self.assertFalse(self.marker.exists(), "something planted ran")
        self.assertFalse((Path(path) / ".git" / "hooks").exists(), "a fresh clone carries no hooks directory")

    def test_a_planted_hook_quarantines_the_clone_and_never_runs(self):
        path = self.fresh()
        hooks = Path(path) / ".git" / "hooks"
        hooks.mkdir(mode=0o700, exist_ok=True)
        (hooks / "post-checkout").write_text(self.trap.read_text())
        (hooks / "post-checkout").chmod(0o700)
        self.assert_quarantined_and_fresh(self.fresh())

    def test_a_link_at_config_ahc_tmp_is_never_written_through(self):
        """PR 258 v3 F1, exactly: `.git/config.ahc-tmp -> <external file>`. The old code truncated and chmodded it."""
        external = Path(self.tmp.name) / "external.conf"
        external.write_bytes(b"another program's config\n")
        external.chmod(0o644)
        path = self.fresh()
        os.symlink(str(external), str(Path(path) / ".git" / "config.ahc-tmp"))
        self.assert_quarantined_and_fresh(self.fresh())
        self.assertEqual(external.read_bytes(), b"another program's config\n")
        self.assertEqual(external.stat().st_mode & 0o777, 0o644)

    def test_a_link_at_a_name_git_keeps_quarantines_the_clone(self):
        """A link is refused even where the name itself is allowed. packed-refs and objects/pack are names git
        keeps, so only the walk's link check catches these."""
        for name in ("packed-refs", "objects/pack/pack-%s.pack" % ("0" * 40), "refs/heads/main"):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                external = Path(self.tmp.name) / "external"
                external.write_bytes(b"x\n")
                external.chmod(0o644)
                path = self.fresh()
                link = Path(path) / ".git" / name
                link.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if os.path.lexists(str(link)):
                    os.unlink(str(link))
                os.symlink(str(external), str(link))
                self.assert_quarantined_and_fresh(self.fresh())
                self.assertEqual((external.read_bytes(), external.stat().st_mode & 0o777), (b"x\n", 0o644))

    def test_poisoned_config_lines_are_dropped_by_a_rewrite_from_scratch(self):
        path = self.fresh()
        for key, value in (("core.sshCommand", str(self.trap)), ("core.fsmonitor", str(self.trap)),
                           ("core.pager", str(self.trap)), ("include.path", str(self.trap))):   # include last
            git("config", key, value, cwd=path)
        self.fresh()
        config = (Path(path) / ".git" / "config").read_text()
        for planted in ("sshCommand", "include", "pager", str(self.trap)):
            self.assertNotIn(planted, config)
        self.assertEqual(config, ahc_clone.canonical_config_text(str(self.remote)))
        self.assertFalse(self.marker.exists())

    def test_a_foreign_owned_entry_quarantines_the_clone(self):
        """A test cannot chown without root, so the walk's lstat seam reports one entry as another uid's."""
        from unittest import mock
        path = self.fresh()
        head_file = str(Path(path) / ".git" / "HEAD")
        real = os.lstat

        def lstat(p, *a, **k):
            info = real(p, *a, **k)
            if str(p) == head_file:
                fields = list(info)
                fields[4] = os.geteuid() + 1          # st_uid
                return os.stat_result(fields)
            return info
        with mock.patch.object(ahc_clone, "_lstat", lstat, create=True):
            self.assert_quarantined_and_fresh(self.fresh())

    def test_alternates_worktrees_and_modules_quarantine_the_clone(self):
        for planted in ("objects/info/alternates", "worktrees/x/gitdir", "modules/m/config", "info/attributes",
                        "logs/HEAD", "shallow"):
            with self.subTest(planted=planted):
                self.tearDown()
                self.setUp()
                path = self.fresh()
                target = Path(path) / ".git" / planted
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_text(str(self.tmp.name) + "\n")
                self.assert_quarantined_and_fresh(self.fresh())

    def test_the_walk_is_bounded_and_fails_closed(self):
        from unittest import mock
        for name, value in (("MAX_GIT_ENTRIES", 3), ("MAX_GIT_DEPTH", 1)):
            with self.subTest(bound=name):
                self.tearDown()
                self.setUp()
                self.fresh()
                with mock.patch.object(ahc_clone, name, value, create=True):
                    self.assert_quarantined_and_fresh(self.fresh())

    def test_a_clone_directory_another_user_could_write_is_refused(self):
        path = self.fresh()
        os.chmod(path, 0o775)
        with self.assertRaises(ahc_clone.CloneError):
            self.fresh()
        self.assertFalse(self.marker.exists())

    def test_git_runs_with_no_system_or_global_config_https_only_under_umask_077(self):
        calls = []
        real = ahc_clone.ahc_core.run_argv

        def recording(argv, timeout, cwd=None, env=None):
            calls.append((list(argv), dict(env or {}), os.umask(0o077)))
            os.umask(calls[-1][2])
            return real(argv, timeout, cwd=cwd, env=env)
        # The caller's environment is hostile: a global config that sets a hook path, and system config allowed.
        # ahc's own GIT_ENV must override both (the shared ENV fixture already isolates git, so it is not used).
        hostile_global = Path(self.tmp.name) / "hostile.gitconfig"
        hostile_global.write_text("[core]\n\thooksPath = %s\n" % (Path(self.tmp.name) / "hostile-hooks"))
        hostile = {**ENV, "GIT_CONFIG_GLOBAL": str(hostile_global), "GIT_CONFIG_NOSYSTEM": "0"}
        ahc_clone.ahc_core.run_argv = recording
        try:
            path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=hostile,
                                     **CLONE_KW)
        finally:
            ahc_clone.ahc_core.run_argv = real
        self.assertTrue(calls)
        for argv, env, umask in calls:
            self.assertEqual(env.get("GIT_CONFIG_NOSYSTEM"), "1")
            self.assertEqual(env.get("GIT_CONFIG_GLOBAL"), os.devnull)
            self.assertIn("protocol.allow=never", argv)
            self.assertIn("core.hooksPath=/dev/null", argv)
            self.assertEqual(umask, 0o077)
        self.assertEqual(os.stat(Path(path) / ".git").st_mode & 0o777, 0o700)
        with self.assertRaises(ahc_clone.CloneError):          # the file transport is opt-in (tests only)
            ahc_clone.prepare(Path(self.tmp.name) / "other" / "clones", "o/n", str(self.remote), self.head,
                              self.base, env=ENV)


if __name__ == "__main__":
    unittest.main()
