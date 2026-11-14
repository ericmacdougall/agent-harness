"""S1 (GoodQA goodqa#15946): canonical repository identity, lane key, stream key, held targets.

Covers AC-2, AC-10, NEG-1, NEG-3, NEG-10 of software-factory/s1/spec.md.
Bounded probes: at most 6 short git subprocesses per test, one temp directory, no network, 60 s timeout.
Fails on main c82ad2af: module `lane.identity` does not exist.
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
from lane import identity as ident  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]


def git(cwd, *args):
    return subprocess.run(GIT + list(args), cwd=cwd, check=True, capture_output=True, text=True, timeout=60).stdout


def make_repo(path, remotes=()):
    Path(path).mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    git(path, "commit", "-q", "--allow-empty", "-m", "init")
    for name, url in remotes:
        git(path, "remote", "add", name, url)
    return Path(path)


class SpellingTests(unittest.TestCase):
    EXPECT = "github.com/owner/repo"

    def test_every_spelling_gives_one_identity(self):
        spellings = [
            "https://github.com/Owner/Repo.git",
            "https://github.com/owner/repo",
            "https://GitHub.com/OWNER/REPO/",
            "https://x-access-token:SECRETVALUE@github.com/owner/repo.git",
            "https://user@github.com:443/owner/repo.git",
            "git@github.com:owner/repo.git",
            "ssh://git@github.com:22/owner/repo.git",
            "ssh://git@GITHUB.com/Owner/Repo.git/",
        ]
        for url in spellings:
            with self.subTest(url=url):
                self.assertEqual(ident.canonical_repo(url), (self.EXPECT, "remote"))

    def test_identity_never_carries_userinfo(self):
        identity, _ = ident.canonical_repo("https://user:hunter2@github.com/owner/repo.git")
        self.assertNotIn("hunter2", identity)
        self.assertNotIn("user", identity.split("/")[0])
        self.assertNotIn("@", identity)

    def test_different_repositories_differ(self):
        a, _ = ident.canonical_repo("https://github.com/owner/repo")
        b, _ = ident.canonical_repo("https://github.com/owner/repo2")
        c, _ = ident.canonical_repo("https://github.com/other/repo")
        self.assertEqual(len({a, b, c}), 3)

    def test_malformed_input_is_refused(self):  # NEG-1
        for bad in ("", "   ", "https://github.com/", "https://github.com/onlyowner", "git@github.com:repo.git",
                    "https:///owner/repo", "ftp://github.com/owner/repo"):
            with self.subTest(bad=bad):
                with self.assertRaises(ident.IdentityError):
                    ident.canonical_repo(bad)

    def test_non_git_directory_is_refused(self):  # NEG-1
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ident.IdentityError):
                ident.canonical_repo(tmp)
            with self.assertRaises(ident.IdentityError):
                ident.canonical_repo(os.path.join(tmp, "does-not-exist"))


class LocalRepoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(os.path.realpath(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_clone_worktree_and_spellings_share_one_identity(self):  # AC-2 positive
        main = make_repo(self.root / "main", [("origin", "https://github.com/Owner/Repo.git")])
        git(main, "worktree", "add", "-q", str(self.root / "wt"), "-b", "side")
        git(self.root, "clone", "-q", str(main), "second")
        git(self.root / "second", "remote", "set-url", "origin", "git@github.com:owner/repo.git")
        expected = ("github.com/owner/repo", "remote")
        self.assertEqual(ident.canonical_repo(str(main)), expected)
        self.assertEqual(ident.canonical_repo(str(self.root / "wt")), expected)
        self.assertEqual(ident.canonical_repo(str(self.root / "second")), expected)

    def test_a_different_repository_is_a_different_identity(self):  # AC-2 positive control
        a = make_repo(self.root / "a", [("origin", "https://github.com/owner/one.git")])
        b = make_repo(self.root / "b", [("origin", "https://github.com/owner/two.git")])
        self.assertNotEqual(ident.canonical_repo(str(a)), ident.canonical_repo(str(b)))

    def test_no_remote_uses_device_and_inode_of_common_git_dir(self):  # NEG-3
        main = make_repo(self.root / "plain")
        git(main, "worktree", "add", "-q", str(self.root / "plain-wt"), "-b", "side")
        other = make_repo(self.root / "other")
        identity, kind = ident.canonical_repo(str(main))
        st = os.stat(main / ".git")
        self.assertEqual(kind, "local")
        self.assertEqual(identity, "local:%d:%d" % (st.st_dev, st.st_ino))
        self.assertEqual(ident.canonical_repo(str(self.root / "plain-wt")), (identity, kind))
        self.assertNotEqual(ident.canonical_repo(str(other))[0], identity)

    def test_two_remotes_use_origin_and_record_the_choice(self):  # NEG-3
        repo = make_repo(self.root / "two", [("upstream", "https://github.com/up/stream.git"),
                                            ("origin", "https://github.com/owner/repo.git")])
        self.assertEqual(ident.canonical_repo(str(repo)), ("github.com/owner/repo", "remote-origin"))

    def test_two_remotes_without_origin_fall_back_to_local(self):  # NEG-3: never guesses between remotes
        repo = make_repo(self.root / "noorigin", [("a", "https://github.com/x/a.git"), ("b", "https://github.com/x/b.git")])
        self.assertEqual(ident.canonical_repo(str(repo))[1], "local")


class KeyTests(unittest.TestCase):
    def test_lane_key_and_stream_key(self):
        key = ident.lane_key("GoodQA goodqa#15946", "github.com/owner/repo")
        self.assertEqual(key, "GoodQA goodqa#15946|github.com/owner/repo")
        stream = ident.stream_key(key)
        self.assertEqual(stream, "stream-" + hashlib.sha256(key.encode()).hexdigest()[:12])
        self.assertRegex(stream, r"^stream-[0-9a-f]{12}$")

    def test_ticket_ref_is_normalised_so_the_stream_key_is_stable(self):
        a = ident.lane_key("GoodQA GOODQA#15946", "github.com/o/r")
        b = ident.lane_key("goodqa goodqa#15946", "github.com/o/r")
        self.assertEqual(ident.stream_key(a), ident.stream_key(b))

    def test_stream_key_depends_on_ticket_and_repo_only(self):
        a = ident.stream_key(ident.lane_key("GoodQA goodqa#1", "github.com/o/r"))
        self.assertNotEqual(a, ident.stream_key(ident.lane_key("GoodQA goodqa#2", "github.com/o/r")))
        self.assertNotEqual(a, ident.stream_key(ident.lane_key("GoodQA goodqa#1", "github.com/o/s")))

    def test_ticket_ref_without_project_slug_is_refused(self):  # NEG-1
        for bad in ("GoodQA #15946", "15946", "", "GoodQA goodqa#", "GoodQA goodqa#abc", "GoodQA a b#1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ident.IdentityError):
                    ident.lane_key(bad, "github.com/o/r")


class HeldTargetTests(unittest.TestCase):
    def test_identity_names_are_refused_with_the_rule(self):  # AC-10
        for identity, rule in (("github.com/acme/yates-cloud", "yates"), ("github.com/acme/apex_app_pos", "yates"),
                               ("github.com/acme/OptinRouter".lower(), "optinrouter"),
                               ("github.com/acme/vertex-provider", "vertex")):
            with self.subTest(identity=identity):
                self.assertEqual(ident.held_rule(identity=identity), rule)

    def test_clean_identity_is_not_held(self):  # positive control
        self.assertIsNone(ident.held_rule(identity="github.com/ericmacdougall/agent-harness"))

    def test_held_target_through_symlink_renamed_remote_and_worktree(self):  # NEG-10
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp))
            held = make_repo(root / "innocent-dir", [("somename", "https://github.com/acme/yates-cloud.git")])
            link = root / "link-to-it"
            link.symlink_to(held)
            git(held, "worktree", "add", "-q", str(root / "plain-looking"), "-b", "w")
            clean = make_repo(root / "clean", [("origin", "https://github.com/acme/fine.git")])
            for path in (held, link, root / "plain-looking"):
                with self.subTest(path=str(path)):
                    self.assertEqual(ident.held_rule(path=str(path)), "yates")
            self.assertIsNone(ident.held_rule(path=str(clean)))

    def test_held_directory_name_through_a_symlink(self):  # NEG-10
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp))
            held = make_repo(root / "OptinRouter")
            link = root / "harmless"
            link.symlink_to(held)
            self.assertEqual(ident.held_rule(path=str(link)), "optinrouter")

    def test_rule_never_trusts_a_spoofed_name_in_a_url_userinfo(self):
        # a clean repo whose credentials-in-URL mention a held name must not be refused: userinfo is stripped first
        identity, _ = ident.canonical_repo("https://yates-cloud:pw@github.com/acme/fine.git")
        self.assertIsNone(ident.held_rule(identity=identity))


class NoExecTests(unittest.TestCase):
    """AC-8: repository identity is read from .git files in Python; no process is started."""

    def test_identity_and_held_check_start_no_process_and_agree_with_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp))
            main = make_repo(root / "main", [("origin", "https://github.com/Owner/Repo.git"),
                                             ("up", "https://github.com/up/stream.git")])
            git(main, "worktree", "add", "-q", str(root / "wt"), "-b", "side")
            plain = make_repo(root / "plain")
            bare = root / "bare.git"
            subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, capture_output=True, timeout=30)
            expected = {p: ident.canonical_repo(str(p)) for p in (main, root / "wt", plain)}  # reference run (may exec)
            hits = []
            original = subprocess.Popen.__init__
            subprocess.Popen.__init__ = lambda s, *a, **k: hits.append(a) or (_ for _ in ()).throw(OSError("no exec"))
            try:
                got = {p: ident.canonical_repo(str(p)) for p in (main, root / "wt", plain)}
                held = [ident.held_rule(path=str(p)) for p in (main, root / "wt", plain, bare)]
            finally:
                subprocess.Popen.__init__ = original
            self.assertEqual(hits, [])
            self.assertEqual(got, expected)
            self.assertEqual(got[main], ("github.com/owner/repo", "remote-origin"))
            self.assertEqual(held, [None, None, None, None])
            self.assertEqual(ident.canonical_repo(str(bare))[1], "local")

    def test_gitdir_file_pointing_outside_or_garbage_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp))
            (root / "a").mkdir()
            (root / "a" / ".git").write_text("gitdir: " + str(root / "nowhere") + "\n")
            with self.assertRaises(ident.IdentityError):
                ident.canonical_repo(str(root / "a"))
            (root / "b").mkdir()
            (root / "b" / ".git").write_text("garbage\n")
            with self.assertRaises(ident.IdentityError):
                ident.canonical_repo(str(root / "b"))

    def test_url_with_a_credential_in_the_config_is_reduced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.path.realpath(tmp))
            repo = make_repo(root / "r", [("origin", "https://user:hunter2@github.com/owner/repo.git")])
            identity, _ = ident.canonical_repo(str(repo))
            self.assertEqual(identity, "github.com/owner/repo")


if __name__ == "__main__":
    unittest.main()
