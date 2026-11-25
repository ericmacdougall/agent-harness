"""git_save: save what one checkout holds nowhere else, and prove it.

Real git repositories in a temporary directory with a temporary HOME. A bare repository named as `rescue_remote`
through AH_LOCAL_CONFIG stands in for the remote. No test can reach a real host: the global git config used here
rewrites every https://github.com/acme/ and https://fixture.invalid/ URL to a local bare repository, sends any other
HTTP request to a closed local port, and replaces ssh with `false`.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ah_local  # noqa: E402
import git_save  # noqa: E402

SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
HOST = "testhost"
AT = "@"   # URLs with a user part are put together at run time, so this file holds no credential-shaped literal
LOGIN_URL = "https://user:hunter2" + AT + "fixture.invalid/"


class Case(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(self.make_writable)
        self.root = Path(os.path.realpath(temp.name))
        self.home, self.remotes, fake_bin = self.root / "home", self.root / "remotes", self.root / "bin"
        for folder in (self.home, self.remotes, fake_bin, self.root / "tmp"):
            folder.mkdir()
        self.gh_log, self.gh_answer = self.root / "gh.log", self.root / "gh.answer"
        gh = fake_bin / "gh"   # answers what the test wrote to gh.answer; fails when there is no answer
        gh.write_text('#!/bin/sh\necho "$@" >> "%s"\n[ -f "%s" ] || exit 1\ncat "%s"\n'
                      % (self.gh_log, self.gh_answer, self.gh_answer))
        gh.chmod(0o755)
        (self.home / ".gitconfig").write_text(
            "[user]\n\tname = Test\n\temail = test@fixture.invalid\n[init]\n\tdefaultBranch = main\n"
            "[http]\n\tproxy = http://127.0.0.1:9\n[core]\n\tsshCommand = false\n"
            '[url "%s/"]\n\tinsteadOf = https://fixture.invalid/\n\tinsteadOf = %s\n'
            "\tinsteadOf = https://github.com/acme/\n" % (self.remotes, LOGIN_URL))
        self.config_path = self.home / "local.json"
        env = {"HOME": str(self.home), "AH_LOCAL_CONFIG": str(self.config_path), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": str(self.home / ".gitconfig"), "TMPDIR": str(self.root / "tmp"),
               "GIT_CEILING_DIRECTORIES": str(self.root),
               "PATH": "%s%s%s" % (fake_bin, os.pathsep, os.environ.get("PATH", ""))}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in [key for key in os.environ if key.startswith("GIT_") and key not in env] + ["XDG_CONFIG_HOME"]:
            os.environ.pop(name, None)
        tempfile.tempdir = None   # mkdtemp must follow the TMPDIR set above
        self.addCleanup(setattr, tempfile, "tempdir", None)
        ah_local.reset()
        self.addCleanup(ah_local.reset)
        git_save._HOOKS_OFF.clear()
        self.rescue = self.bare("rescue")
        self.configure(rescue_remote=str(self.rescue))

    def make_writable(self):
        for folder, _dirs, _files in os.walk(self.root):
            os.chmod(folder, 0o700)

    def configure(self, **keys):
        self.config_path.write_text(json.dumps(keys))
        ah_local.reset()

    def git(self, repo, *args, check=True):
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
        if check and done.returncode != 0:
            self.fail("git %s failed: %s" % (" ".join(args), done.stderr))
        return done.stdout.strip()

    def bare(self, name):
        path = self.remotes / (name + ".git")
        subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True)
        return path

    def commit(self, repo, name="file.txt", text="one\n", message="change"):
        (Path(repo) / name).parent.mkdir(parents=True, exist_ok=True)
        (Path(repo) / name).write_text(text)
        self.git(repo, "add", "-f", "--", name)
        self.git(repo, "commit", "-q", "-m", message)
        return self.git(repo, "rev-parse", "HEAD")

    def repo(self, name="work", origin=None):
        """A checkout with one commit. `origin`: a URL to clone from (the clone starts in step with it)."""
        path = self.root / name
        if origin:
            subprocess.run(["git", "clone", "-q", origin, str(path)], check=True, capture_output=True)
        else:
            subprocess.run(["git", "init", "-q", str(path)], check=True)
            self.commit(path, "README.md", "hello\n", "first")
        return path

    def seeded_remote(self, name="proj"):
        """A bare repository with one commit on main, reachable as https://fixture.invalid/<name>.git."""
        seed = self.repo("seed-" + name)
        bare = self.bare(name)
        self.git(seed, "push", "-q", str(bare), "main")
        return bare

    def refs(self, bare, prefix="refs/"):
        out = self.git(bare, "for-each-ref", "--format=%(refname) %(objectname)", prefix)
        return dict(line.split(" ") for line in out.splitlines())

    def save(self, repo, name="work", **kw):
        return git_save.save(repo, SESSION, name, host=HOST, **kw)

    def assert_saved_remote(self, result, remote=None):
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["where"], "remote", result)
        self.assertIsNone(result["reason"])
        there = self.refs(remote or self.rescue)
        for ref, commit in result["refs"].items():
            self.assertEqual(there.get(ref), commit, ref)
        return there

    def ref(self, result, ending):
        found = [ref for ref in result["refs"] if ref.endswith(ending)]
        self.assertEqual(len(found), 1, (ending, result["refs"]))
        return found[0]

    def verify_alone(self, bundle):
        """The bundle is complete: it verifies in a repository that has nothing else."""
        empty = Path(tempfile.mkdtemp(dir=self.root / "remotes"))
        subprocess.run(["git", "init", "-q", str(empty)], check=True)
        self.git(empty, "bundle", "verify", "-q", str(bundle))

    def tree_files(self, repo, commit):
        return set(self.git(repo, "ls-tree", "-r", "--name-only", commit).splitlines())


class Offhost(unittest.TestCase):
    def test_which_urls_are_another_machine(self):
        me = git_save.socket.gethostname()
        for url in ("https://github.com/acme/proj.git", "https://user:pw" + AT + "example.com/x.git",
                    "ssh://git" + AT + "example.com/x", "git@github.com:acme/proj.git", "example.com:path/x.git",
                    "ssh://git" + AT + "[2001:db8::1]:22/x.git", "http://example.com/x.git",
                    "git://example.com/x.git"):
            self.assertTrue(git_save.is_offhost(url), url)
        for url in ("", None, "/srv/git/x.git", "./x", "../x", "~/x", "file:///srv/x.git", "x.git", "sub/dir",
                    "https://localhost/x.git", "ssh://git" + AT + "127.0.0.1/x", "git@localhost:x.git",
                    "https://[::1]/x",
                    "https://%s/x.git" % me, "git@%s:x.git" % me.split(".")[0], "/srv/saved.bundle",
                    "https://example.com/saved.bundle", "ext::ssh example.com x", "gcrypt::/srv/x"):
            self.assertFalse(git_save.is_offhost(url), url)


class Facts(Case):
    def test_a_plain_checkout(self):
        repo = self.repo()
        head = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "tag", "v1")
        f = git_save.facts(repo)
        self.assertEqual(f["errors"], [])
        self.assertEqual((f["toplevel"], f["git_dir"], f["common_dir"]),
                         (str(repo), str(repo / ".git"), str(repo / ".git")))
        self.assertEqual((f["head"], f["branch"], f["linked_worktree"]), (head, "main", False))
        self.assertEqual((f["origin"], f["real_remote"], f["dirty"], f["untracked"]), (None, None, False, 0))
        self.assertEqual(f["tips"], {"heads/main": head, "tags/v1": head})
        self.assertEqual((f["stashes"], f["alternates"], f["worktrees"]), ([], [], []))

    def test_dirty_untracked_stash_and_detached_are_all_seen(self):
        repo = self.repo()
        self.commit(repo, ".gitignore", "ignored.txt\n")
        self.commit(repo, "a.txt", "a\n")
        (repo / "a.txt").write_text("stashed\n")
        self.git(repo, "stash")
        (repo / "a.txt").write_text("changed\n")
        (repo / "new 1.txt").write_text("x")
        (repo / "new2.txt").write_text("x")
        (repo / "ignored.txt").write_text("x")
        self.git(repo, "checkout", "-q", "--detach")
        f = git_save.facts(repo)
        self.assertEqual((f["dirty"], f["untracked"], f["branch"]), (True, 2, None))
        self.assertEqual(len(f["stashes"]), 1)
        self.assertEqual(f["tips"]["stash/0"], self.git(repo, "rev-parse", "refs/stash"))
        self.assertEqual(f["tips"]["detached"], f["head"])

    def test_no_commit_yet_a_bare_repository_and_not_a_checkout(self):
        empty = self.root / "empty"
        subprocess.run(["git", "init", "-q", str(empty)], check=True)
        f = git_save.facts(empty)
        self.assertEqual((f["errors"], f["head"], f["branch"], f["tips"]), ([], None, None, {}))
        f = git_save.facts(self.rescue)
        self.assertEqual((f["errors"], f["toplevel"], f["git_dir"]), ([], None, str(self.rescue)))
        (self.root / "plain").mkdir()
        f = git_save.facts(self.root / "plain")
        self.assertTrue(f["errors"])
        self.assertIsNone(f["toplevel"])
        self.assertFalse(git_save.save(self.root / "plain", SESSION, "plain", host=HOST)["ok"])

    def test_a_local_path_origin_is_followed_to_the_real_remote(self):
        self.seeded_remote("proj")
        first = self.repo("first", origin="https://fixture.invalid/proj.git")
        second = self.repo("second", origin=str(first))
        third = self.repo("third", origin="file://" + str(second))
        self.assertEqual(git_save.facts(first)["real_remote"], "https://fixture.invalid/proj.git")
        f = git_save.facts(third)
        self.assertEqual((f["origin"], f["real_remote"]),
                         ("file://" + str(second), "https://fixture.invalid/proj.git"))
        chain = [third]
        for n in range(5):   # the origin of the last one is five local repositories away from `first`'s remote
            chain.append(self.repo("hop%d" % n, origin=str(chain[-1])))
        self.assertEqual(git_save.facts(chain[3])["real_remote"], "https://fixture.invalid/proj.git")
        self.assertIsNone(git_save.facts(chain[5])["real_remote"])

    def test_a_bundle_origin_and_a_missing_origin_have_no_real_remote(self):
        source = self.repo("source")
        bundle = self.root / "source.bundle"
        self.git(source, "bundle", "create", "-q", str(bundle), "main")
        clone = self.repo("from-bundle", origin=str(bundle))
        self.assertIsNone(git_save.facts(clone)["real_remote"])
        self.git(source, "remote", "add", "origin", str(self.root / "gone"))
        self.assertIsNone(git_save.facts(source)["real_remote"])

    def test_linked_worktrees_and_alternates_are_reported(self):
        repo = self.repo("main-repo")
        linked = self.root / "linked"
        self.git(repo, "worktree", "add", "-q", "-b", "side", str(linked))
        self.assertEqual(git_save.facts(repo)["worktrees"], [str(linked)])
        f = git_save.facts(linked)
        self.assertEqual((f["linked_worktree"], f["common_dir"], f["worktrees"]), (True, str(repo / ".git"), []))
        self.assertEqual(f["git_dir"], str(repo / ".git" / "worktrees" / "linked"))
        borrower = self.root / "borrower"
        subprocess.run(["git", "clone", "-q", "--reference", str(repo), str(repo), str(borrower)], check=True)
        self.assertEqual(git_save.facts(borrower)["alternates"], [str(repo / ".git" / "objects")])


class UnsavedTips(Case):
    def test_reachable_tips_are_saved_and_the_rest_are_not(self):
        bare = self.seeded_remote("proj")
        repo = self.repo(origin="https://fixture.invalid/proj.git")
        self.commit(repo, "pushed.txt")
        self.git(repo, "push", "-q", "origin", "main")
        self.git(repo, "branch", "behind", "HEAD~1")   # an ancestor of what the remote holds
        self.git(repo, "checkout", "-q", "-b", "ahead")
        self.commit(repo, "local.txt")
        names, state = git_save.unsaved_tips(repo, git_save.facts(repo), str(bare))
        self.assertEqual((names, state), (["heads/ahead"], "known"))

    def test_a_failed_ls_remote_means_everything_is_unsaved(self):
        repo = self.repo()
        self.git(repo, "branch", "other")
        names, state = git_save.unsaved_tips(repo, git_save.facts(repo), str(self.root / "no-such-remote"))
        self.assertEqual((names, state), (["heads/main", "heads/other"], "unknown"))

    def test_a_tip_git_cannot_walk_counts_as_unsaved(self):
        bare = self.seeded_remote("proj")
        repo = self.repo(origin="https://fixture.invalid/proj.git")
        tips = {"heads/main": self.git(repo, "rev-parse", "HEAD"), "heads/ghost": "1" * 40}
        self.assertEqual(git_save.unsaved_tips(repo, {"tips": tips}, str(bare)), (["heads/ghost"], "known"))

    def test_a_remote_commit_that_is_not_local_vouches_for_nothing(self):
        bare = self.seeded_remote("proj")
        repo = self.repo()
        self.git(repo, "commit", "-q", "--amend", "-m", "an unrelated history")
        names, state = git_save.unsaved_tips(repo, git_save.facts(repo), str(bare))
        self.assertEqual((names, state), (["heads/main"], "known"))


class Snapshot(Case):
    def untouched(self, repo):
        index = repo / ".git" / "index"
        return (hashlib.sha256(index.read_bytes()).hexdigest(), self.git(repo, "status", "--porcelain=v1", "-uall"),
                self.git(repo, "for-each-ref"), self.git(repo, "rev-parse", "HEAD"), self.git(repo, "stash", "list"))

    def test_tracked_changes_and_untracked_files_are_captured_without_touching_the_checkout(self):
        repo = self.repo()
        self.commit(repo, "gone.txt")
        (repo / ".gitignore").write_text("*.log\n")
        self.git(repo, "add", ".gitignore")
        (repo / "README.md").write_text("edited\n")
        (repo / "sub").mkdir()
        (repo / "sub" / "new file.txt").write_text("new\n")
        (repo / "debug.log").write_text("ignored\n")
        (repo / "gone.txt").unlink()
        before = self.untouched(repo)
        commit, held = git_save.snapshot(repo, SESSION)
        self.assertEqual(self.untouched(repo), before)
        self.assertEqual(held, [])
        self.assertEqual(self.git(repo, "rev-parse", commit + "^"), before[3])
        self.assertEqual(self.tree_files(repo, commit), {".gitignore", "README.md", "sub/new file.txt"})
        self.assertEqual(self.git(repo, "show", commit + ":README.md"), "edited")
        self.assertEqual(git_save.snapshot(repo, SESSION)[0], commit)   # same tree, same day: same commit

    def test_a_clean_checkout_has_no_snapshot(self):
        repo = self.repo()
        self.assertEqual(git_save.snapshot(repo, SESSION), (None, []))

    def test_secret_shaped_oversized_and_special_files_are_held_back(self):
        repo = self.repo()
        self.commit(repo, ".npmrc", "registry=https://fixture.invalid\n")
        (repo / ".npmrc").write_text("registry=https://other.invalid\n")
        for name in (".env", ".env.production", "deploy.pem", "id_rsa", "aws-credentials.json", "prod.tfvars",
                     "nested/dir/auth.json", "Server.KEY"):
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text("value\n")
        self.git(repo, "add", "-f", "deploy.pem")   # staged: still never in a snapshot
        (repo / "big.bin").write_bytes(b"x" * 5000)
        (repo / "notes.txt").write_text("keep me\n")
        os.symlink("/etc/hosts", repo / "link")
        os.mkfifo(repo / "pipe")
        with mock.patch.object(git_save, "MAX_FILE", 4096):
            commit, held = git_save.snapshot(repo, SESSION)
        reasons = {item["path"]: item["reason"] for item in held}
        secrets = {".npmrc", ".env", ".env.production", "deploy.pem", "id_rsa", "aws-credentials.json", "prod.tfvars",
                   "nested/dir/auth.json", "Server.KEY"}
        self.assertEqual({path for path, why in reasons.items() if why == "secret-shaped name"}, secrets)
        self.assertEqual(reasons["big.bin"], "over 20 MB")
        self.assertEqual(reasons["link"], "not a regular file")
        self.assertNotIn("pipe", reasons)   # git never lists a FIFO, and it holds nothing to save
        self.assertEqual(self.tree_files(repo, commit), {"README.md", ".npmrc", "notes.txt"})
        self.assertEqual(self.git(repo, "show", commit + ":.npmrc"), "registry=https://fixture.invalid")

    def test_a_repository_with_no_commit_yet(self):
        repo = self.root / "fresh"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self.assertEqual(git_save.snapshot(repo, SESSION), (None, []))
        (repo / "draft.txt").write_text("draft\n")
        (repo / ".env").write_text("A=1\n")
        self.git(repo, "add", ".env")
        commit, held = git_save.snapshot(repo, SESSION)
        self.assertEqual(self.tree_files(repo, commit), {"draft.txt"})
        self.assertEqual(self.git(repo, "rev-list", "--count", commit), "1")
        self.assertEqual([item["path"] for item in held], [".env"])

    def test_files_hidden_from_git_status_are_captured(self):
        repo = self.repo()
        self.commit(repo, "a.txt", "a\n")
        self.commit(repo, "b.txt", "b\n")
        self.git(repo, "update-index", "--assume-unchanged", "a.txt")
        self.git(repo, "update-index", "--skip-worktree", "b.txt")
        (repo / "a.txt").write_text("hidden a\n")
        (repo / "b.txt").write_text("hidden b\n")
        self.assertEqual(self.git(repo, "status", "--porcelain"), "")
        commit, _held = git_save.snapshot(repo, SESSION)
        self.assertEqual(self.git(repo, "show", commit + ":a.txt"), "hidden a")
        self.assertEqual(self.git(repo, "show", commit + ":b.txt"), "hidden b")
        self.assertEqual(self.git(repo, "ls-files", "-v"), "H README.md\nh a.txt\nS b.txt")   # the real index is kept

    def test_a_merge_conflict_is_captured_as_it_stands(self):
        repo = self.repo()
        self.git(repo, "checkout", "-q", "-b", "side")
        self.commit(repo, "README.md", "side\n")
        self.git(repo, "checkout", "-q", "main")
        self.commit(repo, "README.md", "main\n")
        self.git(repo, "merge", "side", check=False)
        self.assertIn("UU README.md", self.git(repo, "status", "--porcelain"))
        commit, held = git_save.snapshot(repo, SESSION)
        self.assertEqual(held, [])
        self.assertIn("<<<<<<<", self.git(repo, "show", commit + ":README.md"))
        self.assertIn("UU README.md", self.git(repo, "status", "--porcelain"))

    def test_a_nested_checkout_is_left_to_its_own_save(self):
        repo = self.repo()
        self.repo("work/inner")
        (repo / "loose.txt").write_text("x")
        commit, held = git_save.snapshot(repo, SESSION)
        self.assertEqual(held, [])
        self.assertEqual(self.tree_files(repo, commit), {"README.md", "loose.txt"})

    def test_no_hook_of_the_repository_runs(self):
        repo = self.repo()
        marker = self.root / "hook-ran"
        for name in ("pre-push", "post-index-change", "reference-transaction", "pre-commit", "post-commit"):
            hook = repo / ".git" / "hooks" / name
            hook.write_text("#!/bin/sh\ntouch '%s'\n" % marker)
            hook.chmod(0o755)
        self.git(repo, "config", "hook.spy.command", "touch '%s'" % marker)
        for event in ("post-index-change", "pre-push", "reference-transaction"):
            self.git(repo, "config", "--add", "hook.spy.event", event)
        marker.unlink(missing_ok=True)   # the config commands above may have fired a hook themselves
        (repo / "README.md").write_text("edited\n")
        (repo / ".env").write_text("A=1\n")
        self.assert_saved_remote(self.save(repo))
        self.configure(rescue_remote=str(self.root / "missing"))
        self.assertEqual(self.save(repo, fresh=True)["where"], "bundle")
        self.assertFalse(marker.exists())


class IgnoredKeepers(Case):
    def test_ignored_files_worth_keeping_are_listed_and_rebuildable_output_is_not(self):
        repo = self.repo()
        (repo / ".gitignore").write_text(".env\n*.local\n*.sqlite\nnode_modules/\n__pycache__/\n*.pyc\ndist/\nbuild/\n"
                                         "target/\ndata/\nhuge.bin\nouter/\n")
        (repo / "Cargo.toml").write_text("[package]\n")
        files = {".env": "A=1\n", "settings.local": "x", "dev.sqlite": "db", "node_modules/pkg/.env": "x",
                 "src/__pycache__/m.pyc": "x", "src/keep.pyc": "x", "dist/app.js": "x", "build/out.o": "x",
                 "target/debug/app": "x", "data/run1/result.json": "{}", "data/node_modules/x.js": "x",
                 "data/dist/y.js": "y", "sub/target/note.txt": "kept: no Cargo.toml beside it",
                 "untracked/inner/.env": "B=2\n", "untracked/visible.txt": "x", "huge.bin": "x" * 5000,
                 "outer/inner-repo/.env": "C=3\n"}
        for name, text in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text)
        subprocess.run(["git", "init", "-q", str(repo / "outer" / "inner-repo")], check=True)
        os.symlink("/etc/hosts", repo / "link.local")
        with mock.patch.object(git_save, "MAX_FILE", 4096):
            found = git_save.ignored_keepers(repo)
        self.assertEqual(found, [".env", "data/run1/result.json", "dev.sqlite", "settings.local", "src/keep.pyc",
                                 "sub/target/note.txt", "untracked/inner/.env"])

    def test_rebuildable_names(self):
        base = self.root / "r"
        (base / "java").mkdir(parents=True)
        (base / "java" / "pom.xml").write_text("<project/>")
        self.assertTrue(git_save.rebuildable(str(base / "node_modules")))
        self.assertTrue(git_save.rebuildable(str(base / "java" / "target")))
        self.assertFalse(git_save.rebuildable(str(base / "target")))
        self.assertFalse(git_save.rebuildable(str(base / "dist")))
        self.assertTrue(git_save.rebuildable(str(base / "dist"), ignored=True))
        self.assertFalse(git_save.rebuildable(str(base / "src"), ignored=True))

    def test_too_many_ignored_files_is_an_error_not_a_guess(self):
        repo = self.repo()
        (repo / ".gitignore").write_text("data/\n")
        (repo / "data").mkdir()
        for n in range(6):
            (repo / "data" / ("f%d" % n)).write_text("x")
        with mock.patch.object(git_save, "MAX_KEEPERS", 5):
            with self.assertRaises(git_save.SaveError):
                git_save.ignored_keepers(repo)
            result = self.save(repo)
        self.assertFalse(result["ok"])
        self.assertIn("ignored files", result["reason"])


class Destination(Case):
    def origin_facts(self):
        return {"real_remote": "https://github.com/acme/proj.git"}

    def test_the_rescue_remote_takes_everything(self):
        got = git_save.destination(self.origin_facts())
        self.assertEqual((got["kind"], got["url"]), ("remote", str(self.rescue)))
        self.assertFalse(self.gh_log.exists())

    def test_the_origin_is_used_only_as_rescue_to_origin_allows(self):
        self.configure(rescue_to_origin="never")
        self.assertEqual(git_save.destination(self.origin_facts())["kind"], "bundle")
        self.configure(rescue_to_origin="always")
        self.assertEqual(git_save.destination(self.origin_facts())["url"], "https://github.com/acme/proj.git")
        self.assertEqual(git_save.destination({"real_remote": None})["kind"], "bundle")
        self.assertFalse(self.gh_log.exists())

    def test_private_needs_proof_and_any_failure_counts_as_not_private(self):
        for config in ({}, {"rescue_to_origin": "private"}, {"rescue_to_origin": "bogus"}, {"rescue_to_origin": 7}):
            self.configure(**config)
            self.assertEqual(git_save.destination(self.origin_facts())["kind"], "bundle", config)   # gh fails
        self.assertEqual(self.gh_log.read_text().splitlines()[0], "api repos/acme/proj --jq .private")
        self.gh_answer.write_text("false\n")
        self.assertEqual(git_save.destination(self.origin_facts())["kind"], "bundle")
        self.gh_answer.write_text("true\n")
        self.assertEqual(git_save.destination(self.origin_facts())["kind"], "bundle")   # the "no" is cached
        self.assertEqual(git_save.destination({"real_remote": "https://fixture.invalid/x.git"})["kind"], "bundle")

    def test_a_private_answer_is_cached_for_a_day_under_the_temporary_home(self):
        self.configure()
        self.gh_answer.write_text("true\n")
        self.assertEqual(git_save.destination(self.origin_facts())["url"], "https://github.com/acme/proj.git")
        self.gh_answer.unlink()
        calls = len(self.gh_log.read_text().splitlines())
        self.assertEqual(git_save.destination(self.origin_facts())["kind"], "remote")
        self.assertEqual(len(self.gh_log.read_text().splitlines()), calls)
        cache = list((self.home / ".agent-harness" / "state" / "git-save").glob("private-*.json"))
        self.assertEqual(len(cache), 1)
        data = json.loads(cache[0].read_text())
        data["at"] -= 25 * 3600
        cache[0].write_text(json.dumps(data))
        self.assertEqual(git_save.destination(self.origin_facts())["kind"], "bundle")   # stale, and gh now fails


class SaveToRemote(Case):
    def test_an_unpushed_branch_a_tag_a_detached_head_and_a_stash(self):
        repo = self.repo()
        main = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "checkout", "-q", "-b", "feature/x")
        feature = self.commit(repo, "f.txt")
        self.git(repo, "tag", "-a", "-m", "release", "v1")
        (repo / "f.txt").write_text("stashed\n")
        (repo / "untracked-in-stash.txt").write_text("u\n")
        self.git(repo, "stash", "push", "-q", "--include-untracked")
        self.git(repo, "checkout", "-q", "--detach")
        detached = self.commit(repo, "d.txt")
        result = self.save(repo)
        there = self.assert_saved_remote(result)
        base = "refs/rescue/%s/%s/work-%s/" % (HOST, SESSION, hashlib.sha256(str(repo).encode()).hexdigest()[:8])
        self.assertEqual(result["refs"], {
            base + "heads/main": main, base + "heads/feature/x": feature, base + "detached": detached,
            base + "tags/v1": self.git(repo, "rev-parse", "refs/tags/v1"),
            base + "stash/0": self.git(repo, "rev-parse", "refs/stash")})
        self.assertEqual(there, result["refs"])
        self.assertEqual((result["url"], result["bundle"], result["held"]), (str(self.rescue), None, []))
        restored = self.root / "restored"
        subprocess.run(["git", "init", "-q", str(restored)], check=True)
        self.git(restored, "fetch", "-q", str(self.rescue), "refs/rescue/%s/%s/*:refs/rescue/*" % (HOST, SESSION))
        stash = self.git(restored, "for-each-ref", "--format=%(refname)", "refs/rescue/*/stash/0")
        self.assertEqual(self.git(restored, "show", stash + ":f.txt"), "stashed")
        self.assertEqual(self.git(restored, "show", stash + "^3:untracked-in-stash.txt"), "u")

    def test_a_commit_kept_only_by_a_local_rescue_ref_is_saved(self):
        repo = self.repo()
        self.git(repo, "checkout", "-q", "-b", "gone")
        lost = self.commit(repo, "lost.txt")
        self.git(repo, "update-ref", "refs/rescue/gone", lost)   # what `ah worktree --rescue` leaves behind
        self.git(repo, "checkout", "-q", "main")
        self.git(repo, "branch", "-q", "-D", "gone")
        result = self.save(repo)
        self.assert_saved_remote(result)
        self.assertEqual(result["refs"][self.ref(result, "/rescue/gone")], lost)

    def test_a_dirty_tracked_file_and_an_untracked_file_go_into_a_snapshot_ref(self):
        repo = self.repo()
        (repo / "README.md").write_text("edited\n")
        (repo / "new.txt").write_text("new\n")
        result = self.save(repo)
        self.assert_saved_remote(result)
        snapshot = result["refs"][self.ref(result, "/snapshot")]
        self.assertEqual(self.git(self.rescue, "show", snapshot + ":README.md"), "edited")
        self.assertEqual(self.git(self.rescue, "show", snapshot + ":new.txt"), "new")
        self.assertEqual(self.git(repo, "status", "--porcelain"), " M README.md\n?? new.txt".strip())
        (repo / "new.txt").write_text("newer\n")   # the next save moves the snapshot ref (forced inside refs/rescue/)
        again = self.save(repo)
        self.assert_saved_remote(again)
        moved = again["refs"][self.ref(again, "/snapshot")]
        self.assertEqual(self.git(self.rescue, "show", moved + ":new.txt"), "newer")

    def test_held_files_are_copied_private_and_never_pushed(self):
        repo = self.repo()
        (repo / ".gitignore").write_text(".env\nnode_modules/\n")
        self.git(repo, "add", ".gitignore")
        (repo / ".env").write_text("COLOUR=blue\n")            # ignored: a keeper
        (repo / "conf").mkdir()
        (repo / "conf" / "deploy.pem").write_text("pem\n")                # untracked, secret-shaped: held back
        (repo / "big.bin").write_bytes(b"x" * 5000)                        # untracked, oversized: held back
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "lib.js").write_text("x")
        os.symlink("conf/deploy.pem", repo / "link")
        with mock.patch.object(git_save, "MAX_FILE", 4096):
            result = self.save(repo)
        self.assert_saved_remote(result)
        self.assertEqual(result["held"], [".env", "big.bin", "conf/deploy.pem", "link"])
        held = Path(result["held_dir"])
        self.assertEqual(held.relative_to(self.home / ".agent-harness" / "rescue" / "held").parts[:2], (HOST, SESSION))
        self.assertEqual((held / ".env").read_text(), "COLOUR=blue\n")
        self.assertEqual((held / "big.bin").stat().st_size, 5000)
        self.assertEqual(os.readlink(held / "link"), "conf/deploy.pem")
        for path in (held / ".env", held / "conf" / "deploy.pem", held / "big.bin"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        folder = held / "conf"
        while folder != self.home / ".agent-harness":
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700, folder)
            folder = folder.parent
        snapshot = result["refs"][self.ref(result, "/snapshot")]
        self.assertEqual(self.tree_files(self.rescue, snapshot), {"README.md", ".gitignore"})
        (repo / ".env").write_text("COLOUR=green\n")
        self.assertTrue(self.save(repo)["ok"])
        self.assertEqual((held / ".env").read_text(), "COLOUR=green\n")

    def test_held_files_too_large_is_not_ok_but_the_commits_are_still_pushed(self):
        repo = self.repo()
        (repo / ".env").write_text("x" * 600)
        (repo / "deploy.key").write_text("y" * 600)
        with mock.patch.object(git_save, "HELD_MAX", 1000):
            result = self.save(repo)
        self.assertEqual((result["ok"], result["reason"], result["held"]), (False, "held files too large", []))
        self.assertEqual(result["where"], "remote")
        self.assertEqual(self.refs(self.rescue), result["refs"])
        self.assertFalse((self.home / ".agent-harness" / "rescue" / "held").exists())

    def test_nothing_to_save_when_the_real_remote_has_it_all(self):
        self.seeded_remote("proj")
        repo = self.repo(origin="https://fixture.invalid/proj.git")
        copy = self.repo("copy", origin=str(repo))   # its origin is a local path; the real remote is found through it
        for checkout in (repo, copy):
            result = self.save(checkout)
            self.assertEqual((result["ok"], result["where"], result["refs"], result["url"], result["bundle"]),
                             (True, "nothing", {}, None, None), result)
        self.assertEqual(self.refs(self.rescue), {})
        self.assertFalse((self.home / ".agent-harness" / "rescue").exists())

    def test_only_what_the_real_remote_lacks_is_pushed(self):
        self.seeded_remote("proj")
        repo = self.repo(origin="https://fixture.invalid/proj.git")
        copy = self.repo("copy", origin=str(repo))
        self.git(copy, "checkout", "-q", "-b", "topic")
        topic = self.commit(copy, "t.txt")
        result = self.save(copy, name="copy")
        self.assert_saved_remote(result)
        self.assertEqual(list(result["refs"].values()), [topic])
        self.assertTrue(self.ref(result, "/heads/topic"))

    def test_the_checkout_own_remote_is_used_when_allowed_and_credentials_are_not_shown(self):
        bare = self.seeded_remote("proj")
        repo = self.repo(origin=LOGIN_URL + "proj.git")
        self.commit(repo, "local.txt")
        self.configure(rescue_to_origin="always")
        result = self.save(repo)
        self.assert_saved_remote(result, bare)
        self.assertEqual(result["url"], "https://fixture.invalid/proj.git")
        self.assertNotIn("hunter2", json.dumps(result))
        self.assertEqual(self.git(bare, "rev-parse", "refs/heads/main"), self.git(repo, "rev-parse", "HEAD~1"))
        self.assertEqual(self.save(repo, fresh=True)["where"], "nothing")   # the rescue ref on the remote vouches now

    def test_a_private_origin_is_used_and_a_public_one_gets_a_bundle(self):
        bare = self.seeded_remote("proj")
        repo = self.repo(origin="https://github.com/acme/proj.git")
        self.commit(repo, "local.txt")
        self.configure()
        self.gh_answer.write_text("true\n")
        self.assert_saved_remote(self.save(repo), bare)
        other = self.repo("other", origin="https://github.com/acme/proj.git")
        self.git(other, "remote", "set-url", "origin", "https://github.com/acme/public.git")
        self.bare("public")
        self.commit(other, "local.txt")
        self.gh_answer.write_text("false\n")
        result = self.save(other, name="other")
        self.assertEqual((result["ok"], result["where"]), (True, "bundle"), result)
        self.assertEqual(self.refs(self.remotes / "public.git"), {})

    def test_a_remote_that_rejects_the_custom_namespace_gets_branches(self):
        hook = self.rescue / "hooks" / "update"
        hook.write_text('#!/bin/sh\ncase "$1" in refs/rescue/*) echo "no custom refs here" >&2; exit 1;; esac\n')
        hook.chmod(0o755)
        repo = self.repo()
        real, pushes = git_save._git, []

        def spy(where, *args, **kw):
            if args[0] == "push":
                pushes.append(args)
            return real(where, *args, **kw)

        with mock.patch.object(git_save, "_git", side_effect=spy):
            result = self.save(repo)
        there = self.assert_saved_remote(result)
        self.assertEqual(set(there), set(result["refs"]))
        self.assertTrue(self.ref(result, "/heads/main").startswith("refs/heads/rescue/%s/%s/work-" % (HOST, SESSION)))
        self.assertEqual(len(pushes), 2)   # the rescue namespace, then one retry as branches
        for args, forced, namespace in zip(pushes, (True, False), ("refs/rescue/", "refs/heads/rescue/")):
            self.assertEqual(args[:5], ("push", "--no-verify", "--quiet", "--", str(self.rescue)))
            for spec in args[5:]:   # a forced update only ever inside refs/rescue/
                self.assertEqual(spec.startswith("+"), forced, spec)
                self.assertTrue(spec.split(":")[1].startswith(namespace), spec)

    def test_two_checkouts_with_the_same_name_never_share_refs(self):
        one, two = self.repo("a/app"), self.repo("b/app")
        first, second = self.save(one, name="app"), self.save(two, name="app")
        self.assert_saved_remote(first)
        self.assert_saved_remote(second)
        self.assertFalse(set(first["refs"]) & set(second["refs"]))
        self.assertEqual(len(self.refs(self.rescue)), 2)

    def test_names_are_made_safe_for_refs_and_paths(self):
        repo = self.repo()
        result = git_save.save(repo, "../se ss/..", "my repo@{1}.lock", host="ho st")
        self.assert_saved_remote(result)
        self.assertRegex(self.ref(result, "/heads/main"),
                         r"^refs/rescue/ho-st/se-ss/my-repo-1-[0-9a-f]{8}/heads/main$")

    def test_a_linked_worktree_and_its_parent_in_both_orders(self):
        for order in ("worktree first", "parent first"):
            with self.subTest(order):
                parent = self.repo("parent-" + order.split()[0])
                linked = self.root / ("linked-" + order.split()[0])
                self.git(parent, "worktree", "add", "-q", "-b", "side", str(linked))
                side = self.commit(linked, "side.txt")
                (linked / "wip.txt").write_text("worktree wip\n")
                (parent / "README.md").write_text("parent wip\n")
                pair = [(linked, "linked"), (parent, "parent")]
                results = {name: self.save(path, name=name)
                           for path, name in (pair if order == "worktree first" else pair[::-1])}
                for result in results.values():
                    self.assert_saved_remote(result)
                self.assertEqual(results["linked"]["refs"][self.ref(results["linked"], "/heads/side")], side)
                wip = results["linked"]["refs"][self.ref(results["linked"], "/snapshot")]
                self.assertEqual(self.git(self.rescue, "show", wip + ":wip.txt"), "worktree wip")
                self.assertEqual(self.git(self.rescue, "show", wip + ":README.md"), "hello")
                mine = results["parent"]["refs"][self.ref(results["parent"], "/snapshot")]
                self.assertEqual(self.git(self.rescue, "show", mine + ":README.md"), "parent wip")
                self.assertNotIn("wip.txt", self.tree_files(self.rescue, mine))

    def test_a_checkout_that_borrows_objects_through_alternates(self):
        lender = self.repo("lender")
        borrower = self.root / "borrower"
        subprocess.run(["git", "clone", "-q", "--shared", str(lender), str(borrower)], check=True)
        own = self.commit(borrower, "own.txt")
        result = self.save(borrower, name="borrower")
        self.assert_saved_remote(result)
        self.assertEqual(self.git(self.rescue, "rev-list", "--count", own), "2")   # the borrowed history went along
        self.configure(rescue_remote=str(self.root / "missing"))
        bundled = self.save(borrower, name="borrower", fresh=True)
        self.assertEqual((bundled["ok"], bundled["where"]), (True, "bundle"), bundled)
        self.verify_alone(bundled["bundle"])


class Proof(Case):
    def test_a_push_that_succeeds_but_leaves_no_ref_is_not_proof(self):
        hook = self.rescue / "hooks" / "post-receive"   # the remote accepts the push, then drops the ref
        hook.write_text('#!/bin/sh\nwhile read old new ref; do git update-ref -d "$ref"; done\n')
        hook.chmod(0o755)
        repo = self.repo()
        head = self.git(repo, "rev-parse", "HEAD")
        self.assertEqual(self.git(repo, "push", "--porcelain", str(self.rescue), "HEAD:refs/rescue/probe").split()[-1],
                         "Done")
        self.assertIsNone(git_save._push(str(repo), str(self.rescue), "refs/rescue/x/", {"heads/main": head}, True))
        result = self.save(repo)
        self.assertEqual(self.refs(self.rescue), {})
        self.assertEqual((result["ok"], result["where"], result["url"]), (True, "bundle", None), result)
        self.verify_alone(result["bundle"])
        blocked = self.home / ".agent-harness" / "rescue"   # and with no place for a bundle the save is not ok
        os.rename(blocked, self.root / "moved-rescue")
        blocked.write_text("not a directory")
        result = self.save(repo, fresh=True)
        self.assertEqual((result["ok"], result["where"], result["refs"], result["bundle"]),
                         (False, "nothing", {}, None))
        self.assertTrue(result["reason"])

    def test_a_ref_with_another_commit_id_is_not_proof(self):
        hook = self.rescue / "hooks" / "post-receive"   # the remote moves every pushed ref to another commit
        other = self.repo("other")
        self.git(other, "push", "-q", str(self.rescue), "main:refs/heads/elsewhere")
        hook.write_text('#!/bin/sh\nwhile read old new ref; do git update-ref "$ref" refs/heads/elsewhere; done\n')
        hook.chmod(0o755)
        repo = self.repo()
        self.commit(repo, "more.txt")
        result = self.save(repo)
        self.assertEqual((result["ok"], result["where"]), (True, "bundle"), result)

    def test_an_unexpected_error_is_a_reason_to_keep_not_a_crash(self):
        repo = self.repo()
        with mock.patch.object(git_save, "facts", side_effect=RuntimeError("boom")):
            result = self.save(repo)
        self.assertEqual((result["ok"], result["reason"]), (False, "RuntimeError: boom"))
        self.assertIsNone(git_save._DEADLINE[0])

    def test_a_ref_without_a_commit_id_is_never_ok(self):
        repo = self.repo()
        real = git_save.facts(repo)
        with mock.patch.object(git_save, "facts", return_value=dict(real, tips={"heads/main": ""})):
            result = self.save(repo)
        self.assertEqual((result["ok"], result["reason"]), (False, "a ref has no commit id"))
        self.assertEqual(self.refs(self.rescue), {})

    def test_a_failed_push_falls_back_to_a_verified_bundle(self):
        self.configure(rescue_remote=str(self.root / "no-such-remote"))
        repo = self.repo()
        self.git(repo, "checkout", "-q", "-b", "topic")
        topic = self.commit(repo, "t.txt")
        self.git(repo, "tag", "v1")
        (repo / "wip.txt").write_text("wip\n")
        refs_before = self.git(repo, "for-each-ref")
        result = self.save(repo)
        self.assertEqual((result["ok"], result["where"], result["url"], result["reason"]),
                         (True, "bundle", None, None))
        bundle = Path(result["bundle"])
        self.assertEqual(bundle.parent, self.home / ".agent-harness" / "rescue" / HOST / SESSION)
        self.assertFalse(str(bundle).startswith(str(repo) + os.sep))
        self.assertEqual(self.git(repo, "for-each-ref"), refs_before)
        self.verify_alone(bundle)
        manifest = json.loads(bundle.with_suffix(".json").read_text())
        self.assertEqual((manifest["repo"], manifest["refs"]), (str(repo), result["refs"]))
        clone = self.root / "from-bundle"
        subprocess.run(["git", "clone", "-q", str(bundle), str(clone)], check=True, capture_output=True)
        self.assertEqual(self.git(clone, "rev-parse", "origin/topic", "v1"), topic + "\n" + topic)
        self.assertEqual(self.git(clone, "show", "origin/rescue/snapshot:wip.txt"), "wip")
        self.assertEqual(sorted(result["refs"]), ["refs/heads/main", "refs/heads/rescue/snapshot", "refs/heads/topic",
                                                  "refs/tags/v1"])

    def test_a_bundle_leaves_out_what_the_real_remote_already_has(self):
        self.seeded_remote("proj")
        repo = self.repo(origin="https://fixture.invalid/proj.git")
        self.git(repo, "checkout", "-q", "-b", "topic")
        topic = self.commit(repo, "t.txt")
        self.configure(rescue_to_origin="never")
        result = self.save(repo)
        self.assertEqual((result["ok"], result["where"], result["refs"]),
                         (True, "bundle", {"refs/heads/topic": topic}))
        fresh = self.repo("fresh", origin="https://fixture.invalid/proj.git")   # the remote plus the bundle is enough
        self.git(fresh, "bundle", "verify", "-q", result["bundle"])
        self.git(fresh, "fetch", "-q", result["bundle"], "refs/heads/topic:refs/heads/topic")
        self.assertEqual(self.git(fresh, "rev-parse", "topic"), topic)
        empty = self.root / "empty"
        subprocess.run(["git", "init", "-q", str(empty)], check=True)
        self.assertNotEqual(subprocess.run(["git", "-C", str(empty), "bundle", "verify", "-q", result["bundle"]],
                                           capture_output=True).returncode, 0)

    def test_a_bundle_is_never_written_inside_the_checkout(self):
        repo = self.repo()
        f = git_save.facts(repo)
        with self.assertRaisesRegex(git_save.SaveError, "inside the checkout"):
            git_save._bundle(f, {"heads/main": f["head"]}, [], str(repo / "saved" / "x.bundle"))
        self.assertFalse((repo / "saved").exists())

    def test_a_bundle_that_does_not_verify_is_not_kept(self):
        self.configure(rescue_remote=str(self.root / "no-such-remote"))
        repo = self.repo()
        real = git_save._git

        def failing_verify(where, *args, **kw):
            return (1, "", "error: bad bundle") if args[:2] == ("bundle", "verify") else real(where, *args, **kw)

        with mock.patch.object(git_save, "_git", side_effect=failing_verify):
            result = self.save(repo)
        self.assertEqual((result["ok"], result["where"], result["bundle"]), (False, "nothing", None))
        self.assertIn("bundle", result["reason"])
        self.assertEqual(list((self.home / ".agent-harness" / "rescue").rglob("*.bundle*")), [])


class StateAndLimits(Case):
    def network_calls(self, repo, **kw):
        real, seen = git_save._git, []

        def spy(where, *args, **kwargs):
            seen.append(args[0])
            return real(where, *args, **kwargs)

        with mock.patch.object(git_save, "_git", side_effect=spy):
            result = self.save(repo, **kw)
        return result, [name for name in seen if name in ("push", "ls-remote", "fetch")]

    def test_an_unchanged_checkout_costs_no_network_call(self):
        repo = self.repo()
        (repo / "wip.txt").write_text("wip\n")
        first, calls = self.network_calls(repo)
        self.assertEqual(calls, ["push", "ls-remote"])
        again, calls = self.network_calls(repo)
        self.assertEqual(calls, [])
        self.assertEqual(again, first)
        state = list((self.home / ".agent-harness" / "state" / "git-save").glob("*.json"))
        self.assertEqual([path.name for path in state], [hashlib.sha256(str(repo).encode()).hexdigest() + ".json"])
        self.assertEqual(stat.S_IMODE(state[0].stat().st_mode), 0o600)
        _result, calls = self.network_calls(repo, fresh=True)   # the proof is made again on request
        self.assertEqual(calls, ["push", "ls-remote"])
        (repo / "wip.txt").write_text("more wip\n")             # a changed working tree
        _result, calls = self.network_calls(repo)
        self.assertEqual(calls, ["push", "ls-remote"])
        self.commit(repo, "wip.txt", "committed\n")              # a new commit
        _result, calls = self.network_calls(repo)
        self.assertEqual(calls, ["push", "ls-remote"])

    def test_a_cached_bundle_that_has_gone_is_made_again(self):
        self.configure(rescue_remote=str(self.root / "no-such-remote"))
        repo = self.repo()
        first = self.save(repo)
        os.unlink(first["bundle"])
        again = self.save(repo)
        self.assertTrue(again["ok"])
        self.assertTrue(os.path.isfile(again["bundle"]))

    def test_a_failed_save_is_tried_again_next_time(self):
        self.configure(rescue_remote=str(self.root / "no-such-remote"))
        repo = self.repo()
        blocked = self.home / ".agent-harness" / "rescue"
        blocked.parent.mkdir(parents=True, exist_ok=True)
        blocked.write_text("not a directory")
        self.assertFalse(self.save(repo)["ok"])
        blocked.unlink()
        self.assertTrue(self.save(repo)["ok"])

    def test_no_time_left_means_not_ok(self):
        repo = self.repo()
        result = self.save(repo, budget_s=0)
        self.assertFalse(result["ok"])
        self.assertIn("time budget", result["reason"])
        self.assertEqual(self.refs(self.rescue), {})
        self.assertIsNone(git_save._DEADLINE[0])

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_a_read_only_tree(self):
        clean = self.repo("clean")
        dirty = self.repo("dirty")
        (dirty / "wip.txt").write_text("wip\n")
        for repo in (clean, dirty):
            for folder, _dirs, files in os.walk(repo):
                for name in files:
                    os.chmod(os.path.join(folder, name), 0o400)
                os.chmod(folder, 0o500)
        result = self.save(clean, name="clean")   # reading is enough to push commits
        self.assert_saved_remote(result)
        result = self.save(dirty, name="dirty")   # a snapshot needs new objects: it cannot be made, so keep
        self.assertFalse(result["ok"])
        self.assertIn("git", result["reason"])

    def test_a_bare_repository_is_saved_without_a_snapshot(self):
        source = self.repo("source")
        bare = self.root / "mirror.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(source), str(bare)], check=True)
        result = self.save(bare, name="mirror")
        self.assert_saved_remote(result)
        self.assertEqual((result["held"], result["held_dir"]), ([], None))

    def test_nothing_is_written_outside_the_temporary_home_and_the_remote(self):
        repo = self.repo()
        (repo / ".env").write_text("A=1\n")
        self.assertTrue(self.save(repo)["ok"])
        top = sorted(path.name for path in (self.home / ".agent-harness").iterdir())
        self.assertEqual(top, ["rescue", "state"])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["bin", "home", "remotes", "tmp", "work"])
        self.assertEqual(list((self.root / "tmp").iterdir()), [])   # scratch indexes and repositories are removed


if __name__ == "__main__":
    unittest.main()
