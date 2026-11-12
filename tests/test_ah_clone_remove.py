"""`ah clone-remove` (goodqa#15743): real temporary repositories under a temporary HOME, a fake network (one patched
ls-remote), no process outside the test touched. Everything removed here lives under a temporary directory."""
import errno
import io
import json
import os
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import clone_remove as cr  # noqa: E402
import command_guard as cg  # noqa: E402

REAL_LSOF = cr._lsof_open
URL = "https://github.com/acme/widgets.git"
SESSION = "sess-1"
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")


def git(cwd, *args, check=True):
    done = subprocess.run(["git", "-c", "protocol.file.allow=always", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if check and done.returncode:
        raise AssertionError("git %s: %s" % (" ".join(args), done.stderr))
    return done.stdout.strip()


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ah-cr-")
        self.addCleanup(self.temp.cleanup)
        self.tmp = os.path.realpath(self.temp.name)
        self.home = os.path.join(self.tmp, "home")
        self.receipts = os.path.join(self.home, ".agent-harness", "work", SESSION, "receipts")
        os.makedirs(self.receipts)
        self.origin = os.path.join(self.tmp, "origin.git")
        git(self.tmp, "init", "-q", "--bare", "-b", "main", self.origin)
        git(self.origin, "config", "uploadpack.allowFilter", "true")
        git(self.origin, "config", "uploadpack.allowAnySHA1InWant", "true")
        seed = os.path.join(self.tmp, "seed")
        git(self.tmp, "init", "-q", "-b", "main", seed)
        Path(seed, ".gitignore").write_text("build/\n*.log\n")
        for n in range(3):
            Path(seed, "a.txt").write_text("version %d\n" % n * 50)
            git(seed, "add", "-A")
            git(seed, "commit", "-q", "-m", "c%d" % n)
        git(seed, "remote", "add", "origin", self.origin)
        git(seed, "push", "-q", "origin", "main")
        self.extra_live = {}
        self.live_calls = []
        self.patches = [
            mock.patch.object(cr, "REMOTE_LS", self.fake_ls),
            mock.patch.object(cr, "_lsof_open", lambda path: (True, [])),
            mock.patch.object(cr, "_mounts", lambda: []),
            mock.patch.object(cg, "busy_processes", lambda path, skip_names=(): []),
            mock.patch.object(cr, "HOOK", None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def fake_ls(self, url, repo, timeout, authenticated=False):
        self.live_calls.append((url, authenticated))
        refs = {}
        for line in git(self.origin, "show-ref").splitlines():
            sha, _, ref = line.partition(" ")
            refs[ref] = sha
        refs.update(self.extra_live)
        return refs

    def clone(self, name="wt-a", partial=False):
        path = os.path.join(self.receipts, name)
        args = ["clone", "-q"] + (["--filter=blob:none"] if partial else []) + ["file://" + self.origin, path]
        git(self.tmp, *args)
        git(path, "remote", "set-url", "origin", URL)
        return path

    def verify(self, path, **kw):
        return cr.verify_clone(path, SESSION, self.home, **kw)

    def remove(self, path, **kw):
        return cr.remove_clone(path, "test", SESSION, self.home, "agent-x", **kw)

    def rows(self, kind=None):
        file = Path(self.home, ".agent-harness", "worktree-audit.jsonl")
        out = [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []
        return [r for r in out if kind is None or r.get("kind") == kind]

    def assertRefused(self, path, fragment=None):
        verdict = self.verify(path)
        self.assertFalse(verdict["removable"], verdict)
        if fragment:
            self.assertIn(fragment, verdict["refusal"])
        return verdict


class FullAndPartialClone(Base):
    def test_full_clone_is_removed_with_its_build_directory_and_audit_rows(self):  # AC-1
        path = self.clone()
        Path(path, "build").mkdir()
        Path(path, "build", "out.bin").write_text("x" * 5000)
        result = self.remove(path)
        self.assertIs(result["removed"], True)
        self.assertIs(result["directory_removed"], True)
        self.assertFalse(os.path.exists(path))
        self.assertEqual([n for n in os.listdir(self.receipts)], [])
        self.assertGreater(result["bytes_freed"], 0)
        self.assertEqual([r["kind"] for r in self.rows()], ["clone-intent", "clone-marker", "clone-result"])
        intent = self.rows("clone-intent")[0]
        for key in ("refs", "proof", "dev", "ino", "parent_dev", "parent_ino", "size_estimate", "git_version",
                    "verifier_version", "cutoff_ns", "audit_id", "snapshot_sha256"):
            self.assertIn(key, intent)

    def test_partial_clone_is_removable_and_every_git_call_denies_the_network(self):  # AC-2, AC-5
        path = self.clone(partial=True)
        self.assertEqual(git(path, "config", "remote.origin.promisor"), "true")
        calls = []
        real = subprocess.run

        def spy(argv, *a, **kw):
            if isinstance(argv, list) and argv and argv[0] == "git" and "-C" in argv and argv[argv.index("-C") + 1] == path:
                calls.append((list(argv), dict(kw.get("env") or {})))
            return real(argv, *a, **kw)
        with mock.patch.object(subprocess, "run", spy):
            verdict = self.verify(path)
        self.assertTrue(verdict["removable"], verdict)
        self.assertTrue(verdict["partial_clone"])
        self.assertGreater(len(calls), 10)
        for argv, env in calls:
            self.assertIn("protocol.allow=never", argv)
            self.assertFalse([a for a in argv if a.startswith("protocol.") and a != "protocol.allow=never"], argv)
            self.assertEqual(env.get("GIT_NO_LAZY_FETCH"), "1")
            self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertEqual(self.remove(path)["removed"], True)

    def test_the_runner_never_contacts_the_remote_for_a_missing_object(self):  # NEG-5 (failing first: the control)
        path = os.path.join(self.receipts, "wt-canary")
        git(self.tmp, "clone", "-q", "--filter=blob:none", "file://" + self.origin, path)
        canary = os.path.join(self.tmp, "canary.sh")
        log = os.path.join(self.tmp, "canary.log")
        Path(canary).write_text("#!/bin/sh\necho contact >> %s\nexec git-upload-pack \"$@\"\n" % log)
        os.chmod(canary, 0o755)
        git(path, "config", "remote.origin.uploadpack", canary)
        missing = [l[1:] for l in git(path, "rev-list", "--objects", "--all", "--missing=print").splitlines() if l.startswith("?")]
        self.assertTrue(missing)
        code, _out = cr.run_git(path, ["cat-file", "-p", missing[0]], 30, check=False)
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(log), "the verification runner contacted the remote")
        subprocess.run(["git", "-c", "protocol.file.allow=always", "-C", path, "cat-file", "-p", missing[0]],
                       env=dict(GIT_ENV), capture_output=True)
        self.assertTrue(os.path.exists(log), "control: a plain git call must contact the remote, or this test proves nothing")
        self.assertRefused(path, "remote.uploadpack")

    def test_partial_clone_variants_refuse(self):  # AC-5, NEG-4
        cases = {
            "other filter": lambda p: git(p, "config", "remote.origin.partialclonefilter", "blob:limit=1k"),
            "tree filter": lambda p: git(p, "config", "remote.origin.partialclonefilter", "tree:0"),
            "no promisor": lambda p: git(p, "config", "--unset", "remote.origin.promisor"),
            "extension names another remote": lambda p: git(p, "config", "extensions.partialClone", "nowhere"),
            "second promisor": lambda p: (git(p, "remote", "add", "other", URL), git(p, "config", "remote.other.promisor", "true")),
            "worktreeConfig": lambda p: git(p, "config", "extensions.worktreeConfig", "true"),
            "objectformat": lambda p: git(p, "config", "extensions.objectFormat", "sha1"),
            "legacy key": lambda p: git(p, "config", "core.partialclonefilter", "blob:none"),
            "format 0": lambda p: git(p, "config", "core.repositoryformatversion", "0"),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                path = self.clone("wt-" + label.replace(" ", "-"), partial=True)
                mutate(path)
                self.assertRefused(path)
        path = self.clone("wt-plain-promisor")
        git(path, "config", "remote.origin.promisor", "true")
        with self.subTest("promisor without extension"):
            self.assertRefused(path)


class UnsafeStates(Base):
    def commit(self, path, name="n.txt"):
        Path(path, name).write_text("new\n")
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", "local")
        return git(path, "rev-parse", "HEAD")

    def test_each_unsafe_state_refuses_and_a_clean_clone_does_not(self):  # AC-3
        def stash(p):
            Path(p, "a.txt").write_text("changed\n")
            git(p, "stash")

        def orphan_reflog(p):
            tree = git(p, "write-tree")
            sha = git(p, "commit-tree", tree, "-m", "orphan")
            logs = Path(p, ".git", "logs", "refs", "heads")
            logs.mkdir(parents=True, exist_ok=True)
            (logs / "orphan").write_text("0" * 40 + " " + sha + " t <t@e.i> 0 +0000\tbranch: x\n")

        def reset_hides_commit(p):
            self.commit(p)
            git(p, "reset", "-q", "--hard", "HEAD~1")

        def stale_tracking(p):
            sha = self.commit(p)
            git(p, "update-ref", "refs/remotes/origin/gone", sha)
            git(p, "reset", "-q", "--hard", "HEAD~1")
            git(p, "reflog", "expire", "--expire=now", "--all")

        cases = {
            "unpushed commit": (lambda p: self.commit(p), "not on the remote"),
            "commit only in logs/HEAD": (reset_hides_commit, "not on the remote"),
            "orphan reflog": (orphan_reflog, "not on the remote"),
            "stale tracking ref": (stale_tracking, "not on the remote"),
            "stash": (stash, "stash"),
            "modified": (lambda p: Path(p, "a.txt").write_text("x\n"), "not clean"),
            "untracked": (lambda p: Path(p, "new.txt").write_text("x\n"), "not clean"),
            "staged": (lambda p: (Path(p, "s.txt").write_text("x\n"), git(p, "add", "s.txt")), "not clean"),
            "ignored file": (lambda p: Path(p, "x.log").write_text("x\n"), "ignored file"),
            "local exclude only": (lambda p: (Path(p, "dist").mkdir(), Path(p, "dist", "f").write_text("x"),
                                              Path(p, ".git", "info", "exclude").write_text("dist/\n")), "local exclude"),
            "linked worktree": (lambda p: git(p, "worktree", "add", "-q", p + "-linked"), "linked worktrees"),
            "modules dir": (lambda p: Path(p, ".git", "modules").mkdir(), "submodules"),
            "commondir": (lambda p: Path(p, ".git", "commondir").write_text("../x\n"), "another repository"),
            "lfs": (lambda p: Path(p, ".git", "lfs").mkdir(), "LFS"),
            "info attributes": (lambda p: Path(p, ".git", "info", "attributes").write_text("* text\n"), "attributes"),
            "hook": (lambda p: Path(p, ".git", "hooks", "pre-commit").write_text("#!/bin/sh\n"), "hooks"),
            "merge head": (lambda p: Path(p, ".git", "MERGE_HEAD").write_text(git(p, "rev-parse", "HEAD") + "\n"), "in progress"),
            "rebase dir": (lambda p: Path(p, ".git", "rebase-merge").mkdir(), "in progress"),
            "unknown .git entry": (lambda p: Path(p, ".git", "tool-state").write_text("x"), "unexpected entry"),
            "missing alternates path": (lambda p: (Path(p, ".git", "objects", "info").mkdir(exist_ok=True),
                                                   Path(p, ".git", "objects", "info", "alternates").write_text("/nope/objects\n")),
                                        "alternates"),
            "unknown host": (lambda p: git(p, "remote", "set-url", "origin", "https://example.org/a/b.git"), "known hosting"),
            "second remote unknown": (lambda p: git(p, "remote", "add", "other", "https://example.org/a/b.git"), "known hosting"),
            "replace ref": (lambda p: git(p, "replace", "HEAD", "HEAD~1"), "replace"),
        }
        for label, (mutate, fragment) in cases.items():
            with self.subTest(label):
                path = self.clone("wt-" + "".join(c if c.isalnum() else "-" for c in label))
                mutate(path)
                self.assertRefused(path, fragment)
        clean = self.clone("wt-clean")
        self.assertTrue(self.verify(clean)["removable"])

    def test_orig_head_naming_an_unpushed_commit_refuses_and_a_pushed_one_passes(self):  # NEG-12
        path = self.clone()
        Path(path, ".git", "ORIG_HEAD").write_text(git(path, "rev-parse", "HEAD~1") + "\n")
        self.assertTrue(self.verify(path)["removable"])
        sha = self.commit(path)
        git(path, "reset", "-q", "--hard", "HEAD~1")
        Path(path, ".git", "ORIG_HEAD").write_text(sha + "\n")
        git(path, "reflog", "expire", "--expire=now", "--all")
        self.assertRefused(path, "not on the remote")

    def test_a_commit_known_only_through_a_pull_head_counts_but_a_pull_merge_ref_does_not(self):  # D5, NEG-2
        path = self.clone()
        sha = self.commit(path)
        self.extra_live["refs/pull/7/merge"] = sha
        self.assertRefused(path, "not on the remote")
        del self.extra_live["refs/pull/7/merge"]
        self.extra_live["refs/pull/7/head"] = sha
        self.assertTrue(self.verify(path)["removable"], self.verify(path))

    def test_a_branch_the_remote_no_longer_lists_refuses(self):  # NEG-2
        path = self.clone()
        sha = self.commit(path)
        git(path, "push", "-q", self.origin, "HEAD:refs/heads/topic")
        git(self.origin, "update-ref", "-d", "refs/heads/topic")
        self.assertRefused(path, "not on the remote")
        self.assertTrue(sha)

    def test_remote_that_does_not_answer_refuses(self):
        path = self.clone()
        with mock.patch.object(cr, "REMOTE_LS", side_effect=ValueError("down")):
            self.assertRefused(path, "did not answer")

    def test_a_remote_url_with_a_credential_refuses_and_leaks_nowhere(self):  # NEG-3
        path = self.clone()
        git(path, "remote", "set-url", "origin", "https://user:s3cr3tvalue@github.com/a/b.git")
        verdict = self.assertRefused(path, "credential")
        with self.assertRaises(cr.CloneError) as caught:
            self.remove(path)
        every = json.dumps(verdict) + str(caught.exception) + json.dumps(self.rows())
        self.assertNotIn("s3cr3tvalue", every)

    def test_a_policy_cannot_widen_the_verifier(self):  # NEG-14
        path = self.clone()
        with self.assertRaises(TypeError):
            cr.verify_clone(path, SESSION, self.home, policy={"reproducible_clone": {"remote_hosts": ["example.org"]}})
        git(path, "remote", "set-url", "origin", "https://example.org/a/b.git")
        self.assertRefused(path, "known hosting")


class Scope(Base):
    def test_paths_outside_the_scope_refuse_before_anything_is_touched(self):  # NEG-1
        path = self.clone()
        work = os.path.join(self.home, ".agent-harness", "work")
        os.makedirs(os.path.join(work, "other", "receipts"))
        shutil.copytree(path, os.path.join(work, "other", "receipts", "wt-x"), symlinks=True)
        shutil.copytree(path, os.path.join(self.receipts, "not-wt"), symlinks=True)
        os.makedirs(os.path.join(self.receipts, "wt-nogit"))
        os.makedirs(os.path.join(self.receipts, "wt-gitfile"))
        Path(self.receipts, "wt-gitfile", ".git").write_text("gitdir: /x\n")
        os.symlink(path, os.path.join(self.receipts, "wt-link"))
        os.makedirs(os.path.join(self.receipts, "task", "wt-deep"))
        bad = [work, os.path.join(work, SESSION), self.receipts, os.path.join(work, "other", "receipts", "wt-x"),
               os.path.join(self.receipts, "not-wt"), os.path.join(self.receipts, "wt-nogit"),
               os.path.join(self.receipts, "wt-gitfile"), os.path.join(self.receipts, "wt-link"),
               os.path.join(self.receipts, "task", "wt-deep"), "wt-a", path + "/", path + "/../wt-a", path + " x", path + ";x",
               os.path.join(self.tmp, "outside"), "", "/", path + "/.git"]
        for candidate in bad:
            with self.subTest(candidate):
                with self.assertRaises(cr.CloneError):
                    cr.check_target(candidate, SESSION, self.home)
                self.assertFalse(cr.verify_clone(candidate, SESSION, self.home)["removable"])
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))

    def test_a_case_variant_spelling_refuses_when_the_filesystem_folds_case(self):  # NEG-1
        path = self.clone("wt-abc")
        variant = os.path.join(self.receipts, "wt-ABC")
        if not os.path.exists(variant):
            self.skipTest("case-sensitive filesystem: the variant names nothing")
        with self.assertRaises(cr.CloneError):
            cr.check_target(variant, SESSION, self.home)
        self.assertTrue(os.path.isdir(path))

    def test_a_missing_or_malformed_session_refuses(self):  # NEG-15
        path = self.clone()
        for session in ("", "../x", "a b", None):
            with self.subTest(session):
                with self.assertRaises(cr.CloneError):
                    cr.check_target(path, session, self.home)

    def test_resume_and_path_cannot_be_combined_and_the_command_is_installed(self):
        text = (ROOT / "install.py").read_text() + (ROOT / "install_codex.py").read_text()
        self.assertIn("clone_remove.py", text)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"AH_HOME": self.home, "CLAUDE_CODE_SESSION_ID": SESSION}), redirect_stdout(out):
            code = ah.main(["clone-remove", "--resume", "20260101T000000-abcdef01", "--path", "/x/y"])
        self.assertNotEqual(code, 0)

    def test_the_calling_directory_inside_the_target_refuses(self):
        path = self.clone()
        with mock.patch.object(os, "getcwd", return_value=path):
            self.assertRefused(path, "calling directory")

    def test_busy_processes_open_files_and_mounts_refuse(self):  # NEG-8
        path = self.clone()
        with mock.patch.object(cg, "busy_processes", lambda p, skip_names=(): [(5, "x")]):
            self.assertRefused(path, "work inside")
        with mock.patch.object(cg, "busy_processes", lambda p, skip_names=(): None):
            self.assertRefused(path, "could not be inspected")
        with mock.patch.object(cr, "_lsof_open", lambda p: (False, [])):
            self.assertRefused(path, "lsof")
        with mock.patch.object(cr, "_lsof_open", lambda p: (True, [42])):
            self.assertRefused(path, "open files")
        with mock.patch.object(cr, "_mounts", lambda: [path + "/sub"]):
            self.assertRefused(path, "mount")
        with mock.patch.object(cr, "_mounts", lambda: [path + "-sibling"]):
            self.assertTrue(self.verify(path)["removable"])

    def test_the_open_file_prefix_match_is_exact_or_followed_by_a_slash(self):  # NEG-16
        listing = "p100\nn%s/f\np101\nn%s0/f\np102\nn/System/Volumes/Data%s/g\n"

        def fake(argv, *a, **kw):
            return subprocess.CompletedProcess(argv, 0, listing % ("/x/wt-a", "/x/wt-a", "/x/wt-a"), "")
        with mock.patch.object(subprocess, "run", fake), mock.patch.object(cr.os.path, "realpath", lambda p: p):
            self.assertEqual(REAL_LSOF("/x/wt-a"), (True, [100, 102]))

    def test_a_real_process_holding_a_file_open_blocks_the_removal(self):  # NEG-8 (real lsof)
        path = self.clone()
        held = os.path.join(path, "a.txt")
        proc = subprocess.Popen([sys.executable, "-c", "import sys,time; f=open(sys.argv[1]); print('ready', flush=True); time.sleep(60)", held],
                                stdout=subprocess.PIPE, cwd=self.tmp)
        proc.stdout.readline()
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        import time
        time.sleep(0.5)
        ok, pids = REAL_LSOF(path)
        self.assertTrue(ok)
        self.assertIn(proc.pid, pids)

    def test_a_repository_borrowing_objects_from_the_target_refuses(self):  # NEG-11
        path = self.clone()
        borrower = os.path.join(self.receipts, "wt-borrower")
        git(self.tmp, "clone", "-q", "--shared", path, borrower)
        self.assertRefused(path, "borrows")


class Walk(Base):
    def tree(self, name="t"):
        root = os.path.join(self.tmp, name)
        os.makedirs(os.path.join(root, "sub", "deep"))
        for rel in ("a", "sub/b", "sub/deep/c"):
            Path(root, rel).write_text("x")
        return root

    def run_walk(self, root, cutoff=None, **kw):
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            kw.setdefault("allowed_dirs", cr.dir_inodes(root))
            return cr.walk_delete(fd, cutoff if cutoff is not None else 2 ** 62, **kw)
        finally:
            os.close(fd)

    def test_a_symlink_is_removed_as_a_link_and_its_target_survives(self):  # AC-6, NEG-6
        root = self.tree()
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        Path(outside, "keep").write_text("keep")
        os.symlink(outside, os.path.join(root, "sub", "link"))
        os.symlink(os.path.join(outside, "keep"), os.path.join(root, "filelink"))
        stats = self.run_walk(root)
        self.assertEqual(stats["left"], [])
        self.assertEqual(os.listdir(root), [])
        self.assertEqual(os.listdir(outside), ["keep"])

    def test_a_directory_swapped_for_a_symlink_mid_walk_never_reaches_the_target(self):  # NEG-6
        root = self.tree()
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(os.path.join(outside, "inner"))
        Path(outside, "inner", "keep").write_text("keep")
        done = []

        def swap(event, rel=None, **kw):
            if event == "entry" and rel.startswith("sub/") and not done:
                done.append(1)
                os.rename(os.path.join(root, "sub"), os.path.join(root, "sub.moved"))
                os.symlink(outside, os.path.join(root, "sub"))
        with mock.patch.object(cr, "HOOK", swap):
            try:
                self.run_walk(root)
            except cr.CloneError:
                pass
        self.assertEqual(os.listdir(os.path.join(outside, "inner")), ["keep"])

    def test_a_second_device_is_not_crossed(self):  # NEG-6
        root = self.tree()
        real = os.lstat(root).st_dev
        stats = self.run_walk(root, dev=real + 1)
        self.assertTrue(os.path.isdir(os.path.join(root, "sub")))
        self.assertTrue([l for l in stats["left"] if "another device" in l])
        self.assertFalse(os.path.exists(os.path.join(root, "a")))

    def test_a_failing_unlink_is_reported_and_the_rest_continues(self):  # AC-6
        root = self.tree()
        real = os.unlink

        def flaky(name, *a, **kw):
            if name == "b":
                raise PermissionError(errno.EPERM, "denied")
            return real(name, *a, **kw)
        with mock.patch.object(os, "unlink", flaky):
            stats = self.run_walk(root)
        self.assertTrue([l for l in stats["left"] if l.startswith("sub/b")])
        self.assertTrue(os.path.exists(os.path.join(root, "sub", "b")))
        self.assertFalse(os.path.exists(os.path.join(root, "a")))

    def test_a_300_deep_tree_works_under_a_small_descriptor_limit(self):  # AC-6
        root = os.path.join(self.tmp, "deep")
        os.makedirs(root)
        fd = os.open(root, os.O_RDONLY)
        current = fd
        for _ in range(300):
            os.mkdir("d", dir_fd=current)
            nxt = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=current)
            if current != fd:
                os.close(current)
            current = nxt
        os.close(current)
        os.close(fd)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (40, hard))
        try:
            stats = self.run_walk(root)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        self.assertEqual(stats["left"], [])
        self.assertEqual(os.listdir(root), [])

    def test_a_read_only_directory_is_made_writable_for_its_own_removal(self):  # NEG-6
        root = self.tree()
        os.chmod(os.path.join(root, "sub", "deep"), 0o500)
        stats = self.run_walk(root)
        self.assertEqual(stats["left"], [])
        self.assertEqual(os.listdir(root), [])


class Removal(Base):
    def quarantines(self):
        return [n for n in os.listdir(self.receipts) if n.startswith(cr.QUARANTINE_PREFIX)]

    def test_verify_only_changes_nothing_and_records_the_plan(self):  # AC-9
        path = self.clone(partial=True)

        def listing():
            out = []
            for root, dirs, files in os.walk(path):
                for n in sorted(dirs + files):
                    i = os.lstat(os.path.join(root, n))
                    out.append((os.path.join(root, n), i.st_size, i.st_mtime_ns, i.st_ino))
            return out
        before = listing()
        result = self.remove(path, verify_only=True)
        self.assertTrue(result["removable"])
        self.assertIs(result["removed"], False)
        self.assertEqual(listing(), before)
        for key in ("snapshot", "proof", "entries", "size_estimate"):
            self.assertIn(key, result["plan"])
        self.assertEqual([r["kind"] for r in self.rows()], ["clone-verify"])
        self.assertIn("refs", self.rows()[0])

    def test_remote_auth_reaches_the_single_ls_remote(self):  # AC-2
        path = self.clone()
        self.verify(path, authenticated=True)
        self.assertEqual(self.live_calls, [(URL, True)])

    def test_the_intent_row_must_be_written_before_anything_moves(self):  # AC-8
        path = self.clone()
        with mock.patch.object(cr, "audit", side_effect=OSError("disk full")), mock.patch.object(os, "rename") as renamed:
            with self.assertRaises(cr.CloneError):
                self.remove(path)
        renamed.assert_not_called()
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertEqual(self.quarantines(), [])

    def test_an_existing_quarantine_name_refuses_and_the_clone_stays(self):  # AC-8
        path = self.clone()
        os.makedirs(os.path.join(self.receipts, cr.QUARANTINE_PREFIX + "20260101T000000-aaaaaaaa"))
        with mock.patch.object(cr, "_now_id", lambda: "20260101T000000-aaaaaaaa"):
            with self.assertRaises(cr.CloneError):
                self.remove(path)
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))

    def test_a_directory_replaced_after_verification_refuses_and_nothing_is_deleted(self):  # NEG-6
        path = self.clone()
        moved = path + "-moved"

        def swap(event, **kw):
            if event == "after_verify":
                os.rename(path, moved)
                shutil.copytree(moved, path, symlinks=True)
        with mock.patch.object(cr, "HOOK", swap):
            with self.assertRaises(cr.CloneError):
                self.remove(path)
        self.assertTrue(os.path.isdir(os.path.join(moved, ".git")))
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertEqual(self.quarantines(), [])

    def test_refs_that_differ_inside_the_quarantine_rename_it_back_without_a_marker(self):  # NEG-16, M5
        path = self.clone()

        def add_ref(event, **kw):
            if event == "after_verify":
                git(path, "update-ref", "refs/heads/sneaky", "HEAD")
        with mock.patch.object(cr, "HOOK", add_ref):
            with self.assertRaises(cr.CloneError):
                self.remove(path)
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertFalse(os.path.exists(os.path.join(path, cr.MARKER_NAME)))
        self.assertEqual(self.quarantines(), [])

    def test_a_failed_marker_row_refuses_before_any_deletion_and_restores_the_clone(self):  # NEG-16
        path = self.clone()
        real = cr.audit

        def flaky(home, record):
            if record.get("kind") == "clone-marker":
                raise OSError("disk full")
            return real(home, record)
        with mock.patch.object(cr, "audit", flaky):
            with self.assertRaises(cr.CloneError):
                self.remove(path)
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertFalse(os.path.exists(os.path.join(path, cr.MARKER_NAME)))
        self.assertTrue(os.path.exists(os.path.join(path, "a.txt")))

    def test_a_file_written_after_verification_survives_even_through_resume(self):  # NEG-7, H2
        path = self.clone()

        def late(event, **kw):
            if event == "after_verify":
                Path(path, "late.txt").write_text("precious")
        with mock.patch.object(cr, "HOOK", late):
            result = self.remove(path)
        self.assertIsNone(result["removed"])
        self.assertFalse(result["directory_removed"])
        self.assertIn("late.txt", " ".join(result["left"]))
        quarantine = result["quarantine"]
        self.assertEqual(Path(quarantine, "late.txt").read_text(), "precious")
        again = cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertIsNone(again["removed"])
        self.assertEqual(Path(quarantine, "late.txt").read_text(), "precious")

    def test_an_interrupted_walk_is_finished_by_resume(self):  # AC-8, NEG-10
        path = self.clone()
        real = os.unlink
        count = []

        def failing(name, *a, **kw):
            count.append(name)
            if len(count) > 5:
                raise OSError(errno.EIO, "io")
            return real(name, *a, **kw)
        with mock.patch.object(os, "unlink", failing):
            result = self.remove(path)
        self.assertIsNone(result["removed"])
        self.assertFalse(os.path.exists(path))
        self.assertTrue(os.path.isdir(result["quarantine"]))
        done = cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertIs(done["removed"], True)
        self.assertEqual(os.listdir(self.receipts), [])
        again = cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertTrue(again["already"])

    def interrupted(self):
        path = self.clone()
        real = os.unlink
        count = []

        def failing(name, *a, **kw):
            count.append(name)
            if len(count) > 3:
                raise OSError(errno.EIO, "io")
            return real(name, *a, **kw)
        with mock.patch.object(os, "unlink", failing):
            return self.remove(path)

    def test_resume_refuses_a_forged_or_mismatched_quarantine(self):  # NEG-10
        result = self.interrupted()
        audit_id = result["audit_id"]
        quarantine = result["quarantine"]
        with self.assertRaises(cr.CloneError):
            cr.resume_clone("20260101T000000-deadbeef", SESSION, self.home)
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(audit_id, "other", self.home)
        with self.assertRaises(cr.CloneError):
            cr.resume_clone("../../x", SESSION, self.home)
        # a refs addition inside the quarantine
        git(quarantine, "update-ref", "refs/heads/extra", "HEAD", check=False)
        victim = os.path.join(quarantine, ".git", "refs", "heads", "extra")
        os.makedirs(os.path.dirname(victim), exist_ok=True)
        Path(victim).write_text("a" * 40 + "\n")
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(audit_id, SESSION, self.home)
        os.unlink(victim)
        # a marker that no longer matches
        marker = os.path.join(quarantine, cr.MARKER_NAME)
        saved = Path(marker).read_text()
        Path(marker).write_text(json.dumps({"audit_id": audit_id, "snapshot_sha256": "0" * 64}))
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(audit_id, SESSION, self.home)
        os.unlink(marker)
        Path(marker).write_text(saved)
        # a different inode behind the same name
        moved = quarantine + "-away"
        os.rename(quarantine, moved)
        shutil.copytree(moved, quarantine, symlinks=True)
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(audit_id, SESSION, self.home)
        self.assertTrue(os.path.isdir(moved))
        self.assertTrue(os.path.isdir(quarantine))

    def test_resume_refuses_when_the_recorded_inode_is_not_the_quarantine(self):  # NEG-10
        result = self.interrupted()
        real = cr.audit_rows

        def forged(home, audit_id):
            return [dict(r, ino=r["ino"] + 1) if r.get("kind") == "clone-intent" else r for r in real(home, audit_id)]
        with mock.patch.object(cr, "audit_rows", forged):
            with self.assertRaises(cr.CloneError):
                cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertTrue(os.path.isdir(result["quarantine"]))

    def test_an_arbitrary_directory_with_a_forged_row_is_not_deletable(self):  # NEG-10
        outside = os.path.join(self.tmp, "victim")
        os.makedirs(outside)
        Path(outside, "precious").write_text("x")
        audit_id = "20260101T000000-feedf00d"
        quarantine = os.path.join(self.receipts, cr.QUARANTINE_PREFIX + audit_id)
        os.rename(outside, quarantine)
        info = os.lstat(quarantine)
        parent = os.lstat(self.receipts)
        row = {"kind": "clone-intent", "audit_id": audit_id, "session": SESSION, "quarantine": quarantine,
               "dev": info.st_dev, "ino": info.st_ino, "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
               "snapshot": {"refs": {}}, "snapshot_sha256": "0" * 64, "cutoff_ns": 2 ** 62}
        cr.audit(self.home, row)
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(audit_id, SESSION, self.home)  # no marker row, no marker file
        self.assertEqual(Path(quarantine, "precious").read_text(), "x")
        outside_row = dict(row, quarantine=os.path.join(self.tmp, cr.QUARANTINE_PREFIX + audit_id))
        cr.audit(self.home, dict(outside_row, audit_id="20260101T000000-feedf00e"))
        with self.assertRaises(cr.CloneError):
            cr.resume_clone("20260101T000000-feedf00e", SESSION, self.home)

    def test_two_concurrent_resumes_one_refuses_by_lock(self):  # NEG-10
        import fcntl
        result = self.interrupted()
        fd = os.open(result["quarantine"], os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with self.assertRaises(cr.CloneError) as caught:
            cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertIn("holds", str(caught.exception))


class Wiring(Base):
    def test_the_command_is_wired_into_ah(self):
        with mock.patch.object(cr, "remove_clone", return_value={"ok": True}) as remove, \
                mock.patch.object(cr, "parent_session_env", lambda pid: SESSION), \
                mock.patch.object(cr, "trusted_home", lambda: self.home), \
                mock.patch.dict(os.environ, {"AH_HOME": self.home, "CLAUDE_CODE_SESSION_ID": SESSION}):
            out = io.StringIO()
            with redirect_stdout(out):
                code = ah.main(["clone-remove", "--path", "/p", "--reason", "why", "--remote-auth"])
        self.assertEqual(code, 0)
        self.assertEqual(remove.call_args[0][:3], ("/p", "why", SESSION))
        self.assertIs(remove.call_args[0][5], True)


if __name__ == "__main__":
    unittest.main()
