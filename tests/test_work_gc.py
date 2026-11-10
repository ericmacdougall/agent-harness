"""GoodQA #15565: work-dir GC removes only finished, clean, pushed worktrees and rebuildable folders, from a dry-run plan."""
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import work_gc as gc  # noqa: E402

REAL_IN_USE = gc.__dict__.get("in_use_paths")

SESSION = "11111111-1111-4111-8111-111111111111"
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")


def run(*cmd, cwd=None):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, env=ENV)


def out(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, env=ENV).stdout.strip()


def age(path: Path, stop: Path, hours=10.0):
    """Set path and its parents up to (and including) stop to an old mtime."""
    old = time.time() - hours * 3600
    for p in [path, *path.parents]:
        os.utime(p, (old, old), follow_symlinks=False)
        if p == stop:
            break


def local_ls_remote(url):
    """Stand-in for the network listing: the heads of a local bare repository."""
    done = subprocess.run(["git", "ls-remote", url, "refs/heads/*"], capture_output=True, text=True)
    if done.returncode != 0:
        return None
    return {ref: sha for sha, ref in (ln.split("\t") for ln in done.stdout.splitlines() if "\t" in ln)}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wgc-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(os.path.realpath(self.tmp.name))
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        self.root = self.home / ".agent-harness" / "work"
        self.session = self.root / SESSION
        self.session.mkdir(parents=True)
        self.wals = self.home / ".claude" / "wals" / SESSION
        self.wals.mkdir(parents=True)
        for name, value in (("in_use_paths", lambda: ["/somewhere/else"]),
                            ("ls_remote", local_ls_remote)):
            patcher = mock.patch.object(gc, name, value, create=True)  # noqa: B023
            patcher.start()
            self.addCleanup(patcher.stop)
        self.repo = self.session / "repo"
        run("git", "init", "-q", "-b", "main", str(self.repo))
        (self.repo / "a.txt").write_text("x\n")
        run("git", "add", "-A", cwd=self.repo)
        run("git", "commit", "-q", "-m", "one", cwd=self.repo)
        self.remote = self.home / "remote.git"
        run("git", "init", "-q", "--bare", str(self.remote))
        run("git", "remote", "add", "origin", str(self.remote), cwd=self.repo)
        run("git", "push", "-q", "origin", "main", cwd=self.repo)
        run("git", "fetch", "-q", "origin", cwd=self.repo)
        allowed = {str(self.remote)}
        patcher = mock.patch.object(gc, "remote_allowed", lambda url: url in allowed, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def worktree(self, name="agent-abc", idle_hours=10.0, pushed=True, repo=None, extra=()):
        repo = repo or self.repo
        path = repo / ".claude" / "worktrees" / name
        run("git", "worktree", "add", "-q", *extra, "-b", "feat-" + name, str(path), cwd=repo)
        if not pushed:
            (path / "b.txt").write_text("b\n")
            run("git", "add", "-A", cwd=path)
            run("git", "commit", "-q", "-m", "unpushed", cwd=path)
        log = self.wals / (name + ".jsonl")
        log.write_text("{}\n")
        old = time.time() - idle_hours * 3600
        os.utime(log, (old, old))
        return path

    def commit_push(self, path, files, branch):
        for rel, text in files.items():
            (path / rel).parent.mkdir(parents=True, exist_ok=True)
            (path / rel).write_text(text)
        run("git", "add", "-A", cwd=path)
        run("git", "commit", "-q", "-m", "c", cwd=path)
        run("git", "push", "-q", "origin", "HEAD:refs/heads/" + branch, cwd=path)
        run("git", "fetch", "-q", "origin", cwd=path)

    def plan(self, idle=3.0, **kw):
        return gc.make_plan(self.root, idle, workers=2, **kw)

    def item(self, plan, path):
        return next(i for i in plan["items"] if i["path"] == str(path))

    def ok_paths(self, plan):
        return {Path(i["path"]).relative_to(self.session).as_posix() for i in plan["items"] if i["ok"]}


class Worktrees(Case):
    def test_a_finished_clean_pushed_worktree_is_reclaimable_and_removed_leaving_the_branch(self):
        path = self.worktree()
        plan = self.plan()
        self.assertTrue(self.item(plan, path)["ok"], self.item(plan, path))
        results = gc.apply_plan(plan, self.root)
        self.assertEqual([r["status"] for r in results], ["removed"])
        self.assertFalse(path.exists())
        branches = out("git", "-C", str(self.repo), "branch", "--list", "feat-agent-abc")
        self.assertIn("feat-agent-abc", branches)  # the branch survives
        audit = [json.loads(x) for x in gc.audit_path().read_text().splitlines()]
        self.assertEqual((audit[-1]["status"], audit[-1]["kind"]), ("removed", "worktree"))

    def test_each_blocker_keeps_the_worktree(self):
        cases = {}
        cases["recent"] = self.worktree("agent-recent", idle_hours=0.1)
        cases["unpushed"] = self.worktree("agent-unpushed", pushed=False)
        dirty = self.worktree("agent-dirty")
        (dirty / "notes.txt").write_text("unique work\n")
        cases["dirty"] = dirty
        modified = self.worktree("agent-modified")
        (modified / "a.txt").write_text("changed\n")
        cases["modified"] = modified
        nolog = self.worktree("agent-nolog")
        (self.wals / "agent-nolog.jsonl").unlink()
        cases["nolog"] = nolog
        locked = self.worktree("agent-locked")
        run("git", "worktree", "lock", "--reason", "keep", str(locked), cwd=self.repo)
        cases["locked"] = locked
        plan = self.plan()
        for name, path in cases.items():
            with self.subTest(name=name):
                self.assertFalse(self.item(plan, path)["ok"], self.item(plan, path))
        self.assertIn("locked", self.item(plan, locked)["reason"])
        self.assertIn("changed or untracked", self.item(plan, dirty)["reason"])
        self.assertIn("changed or untracked", self.item(plan, modified)["reason"])
        gc.apply_plan(plan, self.root)
        for path in cases.values():
            self.assertTrue(path.exists())

    def test_a_subagent_transcript_written_recently_for_this_worktree_keeps_it(self):
        path = self.worktree("agent-sub")
        subagents = self.home / ".claude" / "projects" / "-Users-x" / SESSION / "subagents"
        subagents.mkdir(parents=True)
        (subagents / "agent-other.meta.json").write_text(json.dumps({"worktreePath": str(path)}))
        transcript = subagents / "agent-other.jsonl"
        transcript.write_text("{}\n")
        self.assertFalse(self.item(self.plan(), path)["ok"])
        age(transcript, transcript)  # written 10 h ago: no longer evidence of activity
        self.assertTrue(self.item(self.plan(), path)["ok"])
        (subagents / "agent-broken.meta.json").write_text("{not json")  # unreadable meta is no info, not a crash
        self.assertTrue(self.item(self.plan(), path)["ok"])

    def test_ignored_build_output_inside_a_clean_worktree_does_not_block(self):
        path = self.worktree()
        self.commit_push(path, {".gitignore": "dist/\nnode_modules/\n.DS_Store\n"}, "feat-agent-abc")
        (path / "dist").mkdir()
        (path / "dist/x.js").write_text("x\n")
        (path / "node_modules/pkg").mkdir(parents=True)
        (path / "node_modules/pkg/.env.example").write_text("A=1\n")  # fixtures in dependency trees are fine
        (path / ".DS_Store").write_text("x")
        self.assertTrue(self.item(self.plan(), path)["ok"], self.item(self.plan(), path))

    def test_ignored_files_that_are_not_build_output_keep_the_worktree(self):
        ignore = ".gitignore"
        cases = {
            "log": ({ignore: "*.log\n"}, lambda p: (p / "notes.log").write_text("x\n")),
            "env": ({ignore: ".env\n"}, lambda p: (p / ".env").write_text("TOKEN=redacted\n")),
            "claude": ({ignore: ".claude/\n"}, lambda p: (p / ".claude").mkdir() or (p / ".claude/x.json").write_text("{}")),
            "clone": ({ignore: "vendor/\n"}, "clone:vendor/inner"),
            "clone_in_build": ({ignore: "build/\n"}, "clone:build/inner"),
            "log_in_dist": ({ignore: "dist/\n"}, lambda p: (p / "dist").mkdir() or (p / "dist/run.log").write_text("x")),
            "harness_in_deps": ({ignore: "node_modules/\n"},
                                lambda p: (p / "node_modules/.claude").mkdir(parents=True) or
                                (p / "node_modules/.claude/s.json").write_text("{}")),
            "bare_in_build": ({ignore: "build/\n"}, "bare:build/x.git"),
            "sqlite_in_cache": ({ignore: ".cache/\n"},
                                lambda p: (p / ".cache").mkdir() or (p / ".cache/app.sqlite").write_text("x")),
            "plain_folder": ({ignore: "auth/\n"},
                             lambda p: (p / "auth").mkdir() or (p / "auth/tokens.txt").write_text("x")),
            "session_segment": ({ignore: "wals/dist/\n", "wals/README": "tracked\n"},
                                lambda p: (p / "wals/dist").mkdir() or (p / "wals/dist/x.js").write_text("x")),
        }
        paths = {}
        for i, (name, (files, maker)) in enumerate(cases.items()):
            path = self.worktree("agent-ign%d" % i)
            self.commit_push(path, files, "feat-agent-ign%d" % i)
            if isinstance(maker, str) and maker.startswith("clone:"):
                inner = path / maker[6:]
                run("git", "clone", "-q", str(self.remote), str(inner))
                (inner / "unique.txt").write_text("u\n")
                run("git", "add", "-A", cwd=inner)
                run("git", "commit", "-q", "-m", "unpushed nested", cwd=inner)
            elif isinstance(maker, str) and maker.startswith("bare:"):
                run("git", "init", "-q", "--bare", str(path / maker[5:]))
            else:
                maker(path)
            paths[name] = path
        plan = self.plan()
        for name, path in paths.items():
            with self.subTest(name=name):
                row = self.item(plan, path)
                self.assertFalse(row["ok"], row)
                self.assertIn("ignored", row["reason"], row)
        gc.apply_plan(plan, self.root)
        for path in paths.values():
            self.assertTrue(path.exists())

    def test_a_process_inside_the_worktree_keeps_it(self):
        path = self.worktree()
        with mock.patch.object(gc, "in_use_paths", lambda: [str(path / "sub")]):
            self.assertFalse(self.item(self.plan(), path)["ok"])
        with mock.patch.object(gc, "in_use_paths", lambda: None):  # an unreadable process list removes nothing
            self.assertFalse(self.item(self.plan(), path)["ok"])

    def test_apply_re_verifies_so_a_change_after_the_plan_is_respected(self):
        path = self.worktree()
        plan = self.plan()
        (path / "late.txt").write_text("new unique work\n")
        results = gc.apply_plan(plan, self.root)
        self.assertEqual(results[0]["status"], "skipped")
        self.assertTrue(path.exists())

    def test_a_relative_paths_worktree_is_understood_and_removed(self):
        path = self.worktree("agent-rel", extra=("--relative-paths",))
        self.assertFalse(Path((path / ".git").read_text().split("gitdir:", 1)[1].strip()).is_absolute())
        self.assertEqual(gc._repo_of(path), self.repo)
        plan = self.plan()
        self.assertTrue(self.item(plan, path)["ok"], self.item(plan, path))
        results = gc.apply_plan(plan, self.root)
        self.assertEqual([r["status"] for r in results], ["removed"], results)
        self.assertFalse(path.exists())

    def test_a_full_clone_or_a_foreign_worktree_in_the_worktrees_folder_is_never_a_linked_worktree(self):
        clone = self.repo / ".claude" / "worktrees" / "agent-clone"
        run("git", "clone", "-q", str(self.remote), str(clone))  # .git is a DIRECTORY: a main checkout
        (self.wals / "agent-clone.jsonl").write_text("{}\n")
        age(self.wals / "agent-clone.jsonl", self.wals / "agent-clone.jsonl")
        other = self.session / "other"
        run("git", "clone", "-q", str(self.remote), str(other))
        foreign = self.worktree("agent-foreign", repo=other)  # sits under other/, gitdir points into other/.git
        moved = self.repo / ".claude" / "worktrees" / "agent-foreign"
        os.rename(foreign, moved)  # now under repo/.claude/worktrees but its gitdir points into another repo
        self.assertIsNone(gc._repo_of(clone))
        self.assertIsNone(gc._repo_of(moved))
        plan = self.plan()
        self.assertFalse(self.item(plan, clone)["ok"])
        self.assertFalse(self.item(plan, moved)["ok"])
        forged = gc.seal({"items": [{"kind": "worktree", "path": str(clone), "ok": True, "bytes": 1},
                                    {"kind": "worktree", "path": str(moved), "ok": True, "bytes": 1}]})
        self.assertEqual([r["status"] for r in gc.apply_plan(forged, self.root)], ["skipped", "skipped"])
        self.assertTrue((clone / "a.txt").exists())
        self.assertTrue((moved / "a.txt").exists())


class Pushed(Case):
    """F4: only a live tip of an allowlisted network remote proves a push."""

    def test_remote_host_allowlist(self):
        good = ["https://github.com/o/r.git", "git@github.com:o/r.git", "ssh://git@t2-dev/srv/r.git", "t2-dev:r.git",
                "ssh://git@GitHub.com:22/o/r"]
        bad = ["/srv/r.git", "./r", "../r.git", "~/r.git", "file:///srv/r.git", "https://evil.com/o/r.git",
               "https://github.com.evil.com/o/r", "ext::sh -c x", "", "git@evil.com:github.com/r"]
        for url in good:
            self.assertTrue(gc.remote_host_allowed(url), url)
        for url in bad:
            self.assertFalse(gc.remote_host_allowed(url), url)

    def test_a_local_path_remote_is_no_proof_by_default(self):
        path = self.worktree()
        row = self.item(self.plan(remote_allowed=gc.remote_host_allowed), path)
        self.assertFalse(row["ok"], row)

    def test_a_stale_or_hand_set_tracking_ref_is_no_proof(self):
        stale = self.worktree("agent-stale", pushed=False)
        run("git", "push", "-q", "origin", "HEAD:refs/heads/feat-agent-stale", cwd=stale)
        run("git", "fetch", "-q", "origin", cwd=stale)
        run("git", "-C", str(self.remote), "update-ref", "refs/heads/feat-agent-stale",
            out("git", "-C", str(self.repo), "rev-parse", "main"))  # the remote moved on; the local ref is stale
        handset = self.worktree("agent-handset", pushed=False)
        run("git", "update-ref", "refs/remotes/origin/fake", "HEAD", cwd=handset)  # never pushed anywhere
        plan = self.plan()
        for path in (stale, handset):
            with self.subTest(path=path.name):
                self.assertFalse(self.item(plan, path)["ok"], self.item(plan, path))

    def test_an_unanswered_listing_keeps_the_worktree_and_listings_are_cached_per_url(self):
        path = self.worktree()
        with mock.patch.object(gc, "ls_remote", lambda url: None):
            row = self.item(self.plan(), path)
        self.assertFalse(row["ok"])
        self.assertIn("cannot verify push", row["reason"])
        self.worktree("agent-two")
        calls = []
        self.plan(ls_remote=lambda url: calls.append(url) or local_ls_remote(url))
        self.assertEqual(calls, [str(self.remote)])

    def test_a_detached_head_counts_only_when_a_live_tip_contains_it(self):
        path = self.worktree()
        run("git", "checkout", "-q", "--detach", cwd=path)
        self.assertTrue(self.item(self.plan(), path)["ok"])
        (path / "c.txt").write_text("c\n")
        run("git", "add", "-A", cwd=path)
        run("git", "commit", "-q", "-m", "reflog only", cwd=path)
        self.assertFalse(self.item(self.plan(), path)["ok"])


class Regenerable(Case):
    def make(self, rel, content="x\n"):
        path = self.session / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        age(path, self.session)
        return path

    def git_proj(self, rel, ignore, tracked=None):
        proj = self.session / rel
        run("git", "init", "-q", "-b", "main", str(proj))
        (proj / ".gitignore").write_text(ignore)
        for name, text in (tracked or {}).items():
            (proj / name).parent.mkdir(parents=True, exist_ok=True)
            (proj / name).write_text(text)
        run("git", "add", "-A", "-f", cwd=proj)
        run("git", "commit", "-q", "-m", "init", cwd=proj)
        return proj

    def age_tree(self, top):
        for base, dirs, files in os.walk(top):
            for n in dirs + files:
                age(Path(base) / n, Path(base) / n)
        age(top, self.session)

    def test_recently_changed_rebuildable_folders_are_kept(self):
        path = self.session / "fresh" / "node_modules"
        path.mkdir(parents=True)
        (path / "a.js").write_text("x\n")
        (path.parent / "package.json").write_text("{}")
        self.assertEqual([i for i in self.plan()["items"] if i["ok"]], [])

    def test_inside_git_only_untracked_and_ignored_folders_are_removed(self):
        proj = self.git_proj("proj", "build/\ntarget/\ndist/\nnode_modules/\n",
                             {"build/deploy.sh": "echo deploy\n", "target/schema.sql": "create table t;\n"})
        (proj / "build/deploy.sh").write_text("echo edited, uncommitted\n")
        (proj / "dist").mkdir()
        (proj / "dist/app.js").write_text("x\n")
        (proj / "node_modules").mkdir()
        (proj / "node_modules/x.js").write_text("x\n")
        with self.assertRaises(gc.Refuse) as why:  # ignored AND tracked: the tracked check must refuse it
            gc.check_regen_origin(proj / "build", self.root)
        self.assertIn("tracks", str(why.exception))
        with self.assertRaises(gc.Refuse) as why:
            gc.check_regen_origin(proj / "target", self.root)
        self.assertIn("tracks", str(why.exception))
        loose = self.git_proj("loose", "")  # dist/ here is untracked but NOT ignored
        (loose / "dist").mkdir()
        (loose / "dist/release.tar").write_text("x\n")
        self.age_tree(self.session)
        plan = self.plan()
        self.assertEqual(self.ok_paths(plan), {"proj/dist", "proj/node_modules"})
        gc.apply_plan(plan, self.root)
        self.assertTrue((proj / "build/deploy.sh").exists())
        self.assertTrue((proj / "target/schema.sql").exists())
        self.assertTrue((loose / "dist/release.tar").exists())
        self.assertFalse((proj / "dist").exists())

    def test_outside_git_only_self_identifying_folders_are_removed(self):
        self.make("pp/node_modules/a/index.js")
        self.make("pp/package.json", "{}")
        self.make("bare/node_modules/a/index.js")  # no package.json beside it
        self.make("py/.venv/pyvenv.cfg", "home = /usr\n")
        self.make("py/.venv/bin/python")
        self.make("py2/venv/bin/python")  # no pyvenv.cfg
        self.make("py/__pycache__/m.cpython-39.pyc")
        self.make("py/.pytest_cache/v/x")
        self.make("pp407/build/make_release.sh", "#!/bin/sh\n")
        self.make("agent-wincapture/dist/app-1.0.zip")
        self.make("rs/target/release/bin")
        self.make("web/.cache/blob")
        self.make("web/.next/server.js")
        self.age_tree(self.session)
        plan = self.plan()
        self.assertEqual(self.ok_paths(plan), {"pp/node_modules", "py/.venv", "py/__pycache__", "py/.pytest_cache"})
        gc.apply_plan(plan, self.root)
        self.assertTrue((self.session / "pp407/build/make_release.sh").exists())
        self.assertTrue((self.session / "agent-wincapture/dist/app-1.0.zip").exists())
        self.assertTrue((self.session / "bare/node_modules/a/index.js").exists())
        self.assertFalse((self.session / "pp/node_modules").exists())

    def test_records_secrets_and_repositories_inside_a_rebuildable_folder_keep_it(self):
        proj = self.git_proj("proj", "dist/\nbuild/\ncoverage/\n")
        self.make("proj/build/notes.jsonl", "{}\n")
        self.make("proj/dist/wals/x.txt")
        self.make("proj/coverage/inner/.git/HEAD", "ref: refs/heads/main\n")
        self.make("pp/package.json", "{}")
        self.make("pp/node_modules/.claude/settings.json", "{}")
        self.make("pp2/package.json", "{}")
        self.make("pp2/node_modules/transcripts/t.txt")
        self.age_tree(self.session)
        plan = self.plan()
        self.assertEqual(self.ok_paths(plan), set())
        self.assertTrue((proj / "build/notes.jsonl").exists())

    def test_a_walk_that_hits_its_bound_keeps_the_folder(self):
        self.make("pp/package.json", "{}")
        for i in range(6):
            self.make("pp/node_modules/f%d.js" % i)
        self.age_tree(self.session)
        self.assertEqual(self.ok_paths(self.plan()), {"pp/node_modules"})
        with mock.patch.object(gc, "WALK_LIMIT", 3):
            self.assertEqual(self.ok_paths(self.plan()), set())

    def test_never_enters_git_state_session_logs_or_claude_folders(self):
        self.make(".git/node_modules/x")
        self.make(".git/package.json", "{}")
        self.make("state/node_modules/x")
        self.make("wals/node_modules/x")
        self.make(".claude/projects/node_modules/x")
        plan = self.plan()
        self.assertEqual([i for i in plan["items"] if i["ok"]], [])
        self.assertEqual([i["path"] for i in plan["items"]], [])  # not descended into at all

    def test_a_process_inside_or_at_the_repository_root_keeps_the_folder(self):
        proj = self.git_proj("proj", "node_modules/\n")
        self.make("proj/node_modules/a.js")
        self.age_tree(self.session)
        path = proj / "node_modules"
        self.assertEqual(self.ok_paths(self.plan()), {"proj/node_modules"})
        with mock.patch.object(gc, "in_use_paths", lambda: [str(path)]):
            self.assertEqual(self.ok_paths(self.plan()), set())
        with mock.patch.object(gc, "in_use_paths", lambda: [str(proj)]):  # a dev server run from the repo root
            self.assertEqual(self.ok_paths(self.plan()), set())

    def test_symlinked_folders_are_ignored(self):
        target = self.session / "realvenv" / "venv"  # an old, self-identifying venv: removable under its real path
        target.mkdir(parents=True)
        (target / "pyvenv.cfg").write_text("x")
        self.age_tree(self.session)
        self.assertTrue(gc.regen_verdict(target, ["/x"], self.root, 3.0)[0])
        link = self.session / "venv"
        os.symlink(target, link)
        self.assertEqual([i for i in self.plan()["items"] if i["path"] == str(link)], [])
        ok, reason = gc.regen_verdict(link, ["/x"], self.root, 3.0)
        self.assertFalse(ok, reason)
        self.assertIn("not a real directory", reason)


    def test_regen_folder_inside_a_removed_worktree_is_counted_once(self):
        path = self.worktree()
        exclude = out("git", "-C", str(path), "rev-parse", "--git-path", "info/exclude")
        exclude = Path(exclude) if os.path.isabs(exclude) else path / exclude
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text("node_modules/\n")
        (path / "node_modules").mkdir()
        (path / "node_modules/x.js").write_text("x\n")
        plan = self.plan()
        inner = self.item(plan, path / "node_modules")
        self.assertFalse(inner["ok"])
        self.assertIn("removed whole", inner["reason"])
        self.assertTrue(self.item(plan, path)["ok"])

    def test_dependencies_inside_a_busy_agents_worktree_are_kept_even_when_the_worktree_is_dirty(self):
        exclude = Path(out("git", "-C", str(self.repo), "rev-parse", "--absolute-git-dir")) / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text("node_modules/\n")
        path = self.worktree("agent-live", idle_hours=0.1)
        (path / "node_modules").mkdir()
        (path / "node_modules/x.js").write_text("x\n")
        self.assertFalse(self.item(self.plan(), path / "node_modules")["ok"])
        old = self.worktree("agent-done", idle_hours=10)
        (old / "dirty.txt").write_text("unique\n")  # not removable as a worktree, but its dependencies are
        (old / "node_modules").mkdir()
        (old / "node_modules/x.js").write_text("x\n")
        self.assertTrue(self.item(self.plan(), old / "node_modules")["ok"])
        self.assertFalse(self.item(self.plan(), old)["ok"])

    def test_a_read_only_subfolder_is_removed_after_one_chmod_and_a_failure_is_recorded_and_skipped(self):
        self.make("a/package.json", "{}")
        self.make("a/node_modules/ro/x.js")
        self.make("b/package.json", "{}")
        self.make("b/node_modules/y.js")
        self.age_tree(self.session)
        ro = self.session / "a/node_modules/ro"
        os.chmod(ro, 0o555)
        self.addCleanup(lambda: ro.exists() and os.chmod(ro, 0o755))
        plan = self.plan()
        results = gc.apply_plan(plan, self.root)
        self.assertEqual(sorted(r["status"] for r in results), ["removed", "removed"], results)
        self.make("c/package.json", "{}")
        self.make("c/node_modules/z.js")
        self.make("d/package.json", "{}")
        self.make("d/node_modules/z.js")
        self.age_tree(self.session)
        plan = self.plan()
        real = gc.shutil.rmtree
        first = []

        def flaky(path, *a, **kw):
            if not first:
                first.append(path)
                raise PermissionError(13, "Permission denied", str(path))
            return real(path, *a, **kw)

        with mock.patch.object(gc.shutil, "rmtree", flaky):
            results = gc.apply_plan(plan, self.root)
        self.assertEqual(sorted(r["status"] for r in results), ["failed", "removed"], results)
        failed = next(r for r in results if r["status"] == "failed")
        self.assertIn("Permission denied", failed["error"])
        audit = [json.loads(x) for x in gc.audit_path().read_text().splitlines()]
        self.assertIn("failed", [a["status"] for a in audit])


class Plans(Case):
    """F3: apply trusts nothing in the plan file but the list of candidate paths."""

    def aged_node_modules(self, parent: Path):
        (parent / "node_modules").mkdir(parents=True)
        (parent / "node_modules/x.js").write_text("x\n")
        (parent / "package.json").write_text("{}")
        for p in (parent / "node_modules/x.js", parent / "package.json"):
            age(p, p)
        age(parent / "node_modules", parent / "node_modules")
        return parent / "node_modules"

    def test_forged_entries_are_skipped(self):
        important = self.session / "important_dir"
        important.mkdir()
        (important / "work.txt").write_text("unique\n")
        age(important, self.session)
        outside = self.aged_node_modules(self.home / "outside")
        evil = self.aged_node_modules(Path(str(self.root) + "-evil") / SESSION)
        real = self.session / "realdir"
        real.mkdir()
        inside = self.aged_node_modules(real)
        os.symlink(real, self.session / "linkdir")
        via_link = self.session / "linkdir" / "node_modules"
        os.symlink(outside, self.session / "node_modules")
        forged = gc.seal({"idle_hours": 0, "items": [
            {"kind": "regen", "path": str(important), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(self.session), "ok": True, "bytes": 1},
            {"kind": "worktree", "path": str(self.session), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(outside), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(evil), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(via_link), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(self.session / "node_modules"), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(self.session / ".." / SESSION / "realdir" / "node_modules"), "ok": True},
            {"kind": "regen", "path": str(self.session / "dist"), "ok": False, "bytes": 1}]})
        results = gc.apply_plan(forged, self.root)
        self.assertEqual([r["status"] for r in results], ["skipped"] * 8, results)
        self.assertIn("not a rebuildable folder name", results[0]["reason"])  # the name check, not a later one
        self.assertIn("not a rebuildable folder name", results[1]["reason"])
        self.assertIn("not an agent worktree", results[2]["reason"])
        for row in results[3:]:
            self.assertIn("outside the work root", row["reason"], row)
        root_real = os.path.realpath(self.root)
        self.assertTrue(gc.path_in_root(str(inside), root_real))
        for bad in (str(outside), str(evil), str(via_link), str(self.session / "node_modules"), root_real,
                    str(Path(root_real + "-evil") / "x"), str(self.session / ".." / SESSION / "realdir")):
            with self.subTest(bad=bad):
                self.assertFalse(gc.path_in_root(bad, root_real))
        for p in (important / "work.txt", outside, evil, inside, self.session / "repo" / "a.txt"):
            self.assertTrue(p.exists(), p)
        # the real folder itself, named by its real path, is removable: the skips above are about the forged paths
        ok = gc.seal({"items": [{"kind": "regen", "path": str(inside), "ok": True, "bytes": 1}]})
        self.assertEqual([r["status"] for r in gc.apply_plan(ok, self.root)], ["removed"])

    def test_idle_hours_come_from_the_command_line_never_the_plan(self):
        path = self.worktree("agent-hour", idle_hours=1.0)
        forged = gc.seal({"idle_hours": 0, "items": [{"kind": "worktree", "path": str(path), "ok": True, "bytes": 1}]})
        results = gc.apply_plan(forged, self.root)
        self.assertEqual(results[0]["status"], "skipped")
        self.assertTrue(path.exists())
        with self.assertRaises(ValueError):
            gc.make_plan(self.root, 0, workers=1)
        with self.assertRaises(ValueError):
            gc.apply_plan(forged, self.root, idle_hours=1.0)
        planfile = self.home / "p.json"
        planfile.write_text(json.dumps(forged))
        for argv in (["plan", "--root", str(self.root), "--idle-hours", "0"],
                     ["apply", "--plan", str(planfile), "--root", str(self.root), "--idle-hours", "2"]):
            with self.subTest(argv=argv):
                try:
                    code = gc.main(argv)
                except SystemExit as stop:
                    code = stop.code
                self.assertNotEqual(code, 0)
        self.assertTrue(path.exists())

    def test_a_hand_edited_plan_is_refused(self):
        path = self.worktree()
        plan = self.plan()
        plan["items"].append({"kind": "regen", "path": str(self.session / "repo"), "ok": True, "bytes": 1})
        with self.assertRaises(ValueError):
            gc.apply_plan(plan, self.root)
        unsealed = {"items": [dict(i) for i in plan["items"][:1]]}
        with self.assertRaises(ValueError):
            gc.apply_plan(unsealed, self.root)
        self.assertTrue(path.exists())

    def test_two_applies_cannot_run_at_once(self):
        node_modules = self.aged_node_modules(self.session / "pp")
        plan = self.plan()
        lock = gc.lock_path()
        lock.parent.mkdir(parents=True, exist_ok=True)
        with open(lock, "a") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(RuntimeError):
                gc.apply_plan(plan, self.root)
            self.assertTrue(node_modules.exists())
        self.assertEqual([r["status"] for r in gc.apply_plan(plan, self.root)], ["removed"])

    def test_a_scan_cut_short_marks_the_plan_partial(self):
        self.aged_node_modules(self.session / "pp")
        self.assertFalse(self.plan().get("partial"))
        with mock.patch.object(gc, "SCAN_SECONDS", 0.0):
            plan = self.plan()
        self.assertTrue(plan["partial"])

    def test_a_failing_or_empty_lsof_or_ps_is_an_unreadable_process_list(self):
        for lsof, ps in (((1, "p1\nn/somewhere\n"), (0, "sh\n")), ((0, ""), (0, "sh\n")),
                         ((0, "p1\nn/somewhere\n"), (1, "")), ((0, "p1\nn/somewhere\n"), (0, ""))):
            with self.subTest(lsof=lsof, ps=ps):
                with fake_processes(lsof, ps):
                    self.assertIsNone(REAL_IN_USE())
        with fake_processes((0, "p1\nfcwd\nn/somewhere\n"), (0, "/bin/sh -c x\n")):
            self.assertEqual(sorted(REAL_IN_USE()), ["/bin/sh", "/somewhere"])


def fake_processes(lsof, ps):
    """Patch subprocess.run inside work_gc so lsof and ps return (returncode, stdout)."""
    calls = []

    def run(cmd, *a, **k):
        calls.append(cmd[0])
        if cmd[0] == "lsof":
            return subprocess.CompletedProcess(cmd, lsof[0], stdout=lsof[1], stderr="")
        if cmd[0] == "ps":
            return subprocess.CompletedProcess(cmd, ps[0], stdout=ps[1], stderr="")
        return REAL_RUN(cmd, *a, **k)

    return mock.patch.object(gc.subprocess, "run", run)


REAL_RUN = subprocess.run


class InUse(Case):
    """M1: a folder is busy when any process path (any fd, or its command line) is under it."""

    def setUp(self):
        super().setUp()
        self.real = mock.patch.object(gc, "in_use_paths", REAL_IN_USE)
        self.real.start()
        self.addCleanup(self.real.stop)

    def node_modules(self):
        nm = self.session / "deploy" / "node_modules"
        (nm / "wrangler").mkdir(parents=True)
        (nm / "wrangler/cli.js").write_text("x")
        (nm.parent / "package.json").write_text("{}")
        for p in (nm / "wrangler/cli.js", nm / "wrangler", nm.parent / "package.json"):
            age(p, p)
        age(nm, self.session)
        return nm

    def test_a_program_run_from_the_folder_keeps_it_though_its_cwd_is_elsewhere(self):
        nm = self.node_modules()
        idle = (0, "p6592\nfcwd\nn/Users/x/elsewhere\nftxt\nn/usr/local/bin/node\n")
        with fake_processes(idle, (0, "/usr/local/bin/node /tmp/other.js\n")):
            self.assertTrue(self.item(self.plan(), nm)["ok"])
        with fake_processes(idle, (0, "node %s/wrangler/cli.js tail --format=pretty\n" % nm)):
            row = self.item(self.plan(), nm)
        self.assertFalse(row["ok"], row)
        self.assertIn("uses a path inside", row["reason"])
        with fake_processes((0, idle[1] + "f12\nn%s/wrangler/cli.js\n" % nm), (0, "esbuild --service=0.19\n")):
            self.assertFalse(self.item(self.plan(), nm)["ok"])  # an open file inside, nothing on the command line
        with fake_processes(idle, (0, "node --require=%s/wrangler/cli.js x\n" % nm)):
            self.assertFalse(self.item(self.plan(), nm)["ok"])  # a path after '='

    def test_apply_takes_a_fresh_snapshot_for_each_item(self):
        first = self.node_modules()
        second = self.session / "b" / "node_modules"
        second.mkdir(parents=True)
        (second.parent / "package.json").write_text("{}")
        age(second.parent / "package.json", second.parent / "package.json")
        age(second, self.session)
        with mock.patch.object(gc, "in_use_paths", lambda: ["/elsewhere"]):
            plan = self.plan()
        self.assertTrue(self.item(plan, first)["ok"] and self.item(plan, second)["ok"])
        calls = []

        def snapshot():  # the second item comes into use after the first is removed
            calls.append(1)
            return ["/elsewhere"] if len(calls) == 1 else [str(second / "x")]

        with mock.patch.object(gc, "in_use_paths", snapshot):
            results = {r["path"]: r["status"] for r in gc.apply_plan(plan, self.root)}
        order = [i["path"] for i in plan["items"] if i["ok"]]
        self.assertEqual([results[p] for p in order], ["removed", "skipped"])
        self.assertTrue(Path(order[1]).exists())


class Round2(Case):
    """Delta red-team: liveness keys, git env, ls-remote hygiene, reflog, audit order, late swaps, survivors."""

    def subagent(self, worktree, key, fresh=True, name="agent-sub1"):
        subagents = self.home / ".claude" / "projects" / "-Users-x" / SESSION / "subagents"
        subagents.mkdir(parents=True, exist_ok=True)
        (subagents / (name + ".meta.json")).write_text(json.dumps({key: str(worktree), "agentType": "fixer"}))
        transcript = subagents / (name + ".jsonl")
        transcript.write_text("{}\n")
        if not fresh:
            age(transcript, transcript)

    def test_an_inherited_worktree_path_counts_as_activity_for_the_worktree_and_its_folders(self):
        path = self.worktree("agent-inh")
        exclude = Path(out("git", "-C", str(self.repo), "rev-parse", "--absolute-git-dir")) / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text("node_modules/\n")
        (path / "dirty.txt").write_text("keeps the worktree itself\n")
        (path / "node_modules").mkdir()
        (path / "node_modules/x.js").write_text("x\n")
        self.assertTrue(self.item(self.plan(), path / "node_modules")["ok"])
        self.subagent(path, "inheritedWorktreePath")
        plan = self.plan()
        self.assertFalse(self.item(plan, path / "node_modules")["ok"])
        self.assertIn("sub-agent", self.item(plan, path / "node_modules")["reason"])
        (path / "dirty.txt").unlink()
        row = self.item(self.plan(), path)
        self.assertFalse(row["ok"], row)
        self.assertIn("sub-agent", row["reason"])

    def test_a_callers_git_environment_does_not_redirect_the_checks(self):
        path = self.worktree()
        other = self.home / "other"
        run("git", "init", "-q", str(other))
        (other / "junk.txt").write_text("x\n")
        with mock.patch.dict(os.environ, {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other),
                                          "GIT_INDEX_FILE": str(other / ".git" / "index")}):
            row = self.item(self.plan(), path)
        self.assertTrue(row["ok"], row)

    def test_transport_helpers_and_local_scp_lookalikes_are_not_remotes(self):
        for url in ("ext::github.com:x", "https://github.com/o/r::x", "fd::github.com:3"):
            self.assertFalse(gc.remote_host_allowed(url), url)
        for url in (".:x", "..:x", "~:x"):
            self.assertEqual(gc.remote_host(url), "", url)
        seen = {}

        def fake(cmd, *a, **k):
            seen.update(cmd=cmd, env=k.get("env"), stdin=k.get("stdin"), cwd=k.get("cwd"))
            return subprocess.CompletedProcess(cmd, 0, stdout="%s\trefs/heads/main\n" % ("a" * 40), stderr="")

        with mock.patch.object(gc.subprocess, "run", fake):
            self.assertEqual(gc.live_ls_remote("https://github.com/o/r.git"), {"refs/heads/main": "a" * 40})
            self.assertIn("BatchMode=yes", seen["env"]["GIT_SSH_COMMAND"])
            self.assertEqual(seen["stdin"], subprocess.DEVNULL)
            self.assertEqual(seen["cwd"], "/")
            self.assertNotIn("GIT_DIR", seen["env"])
            seen.clear()
            self.assertIsNone(gc.live_ls_remote("ext::sh -c x"))
            self.assertEqual(seen, {})  # never even run

    def test_listings_of_different_urls_do_not_wait_for_each_other(self):
        import threading
        ready = threading.Event()
        answers = {}

        def slow(url):
            if url == "a":
                answers["a"] = ready.wait(5)
            else:
                ready.set()
            return {}

        ctx = gc.Context(self.root, 3.0, None, slow)
        t = threading.Thread(target=ctx.listing, args=("a",))
        t.start()
        time.sleep(0.2)
        ctx.listing("b")
        t.join(10)
        self.assertTrue(answers.get("a"))

    def test_reset_away_commits_in_the_worktree_reflog_keep_it(self):
        path = self.worktree("agent-reset", pushed=False)  # one unpushed commit
        run("git", "reset", "-q", "--hard", "origin/main", cwd=path)  # HEAD is pushed again; the commit is reflog-only
        row = self.item(self.plan(), path)
        self.assertFalse(row["ok"], row)
        self.assertIn("reflog", row["reason"])

    def test_a_remote_head_tracking_ref_is_never_proof(self):
        path = self.worktree("agent-rhead", pushed=False)
        head = out("git", "-C", str(path), "rev-parse", "HEAD")
        run("git", "update-ref", "refs/remotes/origin/HEAD", head, cwd=path)
        row = self.item(self.plan(ls_remote=lambda url: {"refs/heads/HEAD": head}), path)
        self.assertFalse(row["ok"], row)

    def test_submodules_and_hidden_index_entries_keep_the_worktree(self):
        sub = self.worktree("agent-submod")
        sha = out("git", "-C", str(self.repo), "rev-parse", "main")
        run("git", "update-index", "--add", "--cacheinfo", "160000,%s,lib" % sha, cwd=sub)
        (sub / "lib").mkdir()  # an uninitialized submodule: an empty folder, so status shows nothing
        run("git", "commit", "-q", "-m", "gitlink", cwd=sub)
        run("git", "push", "-q", "origin", "HEAD:refs/heads/feat-agent-submod", cwd=sub)
        run("git", "fetch", "-q", "origin", cwd=sub)
        hidden = {}
        for flag in ("--assume-unchanged", "--skip-worktree"):
            path = self.worktree("agent" + flag.replace("--", "-"))
            run("git", "update-index", flag, "a.txt", cwd=path)
            (path / "a.txt").write_text("edited where status cannot see it\n")
            hidden[flag] = path
        plan = self.plan()
        self.assertIn("submodule", self.item(plan, sub)["reason"])
        for flag, path in hidden.items():
            with self.subTest(flag=flag):
                self.assertIn("assume-unchanged or skip-worktree", self.item(plan, path)["reason"])

    def test_an_unknown_lock_state_keeps_the_worktree(self):
        path = self.worktree()
        with mock.patch.object(gc, "worktree_locked", lambda p: None):
            row = self.item(self.plan(), path)
        self.assertFalse(row["ok"])
        self.assertIn("cannot tell whether the worktree is locked", row["reason"])

    def test_regen_refusals_hold_on_their_own(self):
        # a session-log location, even with a package.json beside it
        logs = self.session / "wals"
        (logs / "node_modules").mkdir(parents=True)
        (logs / "package.json").write_text("{}")
        age(logs / "package.json", logs / "package.json")
        age(logs / "node_modules", self.session)
        ok, reason = gc.regen_verdict(logs / "node_modules", ["/x"], self.root, 3.0)
        self.assertFalse(ok)
        self.assertIn("session-log", reason)
        # a broken repository around the folder: never fall back to the outside-git rules
        broken = self.session / "broken"
        (broken / "node_modules").mkdir(parents=True)
        (broken / "package.json").write_text("{}")
        (broken / ".git").write_text("gitdir: /nonexistent/elsewhere\n")
        for p in (broken / "package.json", broken / ".git"):
            age(p, p)
        age(broken / "node_modules", self.session)
        ok, reason = gc.regen_verdict(broken / "node_modules", ["/x"], self.root, 3.0)
        self.assertFalse(ok)
        self.assertIn("could not inspect", reason)
        # ls-files failing is never read as "nothing tracked"
        proj = self.session / "proj"
        run("git", "init", "-q", str(proj))
        (proj / ".gitignore").write_text("dist/\n")
        (proj / "dist").mkdir()
        real_git = gc.git

        def failing(path, *args, **kw):
            return (1, "") if args and args[0] == "ls-files" else real_git(path, *args, **kw)

        with mock.patch.object(gc, "git", failing):
            with self.assertRaises(gc.Refuse) as why:
                gc.check_regen_origin(proj / "dist", self.root)
        self.assertIn("tracks", str(why.exception))
        self.assertIn("untracked and ignored", gc.check_regen_origin(proj / "dist", self.root))

    def test_an_unreadable_subfolder_is_never_treated_as_walked(self):
        dist = self.session / "x" / "dist"
        (dist / "locked").mkdir(parents=True)
        (dist / "locked" / "secret.txt").write_text("x")
        os.chmod(dist / "locked", 0)
        self.addCleanup(os.chmod, dist / "locked", 0o755)
        with self.assertRaises(gc.Refuse):
            gc.scan_folder(dist, "dist")

    def test_chmod_retry_never_touches_the_folder_above(self):
        top = self.session / "ro"
        nm = top / "node_modules"
        nm.mkdir(parents=True)
        (nm / "x.js").write_text("x")
        os.chmod(top, 0o555)
        self.addCleanup(os.chmod, top, 0o755)
        with self.assertRaises(PermissionError):
            gc.remove_tree(nm)
        self.assertEqual(os.stat(top).st_mode & 0o777, 0o555)

    def test_a_plan_for_another_root_is_refused(self):
        plan = gc.seal({"root": str(self.home / "elsewhere"), "items": []})
        with self.assertRaises(ValueError):
            gc.apply_plan(plan, self.root)

    def test_a_worktree_is_reported_removed_only_when_it_is_gone(self):
        path = self.worktree()
        plan = self.plan()
        real_git = gc.git

        def noop_remove(p, *args, **kw):
            return (0, "") if args[:2] == ("worktree", "remove") else real_git(p, *args, **kw)

        with mock.patch.object(gc, "git", noop_remove):
            results = gc.apply_plan(plan, self.root)
        self.assertEqual(results[0]["status"], "failed", results)
        self.assertTrue(path.exists())

    def test_an_intent_row_precedes_each_removal_and_a_failing_audit_never_stops_the_run(self):
        node_modules = self.session / "pp" / "node_modules"
        node_modules.mkdir(parents=True)
        (node_modules.parent / "package.json").write_text("{}")
        age(node_modules.parent / "package.json", node_modules.parent / "package.json")
        age(node_modules, self.session)
        plan = self.plan()
        seen = []
        real_remove = gc.remove_tree

        def remove(path):
            rows = [json.loads(x) for x in gc.audit_path().read_text().splitlines()]
            seen.append((rows[-1]["status"], rows[-1]["path"]))
            real_remove(path)

        with mock.patch.object(gc, "remove_tree", remove):
            results = gc.apply_plan(plan, self.root)
        self.assertEqual(seen, [("removing", str(node_modules))])
        self.assertEqual(results[0]["status"], "removed")
        statuses = [json.loads(x)["status"] for x in gc.audit_path().read_text().splitlines()]
        self.assertEqual(statuses[-2:], ["removing", "removed"])
        # an audit log that cannot be written: nothing is removed, the run finishes, the error is reported
        node_modules.mkdir()
        age(node_modules, self.session)
        plan = self.plan()
        with mock.patch.object(gc, "record", mock.Mock(side_effect=OSError("disk full"))):
            results = gc.apply_plan(plan, self.root)
        self.assertEqual([r["status"] for r in results], ["failed"])
        self.assertIn("disk full", results[0]["audit_error"])
        self.assertTrue(node_modules.exists())

    def test_a_folder_swapped_for_a_symlink_after_the_check_is_not_removed(self):
        outside = self.home / "precious"
        outside.mkdir()
        (outside / "keep.txt").write_text("unique\n")
        node_modules = self.session / "pp" / "node_modules"
        node_modules.mkdir(parents=True)
        (node_modules.parent / "package.json").write_text("{}")
        age(node_modules.parent / "package.json", node_modules.parent / "package.json")
        age(node_modules, self.session)
        plan = self.plan()
        real_verdict = gc.regen_verdict

        def verdict_then_swap(path, *a, **k):
            result = real_verdict(path, *a, **k)
            os.rmdir(path)
            os.symlink(outside, path)
            return result

        with mock.patch.object(gc, "regen_verdict", verdict_then_swap):
            results = gc.apply_plan(plan, self.root)
        self.assertEqual(results[0]["status"], "skipped", results)
        self.assertTrue((outside / "keep.txt").exists())


class Cli(Case):
    def test_plan_prints_sizes_and_writes_a_plan_that_apply_consumes(self):
        (self.session / "proj/node_modules").mkdir(parents=True)
        (self.session / "proj/node_modules/a.js").write_text("x" * 5000)
        (self.session / "proj/package.json").write_text("{}")
        old = time.time() - 10 * 3600
        os.utime(self.session / "proj/node_modules", (old, old))
        planfile = self.home / "plan.json"
        self.assertEqual(gc.main(["plan", "--root", str(self.root), "--out", str(planfile)]), 0)
        self.assertTrue(json.loads(planfile.read_text())["items"])
        self.assertTrue((self.session / "proj/node_modules").exists())  # a dry run removes nothing
        self.assertEqual(gc.main(["apply", "--plan", str(planfile), "--root", str(self.root)]), 0)
        self.assertFalse((self.session / "proj/node_modules").exists())


if __name__ == "__main__":
    unittest.main()
