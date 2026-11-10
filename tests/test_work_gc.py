"""GoodQA #15565: work-dir GC removes only finished, clean, pushed worktrees and rebuildable folders, from a dry-run plan."""
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

SESSION = "11111111-1111-4111-8111-111111111111"


def run(*cmd, cwd=None):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e"))


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
        self.cwds = mock.patch.object(gc, "process_cwds", lambda: ["/somewhere/else"])
        self.cwds.start()
        self.addCleanup(self.cwds.stop)
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

    def worktree(self, name="agent-abc", idle_hours=10.0, pushed=True):
        path = self.repo / ".claude" / "worktrees" / name
        run("git", "worktree", "add", "-q", "-b", "feat-" + name, str(path), cwd=self.repo)
        if not pushed:
            (path / "b.txt").write_text("b\n")
            run("git", "add", "-A", cwd=path)
            run("git", "commit", "-q", "-m", "unpushed", cwd=path)
        log = self.wals / (name + ".jsonl")
        log.write_text("{}\n")
        old = time.time() - idle_hours * 3600
        os.utime(log, (old, old))
        return path

    def plan(self, idle=3.0):
        return gc.make_plan(self.root, idle, workers=2)

    def item(self, plan, path):
        return next(i for i in plan["items"] if i["path"] == str(path))


class Worktrees(Case):
    def test_a_finished_clean_pushed_worktree_is_reclaimable_and_removed_leaving_the_branch(self):
        path = self.worktree()
        plan = self.plan()
        self.assertTrue(self.item(plan, path)["ok"], self.item(plan, path))
        results = gc.apply_plan(plan, self.root)
        self.assertEqual([r["status"] for r in results], ["removed"])
        self.assertFalse(path.exists())
        out = subprocess.run(["git", "-C", str(self.repo), "branch", "--list", "feat-agent-abc"], capture_output=True, text=True).stdout
        self.assertIn("feat-agent-abc", out)  # the branch survives
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
        plan = self.plan()
        for name, path in cases.items():
            with self.subTest(name=name):
                self.assertFalse(self.item(plan, path)["ok"], self.item(plan, path))
        gc.apply_plan(plan, self.root)
        for path in cases.values():
            self.assertTrue(path.exists())

    def test_ignored_build_output_inside_a_clean_worktree_does_not_block(self):
        path = self.worktree()
        (path / ".gitignore").write_text("dist/\n")
        run("git", "add", "-A", cwd=path)
        run("git", "commit", "-q", "-m", "ignore", cwd=path)
        run("git", "push", "-q", "origin", "HEAD:refs/heads/feat-agent-abc", cwd=path)
        run("git", "fetch", "-q", "origin", cwd=path)
        (path / "dist").mkdir()
        (path / "dist/x.js").write_text("x\n")
        self.assertTrue(self.item(self.plan(), path)["ok"])

    def test_a_process_inside_the_worktree_keeps_it(self):
        path = self.worktree()
        with mock.patch.object(gc, "process_cwds", lambda: [str(path / "sub")]):
            self.assertFalse(self.item(self.plan(), path)["ok"])
        with mock.patch.object(gc, "process_cwds", lambda: None):  # an unreadable process list removes nothing
            self.assertFalse(self.item(self.plan(), path)["ok"])

    def test_apply_re_verifies_so_a_change_after_the_plan_is_respected(self):
        path = self.worktree()
        plan = self.plan()
        (path / "late.txt").write_text("new unique work\n")
        results = gc.apply_plan(plan, self.root)
        self.assertEqual(results[0]["status"], "skipped")
        self.assertTrue(path.exists())

    def test_apply_ignores_items_not_ok_and_paths_outside_the_root_or_via_symlink(self):
        outside = self.home / "outside" / "node_modules"
        outside.mkdir(parents=True)
        link = self.session / "node_modules"
        os.symlink(outside, link)
        plan = {"idle_hours": 3.0, "items": [
            {"kind": "regen", "path": str(outside), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(link), "ok": True, "bytes": 1},
            {"kind": "regen", "path": str(self.session / "dist"), "ok": False, "bytes": 1}]}
        results = gc.apply_plan(plan, self.root)
        self.assertEqual([r["status"] for r in results], ["skipped", "skipped"])
        self.assertTrue(outside.exists())


class Regenerable(Case):
    def make(self, rel, content="x\n"):
        path = self.session / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        old = time.time() - 10 * 3600
        for parent in [path, *path.parents]:
            if str(parent).startswith(str(self.session)):
                os.utime(parent, (old, old))
        return path

    def test_recently_changed_rebuildable_folders_are_kept(self):
        path = self.session / "fresh" / "node_modules"
        path.mkdir(parents=True)
        (path / "a.js").write_text("x\n")
        self.assertEqual([i for i in self.plan()["items"] if i["ok"]], [])

    def test_rebuildable_folders_are_removed_and_a_folder_with_a_log_is_kept(self):
        self.make("proj/node_modules/a/index.js")
        self.make("proj/.venv/bin/python")
        self.make("proj/dist/app.js")
        self.make("proj/build/notes.jsonl", "{}\n")  # a .jsonl inside: a record, not output
        self.make("proj/cache/keep.txt")  # not a rebuildable name
        plan = self.plan()
        ok = {Path(i["path"]).relative_to(self.session).as_posix() for i in plan["items"] if i["ok"]}
        self.assertEqual(ok, {"proj/node_modules", "proj/.venv", "proj/dist"})
        gc.apply_plan(plan, self.root)
        self.assertFalse((self.session / "proj/node_modules").exists())
        self.assertTrue((self.session / "proj/build/notes.jsonl").exists())
        self.assertTrue((self.session / "proj/cache/keep.txt").exists())

    def test_never_enters_git_state_session_logs_or_claude_folders(self):
        self.make(".git/node_modules/x")
        self.make("state/node_modules/x")
        self.make("wals/node_modules/x")
        self.make(".claude/projects/node_modules/x")
        plan = self.plan()
        self.assertEqual([i for i in plan["items"] if i["ok"]], [])

    def test_a_process_inside_keeps_the_folder_and_symlinked_folders_are_ignored(self):
        path = self.make("proj/node_modules/a.js").parent
        with mock.patch.object(gc, "process_cwds", lambda: [str(path)]):
            self.assertEqual([i for i in self.plan()["items"] if i["ok"]], [])
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, self.session / "venv")
        self.assertEqual([i for i in self.plan()["items"] if i["path"].endswith("/venv")], [])

    def test_regen_folder_inside_a_removed_worktree_is_counted_once(self):
        path = self.worktree()
        exclude = subprocess.run(["git", "-C", str(path), "rev-parse", "--git-path", "info/exclude"],
                                 capture_output=True, text=True).stdout.strip()
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


class Cli(Case):
    def test_plan_prints_sizes_and_writes_a_plan_that_apply_consumes(self):
        (self.session / "proj/node_modules").mkdir(parents=True)
        (self.session / "proj/node_modules/a.js").write_text("x" * 5000)
        old = time.time() - 10 * 3600
        os.utime(self.session / "proj/node_modules", (old, old))
        out = self.home / "plan.json"
        self.assertEqual(gc.main(["plan", "--root", str(self.root), "--out", str(out)]), 0)
        self.assertTrue(json.loads(out.read_text())["items"])
        self.assertTrue((self.session / "proj/node_modules").exists())  # a dry run removes nothing
        self.assertEqual(gc.main(["apply", "--plan", str(out), "--root", str(self.root)]), 0)
        self.assertFalse((self.session / "proj/node_modules").exists())


if __name__ == "__main__":
    unittest.main()
