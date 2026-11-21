import json, os, subprocess, sys, tempfile, time, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "harness", "hooks"))
import workspace_janitor as wj

OLD = time.time() - 3 * 86400
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")


def sh(*a, cwd=None):
    subprocess.run(a, cwd=cwd, check=True, capture_output=True, env=ENV)


def age(p):
    for dp, dn, fn in os.walk(p):
        for f in dn + fn:
            os.utime(os.path.join(dp, f), (OLD, OLD), follow_symlinks=False)


class Janitor(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.home = os.path.join(self.t, "home"); os.makedirs(self.home)
        os.environ["HARNESS_JANITOR_HOME"] = self.home
        self.origin = os.path.join(self.t, "origin.git")
        sh("git", "init", "-q", "-b", "main", "--bare", self.origin)
        seed = os.path.join(self.t, "seed"); sh("git", "init", "-q", "-b", "main", seed)
        with open(os.path.join(seed, "a"), "w") as f:
            f.write("a")
        sh("git", "add", ".", cwd=seed); sh("git", "commit", "-qm", "a", cwd=seed); sh("git", "push", "-q", self.origin, "main", cwd=seed)
        self.work = os.path.join(self.home, ".agent-harness", "work")
        self.p_used = mock.patch.object(wj, "in_use_paths", return_value=set())
        self.p_refs = mock.patch.object(wj, "service_refs", return_value=set())
        self.p_used.start(); self.p_refs.start()

    def tearDown(self):
        mock.patch.stopall()
        os.environ.pop("HARNESS_JANITOR_HOME", None)

    def clone(self, rel):
        p = os.path.join(self.work, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
        sh("git", "clone", "-q", self.origin, p)
        return p

    def test_release_removes_clean_pushed_and_keeps_dirty(self):
        clean = self.clone("s1/clean"); dirty = self.clone("s1/dirty")
        os.makedirs(os.path.join(clean, "node_modules", "x"))
        with open(os.path.join(dirty, "new.txt"), "w") as f:
            f.write("work")
        r = wj.release(os.path.join(self.work, "s1"), apply=True)
        self.assertFalse(os.path.exists(clean)); self.assertTrue(os.path.exists(dirty))
        self.assertEqual(r["kept"][0]["why"], "uncommitted or untracked files")
        self.assertTrue(os.path.exists(os.path.join(self.work, "s1")))

    def test_release_keeps_unpushed_and_removes_empty_session(self):
        ahead = self.clone("s2/ahead")
        sh("git", "commit", "-q", "--allow-empty", "-m", "local", cwd=ahead)
        r = wj.release(os.path.join(self.work, "s2"), apply=True)
        self.assertTrue(os.path.exists(ahead)); self.assertIn("no remote", r["kept"][0]["why"])
        sh("git", "push", "-q", "origin", "HEAD:refs/heads/f", cwd=ahead); sh("git", "fetch", "-q", cwd=ahead)
        r = wj.release(os.path.join(self.work, "s2"), apply=True)
        self.assertFalse(os.path.exists(os.path.join(self.work, "s2")))

    def test_service_reference_and_open_files_protect(self):
        c = self.clone("s3/svc")
        with mock.patch.object(wj, "service_refs", return_value={c + "/run.sh"}):
            r = wj.release(os.path.join(self.work, "s3"), apply=True)
        self.assertTrue(os.path.exists(c)); self.assertIn("systemd", r["kept"][0]["why"])
        with mock.patch.object(wj, "in_use_paths", return_value={c + "/a"}):
            wj.release(os.path.join(self.work, "s3"), apply=True)
        self.assertTrue(os.path.exists(c))

    def test_linked_worktree_removed_with_plain_remove_and_base_kept(self):
        base = self.clone("s4/base")
        wt = os.path.join(self.work, "s5", "wt")
        os.makedirs(os.path.dirname(wt)); sh("git", "worktree", "add", "-q", "--detach", wt, cwd=base)
        r = wj.release(os.path.join(self.work, "s4"), apply=True)          # base has a live worktree elsewhere
        self.assertTrue(os.path.exists(base)); self.assertIn("other linked worktrees", r["kept"][0]["why"])
        wj.release(os.path.join(self.work, "s5"), apply=True)
        self.assertFalse(os.path.exists(wt))
        self.assertEqual(subprocess.run(["git", "-C", base, "worktree", "list"], capture_output=True, text=True).stdout.count("\n"), 1)

    def test_protected_name_and_kill_switch(self):
        c = self.clone("yates-x/c")
        wj.release(os.path.join(self.work, "yates-x"), apply=True)
        self.assertTrue(os.path.exists(c))
        c2 = self.clone("s6/c")
        with mock.patch.dict(os.environ, {"HARNESS_JANITOR": "off"}):
            r = wj.release(os.path.join(self.work, "s6"), apply=True)
        self.assertTrue(os.path.exists(c2)); self.assertEqual(r["removed"][0], c2)  # reported only

    def test_sweep_respects_ttl(self):
        fresh = self.clone("s7/fresh"); old = self.clone("s8/old"); age(os.path.join(self.work, "s8"))
        with mock.patch.object(wj, "uncapped_containers", return_value=[]), mock.patch.object(wj, "shm_sweep", return_value=[]):
            r = wj.sweep(apply=True)
        self.assertTrue(os.path.exists(fresh)); self.assertFalse(os.path.exists(old))
        self.assertEqual(r["mode"], "apply")

    def test_checkout_reuses_one_worktree_per_key(self):
        p1 = wj.checkout(self.origin, "pr-12")
        p2 = wj.checkout(self.origin, "pr-12")
        self.assertEqual(p1, p2)
        self.assertTrue(os.path.isfile(os.path.join(p1, "a")))
        with open(os.path.join(p1, "a"), "w") as f:
            f.write("edit")
        wj.checkout(self.origin, "pr-12")       # dirty: left alone
        with open(os.path.join(p1, "a")) as f:
            self.assertEqual(f.read(), "edit")
        self.assertEqual(len(os.listdir(os.path.join(self.home, ".agent-harness", "mirrors"))), 1)

    def test_pretool_container_caps(self):
        ev = lambda c: {"tool_name": "Bash", "tool_input": {"command": c}}
        self.assertEqual(wj.pretool(ev("docker run -d redis"))[0], 2)
        self.assertEqual(wj.pretool(ev("docker run -d --memory 2g redis"))[0], 0)
        self.assertEqual(wj.pretool(ev("docker run -m=2g redis"))[0], 0)
        self.assertEqual(wj.pretool(ev("cd x && sudo docker run --memory=4g elasticsearch:8"))[0], 2)
        self.assertEqual(wj.pretool(ev("docker run --memory=4g -e ES_JAVA_OPTS='-Xmx1g' elasticsearch:8"))[0], 0)
        self.assertEqual(wj.pretool(ev("docker ps; echo 'docker run x'"))[0], 0)
        self.assertEqual(wj.pretool({"tool_name": "Read"})[0], 0)
        self.assertEqual(wj.pretool(ev("docker run 'unterminated"))[0], 0)


if __name__ == "__main__":
    unittest.main()
