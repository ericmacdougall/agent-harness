"""S1 (GoodQA goodqa#15946): PR 238 round-1 review fixes.

F1: an unstamped caller on an unbound lane must not pass checkpoint authorization (real caller-state, through
ah_lane.run). F2: an existing worktree path is accepted only when it is a worktree of the intended repository on the
expected branch, not a symlink, not the main checkout (read in Python, no exec).
Bounded: at most 8 short git setup subprocesses per test class, temp directories only, no network.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ah_lane  # noqa: E402
from lane import commands as cmd, lanes, manifest as mf, store as st  # noqa: E402
from test_lane_commands import Cmd, FakeTicket, owner  # noqa: E402
from test_lane_kit import git  # noqa: E402


def init_repo(path, branch="main"):
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", branch)
    git(path, "commit", "-q", "--allow-empty", "-m", "i")
    return path


class UnstampedCallerTests(Cmd):
    """Real caller state: ah_lane.RealPorts keeps its own is_main, holder_caller, set_caller and caller; only the
    outside world (ticket, session log, clock) is replaced. No stamp exists in the temp HOME."""

    def setUp(self):
        super().setUp()
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.base)
        for k in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID"):
            os.environ.pop(k, None)
        class Ports(ah_lane.RealPorts):  # real caller-state methods; `ticket` becomes a plain attribute
            ticket = None
        real = Ports.__new__(Ports)
        real._caller = {"id": "main"}
        real.session = "sess"
        for name in ("now", "new_id", "templates_root", "policy_files", "default_kit_version", "host_alias", "ticket",
                     "tier_policy", "owners", "ledger", "escalation_root", "grant_for", "make_worktree", "spawn_observed",
                     "spawn_spec", "reviewer_line", "dispatch_task_key", "subagent_start_seen", "task_register",
                     "last_remote_head", "spec_state", "ls_remote", "local_git", "is_ancestor"):
            setattr(real, name, getattr(self.p, name))
        self.effects = []
        real.wal_note = lambda lane, kind, note, op_key, target: self.effects.append("wal") or "row1"
        self.real = real

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.old_home
        super().tearDown()

    def cp(self, lane):
        args = ah_lane.build_parser().parse_args(["checkpoint", "--lane", lane, "--kind", "plan", "--note", "n"])
        return ah_lane.run(args, self.real, self.store)

    def mk_unbound(self):
        self.p.is_main = lambda c, k: True
        lane = self.mk()
        return lane

    def snapshot(self, lane):
        d = self.store.lane_dir(lane)
        return ((d / "journal.jsonl").read_bytes(), sorted(p.name for p in d.iterdir()), list(self.ticket.comments))

    def test_unstamped_caller_on_an_unbound_lane_is_refused_with_zero_effects(self):  # F1
        lane = self.mk_unbound()
        before = self.snapshot(lane)
        calls = len(self.ticket.calls)
        r = self.cp(lane)
        self.assertEqual(r.code, cmd.REFUSED, r.lines)
        self.assertEqual(self.effects, [])
        self.assertEqual(self.snapshot(lane), before)
        self.assertEqual(len(self.ticket.calls), calls)

    def test_unstamped_caller_on_a_bound_lane_is_refused(self):
        lane = self.mk_unbound()
        cmd.start(self.p, self.store, lane=lane)
        m = mf.read_current(self.store.lane_dir(lane))
        self.dispatch["A1"] = m["stream_key"]
        self.owner_rows = [owner(1)]
        cmd.bind(self.p, self.store, lane=lane, agent="A1")
        before = self.snapshot(lane)
        self.assertEqual(self.cp(lane).code, cmd.REFUSED)
        self.assertEqual((self.effects, self.snapshot(lane)), ([], before))

    def test_empty_or_none_caller_is_refused_even_if_the_holder_is_also_empty(self):  # F1 handler level
        lane = self.mk_unbound()
        for who in (None, "", "main-ish"):
            with self.subTest(who=who):
                self.p.is_main = lambda c, k: False
                self.p.caller = lambda who=who: {"id": who, "session": "s"}
                r = cmd.checkpoint(self.p, self.store, lane=lane, kind="plan", note="n")
                self.assertEqual(r.code, cmd.REFUSED)
        self.assertEqual(self.notes, [])

    def test_a_stamped_holder_still_works(self):  # positive control
        lane = self.mk_unbound()
        cmd.start(self.p, self.store, lane=lane)
        m = mf.read_current(self.store.lane_dir(lane))
        self.dispatch["A1"] = m["stream_key"]
        self.owner_rows = [owner(1)]
        cmd.bind(self.p, self.store, lane=lane, agent="A1")
        self.p.is_main = lambda c, k: False
        self.p.caller = lambda: {"id": "A1", "session": "s"}
        self.assertEqual(cmd.checkpoint(self.p, self.store, lane=lane, kind="plan", note="n").code, 0)

    def test_main_with_a_real_stamp_still_works(self):
        from lane import auth
        import caller_identity as ci
        lane = self.mk_unbound()
        ci.put_stamp("lane-main", ["checkpoint", lane], session="s", home=self.base)
        self.real.is_main = lambda c, k: ci.take_stamp("lane-main", [c, k], home=self.base) is not None
        self.assertEqual(self.cp(lane).code, 0)


class WorktreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(os.path.realpath(self.tmp.name))
        self.repo = init_repo(self.base / "repo")
        git(self.repo, "worktree", "add", "-q", "-b", "lane/x", str(self.base / "wt"))
        self.wt = self.base / "wt"

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, worktree, repo=None, branch="lane/x"):
        from lane import worktrees
        return worktrees.verify_worktree(str(worktree), str(repo or self.repo), branch)

    def refused(self, worktree, **kw):
        with self.assertRaises(lanes.LaneRefusal):
            self.verify(worktree, **kw)

    def test_a_registered_worktree_on_the_expected_branch_is_accepted(self):  # positive control
        self.verify(self.wt)

    def test_unrelated_directory_is_refused(self):
        plain = self.base / "plain"
        plain.mkdir()
        self.refused(plain)
        other = init_repo(self.base / "own-git")  # a real git repo that is not a worktree of the repo
        self.refused(other)

    def test_another_repos_worktree_is_refused(self):
        repo_b = init_repo(self.base / "repo-b")
        git(repo_b, "worktree", "add", "-q", "-b", "lane/x", str(self.base / "wt-b"))
        self.refused(self.base / "wt-b")

    def test_wrong_branch_or_detached_head_is_refused(self):
        git(self.repo, "worktree", "add", "-q", "-b", "other", str(self.base / "wt-other"))
        self.refused(self.base / "wt-other")
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.base / "wt-detached"))
        self.refused(self.base / "wt-detached")

    def test_symlink_to_a_valid_worktree_is_refused(self):
        link = self.base / "link-to-wt"
        link.symlink_to(self.wt)
        self.refused(link)

    def test_the_main_checkout_itself_is_refused(self):
        self.refused(self.repo, branch="main")

    def test_a_forged_gitdir_file_pointing_at_a_valid_admin_dir_is_refused(self):
        forged = self.base / "forged"
        forged.mkdir()
        admin = next((self.repo / ".git" / "worktrees").iterdir())
        (forged / ".git").write_text("gitdir: %s\n" % admin)
        self.refused(forged)  # the admin dir's back-link names the real worktree, not this directory

    def test_start_refuses_before_reserving_and_a_good_path_is_accepted(self):  # F2 through the real port and start
        class C(Cmd):
            def runTest(self):
                pass
        c = C()
        c.setUp()
        try:
            c.p.is_main = lambda cmd_, k: True
            real_wt = lambda b, w, r: ah_lane.RealPorts.make_worktree(None, b, w, r)  # noqa: E731
            c.p.make_worktree = real_wt
            lane = c.mk()
            d = c.store.lane_dir(lane)
            m = mf.read_current(d)
            bad = self.base / "unrelated"
            bad.mkdir()
            mf.write_revision(d, dict(m, worktree=str(bad), repo_path=str(self.repo), branch="lane/x"))
            r = cmd.start(c.p, c.store, lane=lane)
            self.assertEqual(r.code, cmd.REFUSED, r.lines)
            rows = (d / "journal.jsonl").read_text()
            self.assertNotIn("start_reserved", rows)
            self.assertFalse((d / "prompt.md").exists())
            mf.write_revision(d, dict(mf.read_current(d), worktree=str(self.wt)))
            ok = cmd.start(c.p, c.store, lane=lane)
            self.assertEqual(ok.code, 0, ok.lines)
            self.assertIn("start_reserved", (d / "journal.jsonl").read_text())
        finally:
            c.tearDown()

    def test_no_process_is_started_to_verify(self):  # AC-8
        from lane import worktrees
        hits = []
        orig = subprocess.Popen.__init__
        subprocess.Popen.__init__ = lambda s, *a, **k: hits.append(a) or (_ for _ in ()).throw(OSError("no exec"))
        try:
            worktrees.verify_worktree(str(self.wt), str(self.repo), "lane/x")
            with self.assertRaises(lanes.LaneRefusal):
                worktrees.verify_worktree(str(self.base), str(self.repo), "lane/x")
        finally:
            subprocess.Popen.__init__ = orig
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
