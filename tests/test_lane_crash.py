"""S1 (GoodQA goodqa#15946): crash recovery of create and kit regeneration, manifest revision chain, kit input safety.

Covers AC-1, AC-2, AC-4, AC-43, NEG-4 and the crash contract of AC-52 in software-factory/s1/spec.md.
Bounded probes: each crash point forks one short-lived child that terminates with os._exit at that publication
boundary (no exception cleanup runs); at most 9 sequential children, one temp directory, 60 s timeout each.
"""
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lane import kit, lanes, manifest as mf, store as st  # noqa: E402
from test_lane_kit import Base, NOW, TICKET, git  # noqa: E402


def _child(action, point, store_root, templates, repo, lane_id):
    def hook(p):
        if p == point:
            os._exit(17)
    lanes._crash_hook = hook
    mf._crash_hook = hook
    s = st.Store(store_root)
    if action == "create":
        ids = iter(["lane_crash1"])
        lanes.create_lane(s, ticket=TICKET, repo=repo, profile="generic", host_alias="mac", branch="b",
                          worktree="/w", session="s", now=NOW, new_id=lambda: next(ids),
                          templates_root=templates, env={}, source="inferred: test")
    else:
        lanes.regenerate_kit(s, lane_id, version="v2", now=NOW, templates_root=templates, reason="canary")
    os._exit(0)  # the crash point was never reached


def run_child(*args):
    proc = multiprocessing.get_context("fork").Process(target=_child, args=args)
    proc.start()
    proc.join(60)
    if proc.is_alive():
        proc.kill()
        raise AssertionError("child hung")
    return proc.exitcode


class CrashBase(Base):
    def make_v2(self):
        shutil.copytree(self.templates / "v1", self.templates / "v2")
        (self.templates / "v2" / "brief.md").write_text((self.templates / "v2" / "brief.md").read_text() + "\nv2\n")

    def verify(self, lane_id, version="v1"):
        return lanes.verify_lane(self.store, lane_id, templates_root=self.templates, default_version=version)


class CreateCrashTests(CrashBase):
    POINTS = ("create:after_render", "create:after_journal", "create:after_rename", "create:after_claim")

    def test_killed_at_each_boundary_then_retry_gives_one_consistent_lane(self):
        for point in self.POINTS:
            with self.subTest(point=point):
                root = self.base / ("s-" + point.split(":")[1])
                store = st.Store(root)
                code = run_child("create", point, str(root), str(self.templates), str(self.repo), None)
                self.assertEqual(code, 17, "crash point must be reached")
                ids = iter(["lane_retry%d" % len(point)])
                result = lanes.create_lane(store, ticket=TICKET, repo=str(self.repo), profile="generic",
                                           host_alias="mac", branch="b", worktree="/w", session="s", now=NOW,
                                           new_id=lambda: next(ids), templates_root=self.templates, env={},
                                           source="inferred: test")
                index = store.load_index()["lanes"]
                self.assertEqual(len(index), 1, "one lane per key after the retry")
                lane_id = result["lane_id"]
                self.assertEqual(list(index.values()), [lane_id])
                if point in ("create:after_rename", "create:after_claim"):
                    self.assertEqual(lane_id, "lane_crash1", "the committed lane is kept, not duplicated")
                    self.assertFalse(result["created"])
                else:
                    self.assertTrue(result["created"], "an uncommitted creation is redone")
                self.assertEqual([p.name for p in root.iterdir() if p.name.startswith(".tmp")], [])
                lane_dirs = [p.name for p in root.iterdir() if p.name.startswith("lane_")]
                self.assertEqual(lane_dirs, [lane_id])
                self.assertEqual(lanes.verify_lane(store, lane_id, templates_root=self.templates,
                                                   default_version="v1")["problems"], [])

    def test_reconcile_never_touches_a_damaged_lane_or_a_foreign_directory(self):
        self.new()
        damaged = self.store.root / "lane_damaged"
        damaged.mkdir(mode=0o700)
        (damaged / "manifest.r0001.json").write_text("{broken")
        before = sorted(p.name for p in damaged.iterdir())
        lanes.reconcile(self.store)
        self.assertEqual(sorted(p.name for p in damaged.iterdir()), before)
        self.assertEqual(len(self.store.load_index()["lanes"]), 1)

    def test_a_tmp_symlink_is_never_followed_by_cleanup(self):
        self.new()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep")
        (self.store.root / ".tmp-evil").symlink_to(outside)
        lanes.reconcile(self.store)
        self.assertTrue((outside / "keep.txt").exists())


class RegenCrashTests(CrashBase):
    POINTS = ("regen:after_staged", "regen:after_old_moved", "regen:after_swapped", "rev:after_tmp", "rev:after_link",
              "regen:after_manifest")

    def test_killed_at_each_boundary_then_retry_gives_consistent_kit_and_manifest(self):
        for n, point in enumerate(self.POINTS):
            with self.subTest(point=point):
                self.make_v2() if not (self.templates / "v2").exists() else None
                ticket = "GoodQA goodqa#%d" % (800 + n)
                lane = self.new(ticket=ticket)["lane_id"]
                code = run_child("regen", point, str(self.store.root), str(self.templates), str(self.repo), lane)
                self.assertEqual(code, 17)
                if point not in ("regen:after_manifest", "regen:after_staged"):
                    self.assertTrue(self.verify(lane)["problems"],
                                    "interruption must be visible to verify, not silent")
                lanes.regenerate_kit(self.store, lane, version="v2", now=NOW, templates_root=self.templates,
                                     reason="canary")
                report = self.verify(lane, "v2")
                self.assertEqual(report["problems"], [], point)
                cur = mf.read_current(self.store.lane_dir(lane))
                self.assertEqual(cur["kit_version"], "v2")
                self.assertIn("v2", (self.store.lane_dir(lane) / "kit" / "brief.md").read_text())
                names = [p.name for p in self.store.lane_dir(lane).iterdir()]
                self.assertFalse([x for x in names if x.startswith(".kit-") or x.endswith(".tmp")])
                self.assertEqual(mf.verify_chain(self.store.lane_dir(lane)), [])

    def test_prior_kit_is_retained_until_the_manifest_commits(self):
        self.make_v2()
        lane = self.new(ticket="GoodQA goodqa#850")["lane_id"]
        d = self.store.lane_dir(lane)
        before = (d / "kit" / "brief.md").read_bytes()
        code = run_child("regen", "regen:after_swapped", str(self.store.root), str(self.templates), str(self.repo), lane)
        self.assertEqual(code, 17)
        self.assertEqual((d / ".kit-old" / "brief.md").read_bytes(), before)
        self.assertEqual(mf.read_current(d)["kit_version"], "v1")


class UncommittedReplacementTests(CrashBase):
    def test_retry_that_cannot_commit_restores_the_prior_kit(self):
        self.make_v2()
        lane = self.new(ticket="GoodQA goodqa#860")["lane_id"]
        d = self.store.lane_dir(lane)
        before = (d / "kit" / "brief.md").read_bytes()
        self.assertEqual(run_child("regen", "regen:after_swapped", str(self.store.root), str(self.templates),
                                   str(self.repo), lane), 17)
        # the retry fails before it can commit (the template is now missing a file): the prior kit must survive
        os.unlink(self.templates / "v2" / "handoff.md")
        with self.assertRaises((lanes.LaneRefusal, kit.KitError)):
            lanes.regenerate_kit(self.store, lane, version="v2", now=NOW, templates_root=self.templates,
                                 reason="canary")
        self.assertEqual((d / "kit" / "brief.md").read_bytes(), before)
        self.assertEqual(lanes.verify_lane(self.store, lane, templates_root=self.templates,
                                           default_version="v1")["problems"], [])


class RevisionChainTests(CrashBase):
    def setUp(self):
        super().setUp()
        self.make_v2()
        self.lane = self.new()["lane_id"]
        self.d = self.store.lane_dir(self.lane)
        lanes.regenerate_kit(self.store, self.lane, version="v2", now=NOW, templates_root=self.templates,
                             reason="canary")
        lanes.regenerate_kit(self.store, self.lane, version="v1", now=NOW, templates_root=self.templates,
                             reason="rollback")

    def test_intact_chain_is_clean(self):  # positive control
        self.assertEqual(mf.verify_chain(self.d), [])
        self.assertEqual(self.verify(self.lane)["problems"], [])

    def test_editing_a_later_revision_is_reported(self):
        p = self.d / "manifest.r0002.json"
        m = json.loads(p.read_text())
        m["branch"] = "changed"
        p.write_text(json.dumps(m, sort_keys=True) + "\n")
        self.assertTrue(any("r0003" in x or "head" in x for x in mf.verify_chain(self.d)))
        self.assertTrue(self.verify(self.lane)["problems"])

    def test_editing_the_newest_revision_is_reported_by_the_head(self):
        p = self.d / "manifest.r0003.json"
        m = json.loads(p.read_text())
        m["branch"] = "changed"
        p.write_text(json.dumps(m, sort_keys=True) + "\n")
        self.assertTrue(any("head" in x for x in mf.verify_chain(self.d)))

    def test_deleting_the_newest_revision_is_reported(self):
        os.unlink(self.d / "manifest.r0003.json")
        self.assertTrue(any("head" in x for x in mf.verify_chain(self.d)))

    def test_substituting_a_revision_with_an_old_valid_one_is_reported(self):
        shutil.copy(self.d / "manifest.r0001.json", self.d / "manifest.r0002.json")
        problems = mf.verify_chain(self.d)
        self.assertTrue(any("r0002" in x for x in problems), problems)

    def test_head_one_behind_without_the_writers_residue_is_not_adopted(self):  # NEG-89
        (self.d / "manifest.head").write_text(mf._sha((self.d / "manifest.r0002.json").read_bytes()) + "\n")
        self.assertFalse(mf.repair_head(self.d))
        self.assertTrue(mf.verify_chain(self.d))

    def test_head_one_behind_with_the_writers_residue_is_repaired(self):  # crash between link and head
        (self.d / "manifest.head").write_text(mf._sha((self.d / "manifest.r0002.json").read_bytes()) + "\n")
        shutil.copy(self.d / "manifest.r0003.json", self.d / ".manifest.4242.tmp")
        self.assertTrue(mf.repair_head(self.d))
        self.assertEqual(mf.verify_chain(self.d), [])

    def verify(self, lane_id, version="v1"):
        return lanes.verify_lane(self.store, lane_id, templates_root=self.templates, default_version=version)


class KitInputSafetyTests(CrashBase):
    def test_symlinked_kit_root_is_refused_not_followed(self):  # NEG-4
        lane = self.new()["lane_id"]
        d = self.store.lane_dir(lane)
        outside = self.base / "outside-kit"
        shutil.copytree(d / "kit", outside)
        shutil.rmtree(d / "kit")
        (d / "kit").symlink_to(outside)
        report = lanes.verify_lane(self.store, lane, templates_root=self.templates, default_version="v1")
        self.assertTrue(any("symlink" in p for p in report["problems"]), report["problems"])
        with self.assertRaises(lanes.LaneRefusal):
            lanes.regenerate_kit(self.store, lane, version="v1", now=NOW, templates_root=self.templates,
                                 reason="regenerate")

    def test_symlink_fifo_and_oversize_entries_are_reported(self):  # NEG-4
        lane = self.new()["lane_id"]
        k = self.store.lane_dir(lane) / "kit"
        (self.base / "secret.txt").write_text("outside")
        (k / "link.md").symlink_to(self.base / "secret.txt")
        os.mkfifo(k / "pipe.md")
        (k / "big.md").write_bytes(b"x" * (st.MAX_FILE + 1))
        report = lanes.verify_lane(self.store, lane, templates_root=self.templates, default_version="v1")
        text = " ".join(report["problems"])
        self.assertIn("link.md", text)
        self.assertIn("pipe.md", text)
        self.assertIn("big.md", text)

    def test_clean_kit_has_no_safety_problems(self):  # positive control
        lane = self.new()["lane_id"]
        report = lanes.verify_lane(self.store, lane, templates_root=self.templates, default_version="v1")
        self.assertEqual(report["problems"], [])


if __name__ == "__main__":
    unittest.main()
