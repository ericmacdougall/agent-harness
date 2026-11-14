"""S1 (GoodQA goodqa#15946): manifest, kit renderer and lint, lane creation, kit_version canary and rollback.

Covers AC-1, AC-3 (library level), AC-4, AC-5 (subset), AC-10, AC-43, NEG-1, NEG-2, NEG-5, NEG-8, NEG-56, NEG-80.
Bounded probes: at most 4 short git subprocesses, one temp directory, no network, 60 s timeout.
Fails on main c82ad2af: modules `lane.manifest`, `lane.kit`, `lane.lanes` do not exist.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
from lane import kit, lanes, manifest as mf, store as st  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
NOW = "2026-11-13T00:00:00Z"
TICKET = "GoodQA goodqa#15946"
SHIPPED = HOOKS / "lane" / "templates"


def git(cwd, *args):
    subprocess.run(GIT + list(args), cwd=cwd, check=True, capture_output=True, timeout=60)


def tree_hash(path):
    h = hashlib.sha256()
    for p in sorted(Path(path).rglob("*")):
        h.update(str(p.relative_to(path)).encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(os.path.realpath(self.tmp.name))
        self.templates = self.base / "templates"
        shutil.copytree(SHIPPED, self.templates)
        self.store = st.Store(self.base / "lanes")
        self.repo = self.base / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "i")
        git(self.repo, "remote", "add", "origin", "https://github.com/owner/repo.git")
        self.ids = iter("lane_%02d" % i for i in range(1, 50))

    def tearDown(self):
        self.tmp.cleanup()

    def new(self, ticket=TICKET, repo=None, env=None, **kw):
        return lanes.create_lane(self.store, ticket=ticket, repo=str(repo or self.repo), profile="python-hooks",
                                 host_alias="mac", branch="lane/x", worktree="/work/x", session="sess",
                                 now=NOW, new_id=lambda: next(self.ids), templates_root=self.templates,
                                 env=env or {}, source="inferred: test", **kw)


class ManifestTests(Base):
    def good(self):
        return mf.new_manifest(lane_id="lane_01", key="GoodQA goodqa#15946|github.com/o/r", ticket=TICKET, repo_identity="github.com/o/r",
                               repo_kind="remote", host_alias="mac", branch="b", worktree="/w", profile="generic",
                               domains=["auth"], session="s", stream_key="stream-aaaaaaaaaaaa", kit_version="v1",
                               kit_digests={"a.md": "0" * 64}, template_digest="1" * 64, policy_digests={},
                               created_at=NOW)

    def test_valid_manifest_passes(self):
        mf.validate(self.good())

    def test_free_text_field_is_rejected(self):  # AC-4
        for field, value in (("branch", "two words with spaces"), ("worktree", "line\nbreak"),
                             ("ticket", "GoodQA goodqa#1 plus a sentence of free text")):
            m = self.good()
            m[field] = value
            with self.subTest(field=field):
                with self.assertRaises(mf.ManifestError):
                    mf.validate(m)

    def test_unknown_field_or_higher_schema_parks_the_lane(self):  # NEG-5
        m = self.good()
        m["surprise"] = "x"
        with self.assertRaises(mf.NewerSchema):
            mf.validate(m)
        m = self.good()
        m["schema"] = "lane.manifest/2"
        with self.assertRaises(mf.NewerSchema):
            mf.validate(m)

    def test_enumerations_are_closed(self):
        m = self.good()
        m["profile"] = "anything"
        with self.assertRaises(mf.ManifestError):
            mf.validate(m)
        m = self.good()
        m["domains"] = ["not-a-domain"]
        with self.assertRaises(mf.ManifestError):
            mf.validate(m)

    def test_revisions_are_numbered_and_never_overwritten(self):
        d = self.base / "d"
        d.mkdir()
        mf.write_revision(d, self.good())
        second = self.good()
        second["kit_version"] = "v2"
        n = mf.write_revision(d, second)
        self.assertEqual(n, 2)
        self.assertEqual(mf.read_current(d)["kit_version"], "v2")
        self.assertEqual(json.loads((d / "manifest.r0001.json").read_text())["kit_version"], "v1")
        with self.assertRaises(FileExistsError):
            mf.write_revision(d, second, number=1)


class KitTests(Base):
    INPUTS = dict(lane_id="lane_01", ticket=TICKET, stream_key="stream-aaaaaaaaaaaa", branch="b",
                  kit_version="v1", repo_identity="github.com/o/r")

    def test_render_twice_is_byte_identical(self):  # AC-1
        a, b = self.base / "a", self.base / "b"
        da = kit.render("v1", self.INPUTS, a, self.templates)
        db = kit.render("v1", self.INPUTS, b, self.templates)
        self.assertEqual(da, db)
        self.assertEqual(tree_hash(a), tree_hash(b))
        self.assertIn("lane_01", (a / "brief.md").read_text())

    def test_unfilled_placeholder_is_refused_and_writes_nothing(self):  # NEG-2
        (self.templates / "v1" / "extra.md").write_text("hello {{nobody_fills_this}}\n")
        out = self.base / "o"
        with self.assertRaises(kit.KitError):
            kit.render("v1", self.INPUTS, out, self.templates)
        self.assertFalse(out.exists())

    def test_missing_template_dir_is_refused(self):  # AC-1
        with self.assertRaises(kit.KitError):
            kit.render("v9", self.INPUTS, self.base / "o", self.templates)

    def test_input_value_with_placeholder_syntax_cannot_inject(self):
        inputs = dict(self.INPUTS, branch="{{ticket}}")
        with self.assertRaises(kit.KitError):
            kit.render("v1", inputs, self.base / "o", self.templates)

    def lint_with(self, name, text):
        (self.templates / "v1" / name).write_text(text)
        return kit.lint_version("v1", self.templates)

    def test_shipped_v1_passes_lint(self):  # positive control for every refusal below
        self.assertEqual(kit.lint_version("v1", self.templates), [])

    def test_lint_refuses_each_case(self):  # AC-5 subset, NEG-8
        cases = {
            "password.md": "Type the password into the login form.\n",
            "model.md": "Spawn this owner with model fable for speed.\n",
            "poll.md": "while true; do check; sleep 30; done\n",
            "host.md": "ssh to 10.1.2.3 and run it\n",
            "host2.md": "see build-box.internal for logs\n",
            "accept.md": "Verdict: ACCEPT\nSign-off: main approved\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                problems = self.lint_with(name, text)
                self.assertTrue(problems, name)
                os.unlink(self.templates / "v1" / name)
        self.assertEqual(kit.lint_version("v1", self.templates), [])

    def test_kit_version_dropping_a_gate_is_refused(self):  # NEG-56
        shutil.copytree(self.templates / "v1", self.templates / "v2")
        gates = json.loads((self.templates / "v2" / "gates.json").read_text())
        gates["gates"] = [g for g in gates["gates"] if g != "G2"]
        (self.templates / "v2" / "gates.json").write_text(json.dumps(gates))
        problems = kit.lint_version("v2", self.templates)
        self.assertTrue(any("G2" in p for p in problems))
        self.assertEqual(kit.lint_version("v1", self.templates), [])

    def test_select_version_override_applies_to_one_ticket_only(self):  # AC-43
        pol = {"default": "v1"}
        env = {"LANE_KIT_VERSION": "GoodQA goodqa#15946=v2"}
        self.assertEqual(kit.select_version(TICKET, pol, env), ("v2", True))
        self.assertEqual(kit.select_version("GoodQA goodqa#7", pol, env), ("v1", False))
        self.assertEqual(kit.select_version(TICKET, pol, {}), ("v1", False))
        with self.assertRaises(kit.KitError):
            kit.select_version(TICKET, pol, {"LANE_KIT_VERSION": "garbage"})


class CreateLaneTests(Base):
    def test_create_writes_manifest_journal_index_and_kit(self):  # AC-1
        result = self.new()
        d = self.store.lane_dir(result["lane_id"])
        self.assertTrue(result["created"])
        self.assertTrue((d / "manifest.r0001.json").exists())
        self.assertTrue((d / "kit" / "brief.md").exists())
        self.assertEqual(self.store.verify_journal(d), (True, None, None))
        rows = [json.loads(x) for x in (d / "journal.jsonl").read_text().splitlines()]
        self.assertEqual([r["kind"] for r in rows], ["created"])
        self.assertEqual(self.store.load_index()["lanes"][mf.read_current(d)["key"]], result["lane_id"])
        self.assertEqual([p.name for p in self.store.root.iterdir() if p.name.startswith(".tmp")], [])

    def test_same_ticket_and_repo_returns_the_existing_lane(self):  # AC-2
        a = self.new()
        clone = self.base / "clone"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(clone)], check=True, capture_output=True, timeout=60)
        git(clone, "remote", "set-url", "origin", "git@github.com:Owner/Repo.git")
        b = self.new(repo=clone)
        self.assertFalse(b["created"])
        self.assertEqual(a["lane_id"], b["lane_id"])
        self.assertEqual(len(self.store.load_index()["lanes"]), 1)

    def test_missing_template_leaves_no_directory_and_no_index_entry(self):  # AC-1
        os.unlink(self.templates / "v1" / "brief.md")
        before = sorted(p.name for p in self.store.root.iterdir()) if self.store.root.exists() else []
        with self.assertRaises((kit.KitError, lanes.LaneRefusal)):
            self.new()
        after = sorted(p.name for p in self.store.root.iterdir()) if self.store.root.exists() else []
        self.assertEqual(before, [x for x in after if x not in ("store.lock",)])
        self.assertEqual(self.store.load_index()["lanes"], {})

    def test_restoring_the_template_passes(self):  # positive control
        shutil.copy(SHIPPED / "v1" / "brief.md", self.templates / "v1" / "brief.md")
        self.assertTrue(self.new()["created"])

    def test_malformed_ticket_and_non_git_are_refused_with_nothing_written(self):  # NEG-1
        for kwargs in (dict(ticket="GoodQA #1"), dict(repo=self.base)):
            with self.subTest(kw=str(kwargs)[:30]):
                with self.assertRaises(lanes.LaneRefusal):
                    self.new(**kwargs)
        self.assertFalse(self.store.root.exists())

    def test_dry_run_changes_nothing_not_even_the_root(self):  # AC-3
        plan = self.new(dry_run=True)
        self.assertFalse(plan["created"])
        self.assertIn("lane_id", plan)
        self.assertFalse(self.store.root.exists())
        real = self.new()
        before = tree_hash(self.store.root)
        again = self.new(dry_run=True)
        self.assertEqual(again["lane_id"], real["lane_id"])
        self.assertEqual(tree_hash(self.store.root), before)

    def test_held_targets_are_refused_with_the_rule_and_nothing_written(self):  # AC-10, NEG-80
        held = self.base / "yates-cloud"
        held.mkdir()
        git(held, "init", "-q")
        git(held, "commit", "-q", "--allow-empty", "-m", "i")
        for kwargs in (dict(repo=held), dict(ticket="GoodQA yates-cloud#5"), dict(ticket="GoodQA optinrouter#5")):
            with self.subTest(kw=str(kwargs)[-40:]):
                with self.assertRaises(lanes.HeldTarget) as caught:
                    self.new(**kwargs)
                self.assertIn(caught.exception.rule, ("yates", "optinrouter"))
        self.assertFalse(self.store.root.exists())


class CanaryTests(Base):
    def make_v2(self):
        shutil.copytree(self.templates / "v1", self.templates / "v2")
        (self.templates / "v2" / "brief.md").write_text(
            (self.templates / "v2" / "brief.md").read_text() + "\nKit v2 note.\n")

    def test_canary_on_one_lane_rollback_is_byte_identical_and_others_untouched(self):  # AC-43
        self.make_v2()
        older = self.new(ticket="GoodQA goodqa#100")
        older_dir = self.store.lane_dir(older["lane_id"])
        older_hash = tree_hash(older_dir)
        canary = self.new(ticket="GoodQA goodqa#200", env={"LANE_KIT_VERSION": "GoodQA goodqa#200=v2"})
        other = self.new(ticket="GoodQA goodqa#300")
        cd = self.store.lane_dir(canary["lane_id"])
        self.assertEqual(mf.read_current(cd)["kit_version"], "v2")
        self.assertEqual(mf.read_current(self.store.lane_dir(other["lane_id"]))["kit_version"], "v1")
        rows = [json.loads(x) for x in (cd / "journal.jsonl").read_text().splitlines()]
        self.assertEqual(rows[0]["data"]["kit_override"], True)
        lanes.regenerate_kit(self.store, canary["lane_id"], version="v1", now=NOW, templates_root=self.templates,
                             reason="rollback")
        self.assertEqual(mf.read_current(cd)["kit_version"], "v1")
        self.assertEqual((cd / "kit" / "gates.json").read_bytes(),
                         (self.store.lane_dir(other["lane_id"]) / "kit" / "gates.json").read_bytes())
        self.assertNotIn("Kit v2 note", (cd / "kit" / "brief.md").read_text())
        self.assertEqual(tree_hash(older_dir), older_hash)

    def test_rollback_regenerates_exactly_the_pre_canary_digests(self):  # AC-43 exact
        self.make_v2()
        first = self.new(ticket="GoodQA goodqa#500")
        d = self.store.lane_dir(first["lane_id"])
        pre = dict(mf.read_current(d)["kit_digests"])
        lanes.regenerate_kit(self.store, first["lane_id"], version="v2", now=NOW, templates_root=self.templates,
                             reason="canary")
        self.assertNotEqual(mf.read_current(d)["kit_digests"], pre)
        lanes.regenerate_kit(self.store, first["lane_id"], version="v1", now=NOW, templates_root=self.templates,
                             reason="rollback")
        self.assertEqual(mf.read_current(d)["kit_digests"], pre)
        self.assertEqual(mf.read_current(d)["revision"], 3)
        self.assertEqual(self.store.verify_journal(d)[0], True)

    def test_rollback_is_not_blocked_when_the_newer_version_fails_lint(self):  # NEG-56 rollback-not-blocked
        self.make_v2()
        first = self.new(ticket="GoodQA goodqa#600")
        lanes.regenerate_kit(self.store, first["lane_id"], version="v2", now=NOW, templates_root=self.templates,
                             reason="canary")
        (self.templates / "v2" / "bad.md").write_text("type the password\n")
        with self.assertRaises(lanes.LaneRefusal):  # canary of the bad version is refused
            lanes.regenerate_kit(self.store, first["lane_id"], version="v2", now=NOW, templates_root=self.templates,
                                 reason="canary")
        lanes.regenerate_kit(self.store, first["lane_id"], version="v1", now=NOW, templates_root=self.templates,
                             reason="rollback")
        self.assertEqual(mf.read_current(self.store.lane_dir(first["lane_id"]))["kit_version"], "v1")

    def test_new_lane_with_a_lint_failing_version_is_refused(self):
        self.make_v2()
        (self.templates / "v2" / "bad.md").write_text("type the password\n")
        with self.assertRaises(lanes.LaneRefusal):
            self.new(ticket="GoodQA goodqa#700", env={"LANE_KIT_VERSION": "GoodQA goodqa#700=v2"})
        self.assertEqual(self.store.load_index()["lanes"], {})


class VerifyTests(Base):
    def test_clean_lane_verifies_and_verify_writes_nothing(self):
        r = self.new()
        before = tree_hash(self.store.root)
        report = lanes.verify_lane(self.store, r["lane_id"], templates_root=self.templates, default_version="v1")
        self.assertEqual(report["problems"], [])
        self.assertEqual(tree_hash(self.store.root), before)

    def test_edits_are_reported_as_drift(self):  # AC-4
        r = self.new()
        d = self.store.lane_dir(r["lane_id"])
        (d / "kit" / "brief.md").write_text("tampered\n")
        report = lanes.verify_lane(self.store, r["lane_id"], templates_root=self.templates, default_version="v1")
        self.assertTrue(any("brief.md" in p for p in report["problems"]))

    def test_in_place_manifest_edit_is_reported(self):  # AC-4
        r = self.new()
        d = self.store.lane_dir(r["lane_id"])
        p = d / "manifest.r0001.json"
        m = json.loads(p.read_text())
        m["branch"] = "other"
        p.write_text(json.dumps(m, sort_keys=True))
        report = lanes.verify_lane(self.store, r["lane_id"], templates_root=self.templates, default_version="v1")
        self.assertTrue(any("manifest" in x for x in report["problems"]))

    def test_older_lane_gets_a_diff_and_nothing_changes(self):  # AC-43
        shutil.copytree(self.templates / "v1", self.templates / "v2")
        (self.templates / "v2" / "brief.md").write_text(
            (self.templates / "v2" / "brief.md").read_text() + "\nKit v2 note.\n")
        r = self.new()
        before = tree_hash(self.store.root)
        report = lanes.verify_lane(self.store, r["lane_id"], templates_root=self.templates, default_version="v2")
        self.assertEqual(report["problems"], [])
        self.assertTrue(any("Kit v2 note" in line for line in report["drift_diff"]))
        self.assertEqual(tree_hash(self.store.root), before)

    def test_changed_policy_file_is_reported(self):
        r = self.new(policy_files={"spec_policy.json": b"one"})
        report = lanes.verify_lane(self.store, r["lane_id"], templates_root=self.templates, default_version="v1",
                                   policy_files={"spec_policy.json": b"two"})
        self.assertTrue(any("spec_policy.json" in p for p in report["problems"]))

    def test_newer_schema_lane_is_parked_not_guessed(self):  # NEG-5
        r = self.new()
        d = self.store.lane_dir(r["lane_id"])
        p = d / "manifest.r0001.json"
        m = json.loads(p.read_text())
        m["schema"] = "lane.manifest/9"
        p.write_text(json.dumps(m, sort_keys=True))
        report = lanes.verify_lane(self.store, r["lane_id"], templates_root=self.templates, default_version="v1")
        self.assertEqual(report["state"], "newer schema, unreadable")


if __name__ == "__main__":
    unittest.main()
