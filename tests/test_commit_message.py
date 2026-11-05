"""harness/hooks/commit_message.py: field-built messages always validate; refusals are field-level; real refusal shapes replay."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import commit_message as cm  # noqa: E402
import commit_policy as cp  # noqa: E402

POLICY = cp.load_policy()
GOOD = dict(type="fix", scope="deliver", summary="refuse a duplicate full run", why="two owners ran the same suite twice",
            what="reserve one run per head before launching", testing_command="python3 -m unittest tests.test_x",
            testing_result="14 tests OK", ticket="14552")


def build(**over):
    return cm.build_message({**GOOD, **over}, POLICY)


class Build(unittest.TestCase):
    def test_good_fields_build_a_message_that_validates(self):
        r = build()
        self.assertTrue(r["ok"], r["errors"])
        self.assertEqual(cp.validate(r["message"], policy=POLICY), [])
        self.assertIn("Refs: GoodQA #14552", r["message"])
        self.assertIn("Testing: `python3 -m unittest tests.test_x`: 14 tests OK", r["message"])

    def test_safe_normalizations_with_warnings(self):
        r = build(summary="Added a guard.", scope="Deliver", testing="python3 -m unittest: 14 passed", type="FIX",
                  testing_command="", testing_result="")
        self.assertTrue(r["ok"], r["errors"])
        self.assertTrue(r["message"].startswith("fix(deliver): add a guard\n"))
        self.assertTrue(any("imperative" in w for w in r["warnings"]))
        self.assertTrue(any("backticks" in w for w in r["warnings"]))
        trailers = build(trailers=["Co-Authored-By: A <a@b.c>"])["message"]
        self.assertTrue(trailers.rstrip().endswith("Co-Authored-By: A <a@b.c>") and "\n\nCo-Authored-By" in trailers)

    def test_unfixable_problems_are_field_level_with_a_fix(self):
        cases = {"subject": dict(summary="x" * 80), "Why": dict(why=""), "What": dict(what="short"),
                 "Testing": dict(testing_command="", testing_result="", testing="tests pass"),
                 "Refs": dict(ticket="", refs=""), }
        for field, over in cases.items():
            r = build(**over)
            self.assertFalse(r["ok"], field)
            self.assertIsNone(r["message"])
            self.assertIn(field, {e["field"] for e in r["errors"]}, (field, r["errors"]))
            self.assertTrue(all(e["fix"] for e in r["errors"]))
        over = build(summary="x" * 80)["errors"][0]
        self.assertIn("shorten the summary by at least", over["fix"])

    def test_chore_and_docs_may_use_none_but_fix_may_not(self):
        self.assertTrue(build(type="chore", ticket="", refs="none (version bump only)")["ok"])
        self.assertFalse(build(type="fix", ticket="", refs="none (version bump only)")["ok"])

    def test_not_run_testing_and_identical_previous(self):
        self.assertTrue(build(testing_command="", testing_result="", testing="not run: docs only, no behaviour")["ok"])
        first = build()["message"]
        self.assertFalse(cm.build_message({**GOOD}, POLICY, previous=first)["ok"])

    def test_never_returns_a_message_validate_rejects(self):
        import itertools
        for kind, summary, why, testing in itertools.product(("fix", "wip", "feat"), ("add x", "x" * 90, "fixed things", ""),
                                                             ("", "because the thing was broken"), ("", "tests pass", "`make`: ok")):
            r = build(type=kind, summary=summary, why=why, testing_command="", testing_result="", testing=testing)
            if r["ok"]:
                self.assertEqual(cp.validate(r["message"], policy=POLICY), [], r["message"])
            else:
                self.assertIsNone(r["message"])


class Replay(unittest.TestCase):
    """The masked shapes of 138 real refused commit messages (lengths and forms only): synthesize fields of the same
    sizes; the builder either returns a valid message or names the field the policy flagged."""

    SHAPES = json.loads((ROOT / "tests" / "fixtures" / "commit_refusal_shapes.json").read_text())

    def fields(self, s):
        sec = s["sections"]
        text = lambda n, w: (" ".join(["word"] * (n // 5 + 1)))[:max(n, 0)] if n else ""  # noqa: E731
        prefix = len(s["type"] or "fix") + (len("(area)") if s["has_scope"] else 0) + 2
        summary = ("refuse " + "x" * 80)[:max(s["subject_len"] - prefix, 8)]
        fields = dict(type=s["type"] or "fix", scope="area" if s["has_scope"] else "",
                      summary=summary, why=text(sec.get("Why") or 0, "w"),
                      what=text(sec.get("What") or 0, "w"), ticket="14552")
        if s["testing_not_run"]:
            fields["testing"] = "not run: documentation only change"
        elif sec.get("Testing"):
            fields.update(testing_command="python3 -m unittest", testing_result="3 tests OK")
        if s["has_trailer"]:
            fields["trailers"] = ["Co-Authored-By: Someone <s@example.com>"]
        return fields

    def test_every_real_shape_builds_valid_or_names_the_field(self):
        self.assertGreater(len(self.SHAPES), 100)
        ok = refused = 0
        for s in self.SHAPES:
            r = cm.build_message(self.fields(s), POLICY)
            if r["ok"]:
                ok += 1
                self.assertEqual(cp.validate(r["message"], policy=POLICY), [])
            else:
                refused += 1
                self.assertTrue(r["errors"] and all(e["field"] in cm.FIELD_FIX for e in r["errors"]))
        self.assertGreater(ok, 40)  # most real refusals become valid once built from fields
        self.assertGreater(refused, 10)  # and the unbuildable ones (empty prose, over-long subject) are refused, not emitted

    def test_the_largest_real_cause_is_caught_before_git(self):
        long_ones = [s for s in self.SHAPES if s["subject_len"] > 72 and s["subject_parses"]]
        self.assertGreater(len(long_ones), 10)
        for s in long_ones:
            r = cm.build_message(self.fields(s), POLICY)
            self.assertFalse(r["ok"])
            self.assertEqual(r["errors"][0]["field"], "subject")
            self.assertIn("shorten", r["errors"][0]["fix"])


class Pr(unittest.TestCase):
    def test_pr_title_and_body(self):
        r = cm.build_pr({**GOOD, "title": "feat(test-scope): add baselines and one full run per head"}, POLICY)
        self.assertTrue(r["ok"], r["errors"])
        self.assertLessEqual(len(r["title"]), 64)
        self.assertTrue(r["body"].startswith("Why:"))
        bad = cm.build_pr({**GOOD, "title": "feat(test-scope): " + "x" * 60}, POLICY)
        self.assertFalse(bad["ok"])
        self.assertFalse(cm.build_pr({**GOOD, "title": "feat(a): add b", "why": ""}, POLICY)["ok"])


class Ready(unittest.TestCase):
    def test_structure_only_and_no_secrets(self):
        msg = "fix(deliver): added token sk-live-SECRET123 to the thing\n\nWhy: password=hunter2\n"
        out = cm.ready_message(["subject: x"], msg, {"scope": "deliver", "ticket": "GoodQA #14552"}, POLICY)
        self.assertNotIn("SECRET", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("token", out)
        self.assertIn("--type fix --scope deliver", out)
        self.assertIn("GoodQA #14552", out)
        out2 = cm.ready_message([], "wip stuff", {"ticket": "x; rm -rf /"}, POLICY)
        self.assertNotIn(";", out2.split("--ticket")[1])
        self.assertIn("--type fix", out2)


class Cli(unittest.TestCase):
    def run_cli(self, *args, env=None):
        r = subprocess.run([sys.executable, str(HOOKS / "commit_message.py"), *args], capture_output=True, text=True,
                           env={**os.environ, **(env or {})}, timeout=60)
        return r.returncode, json.loads(r.stdout)

    ARGS = ["build", "--type", "fix", "--scope", "deliver", "--summary", "refuse a duplicate run", "--why",
            "two owners ran one suite twice", "--what", "reserve one run per head", "--testing-command", "make test",
            "--testing-result", "9 OK", "--ticket", "14552"]

    def test_exit_codes_and_no_write_on_refusal(self):
        code, data = self.run_cli(*self.ARGS)
        self.assertEqual((code, data["ok"]), (0, True))
        code, data = self.run_cli(*self.ARGS[:-1], "")
        self.assertEqual((code, data["ok"]), (2, False))
        self.assertEqual(data["errors"][0]["field"], "Refs")

    def test_commit_writes_a_0600_file_under_the_work_dir_and_commits(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "f").write_text("x")
            subprocess.run(["git", "-C", str(repo), "add", "f"], check=True)
            work = Path(d) / "work"
            env = {"HARNESS_WORK_DIR": str(work), "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
            code, data = self.run_cli(*self.ARGS, "--commit", "--repo", str(repo), env=env)
            self.assertEqual((code, data["commit_exit"]), (0, 0), data)
            self.assertEqual(oct(Path(data["message_file"]).stat().st_mode & 0o777), "0o600")
            self.assertEqual(Path(data["message_file"]).parent, work)
            subject = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%s"], capture_output=True, text=True).stdout.strip()
            self.assertEqual(subject, "fix(deliver): refuse a duplicate run")

    def test_check_command_and_internal_errors(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "m.txt"
            f.write_text("wip\n")
            code, data = self.run_cli("check", "--file", str(f))
            self.assertEqual((code, data["ok"]), (2, False))
            code, data = self.run_cli("check", "--file", str(Path(d) / "missing"))
            self.assertEqual(code, 4)


if __name__ == "__main__":
    unittest.main()
