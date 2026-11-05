"""harness/hooks/commit_message.py: field-built messages always validate; refusals are field-level; real refusal shapes replay."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
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
        over = [e for e in build(summary="refuse " + "x" * 80)["errors"] if "chars, limit" in e["problem"]][0]
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
                      what=text(sec.get("What") or 0, "w"))
        if s["refs_form"] and s["refs_form"].startswith("none"):
            fields["refs"] = "none (documentation-only change, no ticket)"
        else:
            fields["ticket"] = "14552"
        if s["testing_not_run"]:
            fields["testing"] = "not run: documentation only change"
        elif sec.get("Testing") and s["testing_has_backticks"]:
            fields.update(testing_command="python3 -m unittest", testing_result="3 tests OK")
        elif sec.get("Testing"):
            fields["testing"] = "python3 -m unittest: 3 tests OK"  # the bare form the builder wraps
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
        # 62 ok / 76 refused at the time of writing; the refused ones are empty prose, over-long or unparseable subjects.
        # The fixture is generated by tests/fixtures/extract_refusals.py (counts and masked shapes only).
        self.assertGreaterEqual(ok, 50)
        self.assertGreaterEqual(refused, 60)
        self.assertEqual(ok + refused, len(self.SHAPES))

    def test_the_largest_real_cause_is_caught_before_git(self):
        long_ones = [s for s in self.SHAPES if s["subject_len"] > 72 and s["subject_parses"]]
        self.assertGreater(len(long_ones), 10)
        for s in long_ones:
            r = cm.build_message(self.fields(s), POLICY)
            self.assertFalse(r["ok"])
            long_error = [e for e in r["errors"] if "chars, limit" in e["problem"]]
            self.assertTrue(long_error, r["errors"])
            self.assertEqual(long_error[0]["field"], "subject")
            self.assertIn("shorten", long_error[0]["fix"])


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
            env = {"HARNESS_WORK_DIR": str(work), "HARNESS_ALLOW_TMP_WORK": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
            code, data = self.run_cli(*self.ARGS, "--commit", "--repo", str(repo), env=env)
            self.assertEqual((code, data["commit_exit"]), (0, 0), data)
            self.assertFalse(list(work.iterdir()), "the message file is removed after the commit")
            self.assertEqual(oct(work.stat().st_mode & 0o777), "0o700")
            subject = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%s"], capture_output=True, text=True).stdout.strip()
            self.assertEqual(subject, "fix(deliver): refuse a duplicate run")

    def test_check_command_and_internal_errors(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "m.txt"
            f.write_text("wip\n")
            code, data = self.run_cli("check", "--file", str(f))
            self.assertEqual((code, data["ok"]), (2, False))
            code, data = self.run_cli("check", "--file", str(Path(d) / "missing"))
            self.assertEqual((code, data["errors"][0]["field"]), (2, "input"))


NEG_TESTING = ["tests: pass", "tested locally: ok", "manually checked everything: ok", "nothing: ok", "I eyeballed it - looks ok",
               "all tests pass"]


class SecondReview(unittest.TestCase):
    """Findings of the independent review of e42d903."""

    def test_prose_is_never_laundered_into_a_command(self):  # F1
        for text in NEG_TESTING:
            r = build(testing_command="", testing_result="", testing=text)
            self.assertFalse(r["ok"], text)
            self.assertEqual(r["errors"][0]["field"], "Testing", text)

    def test_real_evidence_is_not_mangled(self):  # F1
        for text, expect in (("curl http://localhost:8080/health: 200 ok", "`curl http://localhost:8080/health`: 200 ok"),
                             ("pytest tests/a.py::test_b passed", None), ("python3 -m unittest -> 14 passed", "`python3 -m unittest`: 14 passed")):
            r = build(testing_command="", testing_result="", testing=text)
            if expect:
                self.assertIn("Testing: " + expect, r["message"], text)
            if r["ok"]:
                self.assertNotIn("`pytest tests/a.py`", r["message"])
        quoted = build(testing_command="", testing_result="", testing="pytest -k 'a: b' passed")
        if quoted["ok"]:
            self.assertNotIn("`pytest -k 'a`", quoted["message"])

    def test_command_and_result_must_both_be_given(self):  # F8
        for over in (dict(testing_command="make clean", testing_result=""), dict(testing_command="", testing_result="python3 x passed")):
            r = build(**over)
            self.assertFalse(r["ok"], over)
            self.assertEqual(r["errors"][0]["field"], "Testing")

    def test_unfilled_placeholders_are_refused(self):  # F8
        for over in (dict(summary="<imperative summary>"), dict(why="<problem or motivation>"),
                     dict(testing_command="<exact command>", testing_result="3 passed")):
            r = build(**over)
            self.assertFalse(r["ok"], over)
            self.assertIn("placeholder", r["errors"][0]["problem"])

    def test_control_and_invisible_characters_are_refused(self):  # F9
        for bad in ("\u200b" * 12, "\x01" * 12, "ok\u202etext here", "esc\x1b[31m text here"):
            r = build(why="because " + bad, what="reserve one run per head")
            self.assertFalse(r["ok"], repr(bad))
            self.assertEqual(r["errors"][0]["field"], "Why")
        self.assertFalse(build(summary="add\u200b")["ok"])

    def test_newlines_cannot_forge_sections(self):  # F7 defence is tested
        r = build(why="real reason here\nTesting: `make`: 9 OK\nRefs: GoodQA #1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["message"].count("\nTesting:"), 1)
        self.assertEqual(r["message"].count("\nRefs:"), 1)
        self.assertEqual(len(r["message"].split("\n\n")), 2)

    def test_trailers_are_validated(self):  # F10
        for bad in ("Co-Authored-By: A <a@b.c>", 5, ["free text here"], ["fix(a): second subject"], ["# hidden"], ["GoodQA #9"]):
            r = build(trailers=bad)
            self.assertFalse(r["ok"], bad)
            self.assertEqual(r["errors"][0]["field"], "trailers")
        self.assertTrue(build(trailers=["Co-Authored-By: A <a@b.c>", "Signed-off-by: B <b@c.d>"])["ok"])

    def test_ticket_forms(self):  # F14
        for good, ref in (("14552", "GoodQA #14552"), ("#14552", "GoodQA #14552"), ("GoodQA #12", "GoodQA #12"),
                          ("goodqa#12", "GoodQA goodqa#12"), ("GoodQA goodqa#12", "GoodQA goodqa#12")):
            self.assertIn("Refs: " + ref + "\n", build(ticket=good)["message"], good)
        for bad in ("12, 13", "GoodQA #12 password=hunter2", "not GoodQA #12", "1\u0662\u0663", "x" * 50):
            r = build(ticket=bad)
            self.assertFalse(r["ok"], bad)
            self.assertEqual(r["errors"][0]["field"], "Refs")

    def test_refs_override_warns_and_revert_has_fields(self):  # F11 F12
        r = build(refs="GoodQA #99", ticket="12")
        self.assertTrue(any("overrides" in w for w in r["warnings"]))
        rv = build(type="revert", summary="undo the duplicate run guard", reason="the guard blocked all deliveries",
                   authorized_by="Eric, GoodQA #14552")
        self.assertTrue(rv["ok"], rv["errors"])
        self.assertIn("Reason: the guard blocked", rv["message"])
        self.assertFalse(build(type="revert", summary="undo the duplicate run guard")["ok"])
        pr = cm.build_pr({**GOOD, "title": "fix(a): add b", "risk": "migrates the store layout"}, POLICY)
        self.assertIn("Risk: migrates the store layout", pr["body"])

    def test_ready_message_copies_nothing_from_the_message(self):  # F5
        for subject in ("fix(sk-live-abc123secret): x y z", "fix(hunter2.password): x y z", "feat(a): token=abc xyz"):
            out = cm.ready_message([], subject + "\n\nWhy: password=hunter2\n", {"scope": "deliver", "ticket": "GoodQA #14552"}, POLICY)
            for leaked in ("sk-live", "hunter2", "abc123", "token="):
                self.assertNotIn(leaked, out)
            self.assertIn("--scope deliver", out)
        for task in ({"scope": "-rf", "ticket": "password hunter2"}, {"scope": "a b", "ticket": "12; rm -rf /"},
                     {"scope": "", "ticket": "GoodQA #9 hunter2"}):
            out = cm.ready_message([], "wip", task, POLICY)
            self.assertNotIn("hunter2", out)
            self.assertNotIn("rm -rf", out)
            self.assertNotIn("-rf", out)
            self.assertIn("'<scope>'", out)
            self.assertIn("'<ticket number>'", out)
        self.assertIn(shlex_quote_check(), cm.ready_message([], "", {}, POLICY))


def shlex_quote_check():
    import shlex
    return shlex.quote(str(HOOKS / "commit_message.py"))


class Commit(unittest.TestCase):
    """--commit applies the hook's rules itself and never reports a failed commit as ok."""

    def repo(self, d, origin=None):
        repo = Path(d) / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        if origin:
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", origin], check=True)
        return repo

    def run_cli(self, *args, work, extra=None):
        env = {**os.environ, "HARNESS_WORK_DIR": str(work), "HARNESS_ALLOW_TMP_WORK": "1", "GIT_AUTHOR_NAME": "t",
               "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", **(extra or {})}
        r = subprocess.run([sys.executable, str(HOOKS / "commit_message.py"), *args], capture_output=True, text=True, env=env, timeout=60)
        return r.returncode, json.loads(r.stdout)

    ARGS = Cli.ARGS

    def test_git_failure_is_an_error_not_ok_and_leaves_no_file(self):  # F2
        with tempfile.TemporaryDirectory() as d:
            repo, work = self.repo(d), Path(d) / "work"
            code, data = self.run_cli(*self.ARGS, "--commit", "--repo", str(repo), work=work)  # nothing staged
            self.assertEqual(code, 2)
            self.assertFalse(data["ok"])
            self.assertIsNone(data["message"])
            self.assertEqual(data["errors"][0]["field"], "git")
            self.assertIn("nothing", data["errors"][0]["problem"].lower())
            self.assertFalse(list(work.iterdir()))

    def test_not_a_repo_and_a_rejecting_hook(self):  # F2
        with tempfile.TemporaryDirectory() as d:
            code, data = self.run_cli(*self.ARGS, "--commit", "--repo", str(Path(d) / "nope"), work=Path(d) / "w")
            self.assertEqual((code, data["errors"][0]["field"]), (2, "git"))
            repo, work = self.repo(d), Path(d) / "work"
            (repo / "f").write_text("x")
            subprocess.run(["git", "-C", str(repo), "add", "f"], check=True)
            hook = repo / ".git" / "hooks" / "commit-msg"
            hook.write_text("#!/bin/sh\necho 'hook says: no ticket id in the body' >&2\nexit 1\n")
            hook.chmod(0o755)
            code, data = self.run_cli(*self.ARGS, "--commit", "--repo", str(repo), work=work)
            self.assertEqual(code, 2)
            self.assertIn("hook says: no ticket id", data["errors"][0]["problem"])
            self.assertFalse(list(work.iterdir()))

    def test_the_ticket_rule_follows_the_repo_origin_like_the_hook(self):  # F3
        with tempfile.TemporaryDirectory() as d:
            repo, work = self.repo(d, "https://github.com/ericmacdougall/agent-harness.git"), Path(d) / "work"
            (repo / "f").write_text("x")
            subprocess.run(["git", "-C", str(repo), "add", "f"], check=True)
            skip = ["build", "--type", "fix", "--scope", "deliver", "--summary", "refuse a duplicate run", "--why",
                    "two owners ran one suite twice", "--what", "reserve one run per head", "--testing-command", "make test",
                    "--testing-result", "9 OK", "--refs", "none (skip the ticket gate)", "--no-tickets", "--commit", "--repo", str(repo)]
            code, data = self.run_cli(*skip, work=work)
            self.assertEqual(code, 2, data)
            self.assertEqual(data["errors"][0]["field"], "Refs")
            self.assertEqual(subprocess.run(["git", "-C", str(repo), "rev-list", "--count", "--all"], capture_output=True, text=True).stdout.strip(), "0")

    def test_untracked_repo_does_not_demand_a_ticket_and_duplicates_are_refused(self):  # F3
        with tempfile.TemporaryDirectory() as d:
            repo, work = self.repo(d), Path(d) / "work"
            (repo / "f").write_text("x")
            subprocess.run(["git", "-C", str(repo), "add", "f"], check=True)
            args = ["build", "--type", "fix", "--scope", "deliver", "--summary", "refuse a duplicate run", "--why",
                    "two owners ran one suite twice", "--what", "reserve one run per head", "--testing-command", "make test",
                    "--testing-result", "9 OK", "--refs", "none (repo has no ticket system)", "--commit", "--repo", str(repo)]
            self.assertEqual(self.run_cli(*args, work=work)[0], 0)
            (repo / "g").write_text("y")
            subprocess.run(["git", "-C", str(repo), "add", "g"], check=True)
            code, data = self.run_cli(*args, work=work)
            self.assertEqual(code, 2)
            self.assertEqual(data["errors"][0]["field"], "message")

    def test_work_dir_rules(self):  # F4
        with tempfile.TemporaryDirectory() as d:
            repo = self.repo(d)
            (repo / "f").write_text("x")
            subprocess.run(["git", "-C", str(repo), "add", "f"], check=True)
            base = ["build", "--type", "chore", "--scope", "x", "--summary", "add a thing", "--why", "needed for the test",
                    "--what", "adds the thing for the test", "--testing", "not run: docs only change", "--refs",
                    "none (test fixture only)", "--commit", "--repo", str(repo)]
            env_off = {"HARNESS_ALLOW_TMP_WORK": ""}
            for bad, why in (("relative/dir", "absolute"), (str(Path(tempfile.gettempdir()) / "w"), "temp")):
                code, data = self.run_cli(*base, work=bad, extra=env_off)
                self.assertEqual(code, 2, (bad, data))
                self.assertIn(why, data["errors"][0]["problem"])
            shared = Path(d) / "shared"
            shared.mkdir(mode=0o755)
            os.chmod(shared, 0o755)
            code, data = self.run_cli(*base, work=shared)
            self.assertEqual(code, 2)
            self.assertEqual(oct(shared.stat().st_mode & 0o777), "0o755")  # refused, not chmod-ed
            link = Path(d) / "link"
            link.symlink_to(shared)
            code, data = self.run_cli(*base, work=link)
            self.assertEqual(code, 2)
            self.assertIn("symlink", data["errors"][0]["problem"])

    def test_bad_arguments_and_unbounded_check_inputs(self):  # F16
        code, data = self.run_cli("build", "--bogus", "x", work=Path("/nonexistent"))
        self.assertEqual((code, data["ok"]), (2, False))
        code, data = self.run_cli("build", "--comm", work=Path("/nonexistent"))  # no abbreviation to --commit
        self.assertEqual(code, 2)
        with tempfile.TemporaryDirectory() as d:
            big = Path(d) / "big.txt"
            big.write_bytes(b"x" * 2_000_000)
            code, data = self.run_cli("check", "--file", str(big), work=Path(d) / "w")
            self.assertEqual(code, 2)
            fifo = Path(d) / "fifo"
            os.mkfifo(fifo)
            code, data = self.run_cli("check", "--file", str(fifo), work=Path(d) / "w")
            self.assertEqual(code, 2)


class Wiring(unittest.TestCase):
    def test_installed_with_the_hooks(self):  # F6
        import install
        self.assertIn("commit_message.py", install.HOOKS)


class ThirdReview(unittest.TestCase):
    """Findings of the delta review of 8eb9cb5 (pure builder parts)."""

    def test_more_prose_is_not_a_command(self):
        for text in ("make sure everything works: ok", "go through it by hand: ok", "git: looks fine ok", "node: ok", "bash: ok",
                     "docker: ok", "make sure tests pass", "git looks clean"):
            r = build(testing_command="", testing_result="", testing=text)
            self.assertFalse(r["ok"], text)
        r = build(testing_command="I eyeballed it", testing_result="ok")
        self.assertFalse(r["ok"])
        self.assertEqual(r["errors"][0]["field"], "Testing")

    def test_arrow_splits_on_the_last_one_and_unquoted_separators_survive(self):
        r = build(testing_command="", testing_result="", testing="make FOO=a->b test: ok")
        self.assertTrue(r["ok"], r["errors"])
        self.assertIn("Testing: `make FOO=a->b test`: ok", r["message"])
        r = build(testing_command="", testing_result="", testing="curl -H Accept: application/json http://x -> 200 ok")
        self.assertTrue(r["ok"], r["errors"])
        self.assertIn("Testing: `curl -H Accept: application/json http://x`: 200 ok", r["message"])

    def test_every_template_placeholder_form_is_refused(self):
        forms = [dict(testing_command="", testing_result="", testing="not run: <reason>"),
                 dict(testing_command="", testing_result="", testing="`<exact command>` -> <result, e.g. 14 passed>"),
                 dict(refs="none (<reason>)", ticket=""), dict(testing_command="`<exact command>`", testing_result="3 passed"),
                 dict(why="<problem or motivation> x"), dict(risk="<a> <b>"),
                 dict(type="revert", reason="<why> <why>", authorized_by="<who> GoodQA #1")]
        for over in forms:
            self.assertFalse(build(**over)["ok"], over)

    def test_trailers_get_the_character_scan_and_one_line_each(self):
        for bad in (["Signed-off-by: x\x1b[31mred\u202e"], ["Co-Authored-By: <trailers last, after a blank line>"],
                    ["Co-Authored-By: A <a@b.c>\nSigned-off-by: B <b@c.d>"], ["Co-Authored-By:"]):
            r = build(trailers=bad)
            self.assertFalse(r["ok"], bad)
            self.assertEqual(r["errors"][0]["field"], "trailers")

    def test_field_shape_length_and_content(self):
        self.assertFalse(build(why="x" * 5000)["ok"])
        self.assertFalse(build(why="\u3164" * 20)["ok"])
        self.assertFalse(build(scope="a): add other thing (b")["ok"])
        self.assertFalse(build(type="fix(")["ok"])
        self.assertTrue(build(scope="deliver")["ok"])

    def test_ready_message_edges(self):
        for subject in ("password(x): y z", "token(a): b c"):
            out = cm.ready_message([], subject + "\n", {"scope": "deliver"}, POLICY)
            self.assertIn("--type fix", out)
            self.assertNotIn("password", out)
        for task in ({"scope": "sk-live-abc123secret", "ticket": "GoodQA ghp_SECRETTOKENabc#1"}, {"scope": None, "ticket": None},
                     b"bytes", None, {"scope": 5, "ticket": ["x"]}):
            out = cm.ready_message([], "x", task, POLICY)
            self.assertNotIn("secret", out.lower())
            self.assertNotIn("ghp_", out)
            self.assertIn("'<scope>'", out)
            self.assertIn("'<ticket number>'", out)

    def test_pr_reason_authorized_by_and_ignored_trailers(self):
        r = cm.build_pr({**GOOD, "title": "revert(a): undo the guard", "reason": "it blocked all deliveries",
                         "authorized_by": "Eric, GoodQA #14552", "trailers": ["Co-Authored-By: A <a@b.c>"]}, POLICY)
        self.assertTrue(r["ok"], r["errors"])
        self.assertIn("Reason: it blocked", r["body"])
        self.assertTrue(any("trailers" in w for w in r["warnings"]))
        both = cm.build_pr({**GOOD, "title": "fix(a): add b", "testing": "ignored text"}, POLICY)
        self.assertTrue(any("ignored" in w for w in both["warnings"]))


class CommitEdges(Commit):
    """Review F1 and friends: the outcome is judged by HEAD; files are private and removed."""

    def staged(self, d, hooks=None):
        repo = self.repo(d)
        (repo / "f").write_text("x")
        subprocess.run(["git", "-C", str(repo), "add", "f"], check=True)
        for name, body in (hooks or {}).items():
            hook = repo / ".git" / "hooks" / name
            hook.write_bytes(body)
            hook.chmod(0o755)
        return repo

    CMD = ["build", "--type", "chore", "--scope", "x", "--summary", "add a thing", "--why", "needed for the test",
           "--what", "adds the thing for the test", "--testing", "not run: docs only change", "--refs", "none (test fixture only)"]

    def heads(self, repo):
        r = subprocess.run(["git", "-C", str(repo), "rev-list", "--count", "--all"], capture_output=True, text=True)
        return int(r.stdout.strip() or 0)

    def test_undecodable_hook_output_does_not_turn_a_landed_commit_into_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"post-commit": b"#!/bin/sh\nprintf 'caf\\351' >&2\n"})
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertEqual((code, data["ok"], data["committed"]), (0, True, True), data)
            self.assertEqual(self.heads(repo), 1)

    def test_failing_hook_with_binary_output_keeps_the_cause_and_says_not_committed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"pre-commit": b"#!/bin/sh\necho 'cause: lint failed' >&2\nprintf '\\377\\376' >&2\nexit 1\n"})
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertEqual((code, data["ok"], data["committed"]), (2, False, False), data)
            self.assertIn("cause: lint failed", data["errors"][0]["problem"])
            self.assertEqual(self.heads(repo), 0)
            self.assertFalse(list((Path(d) / "w").iterdir()))

    def test_timeout_after_the_commit_landed_reports_committed_and_before_it_reports_not(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"post-commit": b"#!/bin/sh\nsleep 6\n"})
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=Path(d) / "w",
                                      extra={"HARNESS_COMMIT_TIMEOUT_S": "2"})
            self.assertEqual(data["committed"], True, data)
            self.assertEqual(self.heads(repo), 1)
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"pre-commit": b"#!/bin/sh\nsleep 6\n"})
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=Path(d) / "w",
                                      extra={"HARNESS_COMMIT_TIMEOUT_S": "2"})
            self.assertEqual((code, data["ok"], data["committed"]), (2, False, False), data)
            self.assertIn("did not finish", data["errors"][0]["problem"])

    def test_a_hook_that_rewrites_the_message_is_reported_not_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"commit-msg": b"#!/bin/sh\necho wip > \"$1\"\n"})
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertEqual(code, 2, data)
            self.assertTrue(data["committed"])
            self.assertFalse(data["ok"])
            self.assertFalse(data["committed_valid"])
            self.assertEqual(data["message"].strip(), "wip")
            self.assertTrue(any("differs" in w for w in data["warnings"]))

    def test_secrets_in_hook_output_are_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"pre-commit": b"#!/bin/sh\necho 'token=ghp_abcdefSECRET12345 seen' >&2\nexit 1\n"})
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertNotIn("ghp_abcdef", json.dumps(data))
            self.assertIn("[redacted]", data["errors"][0]["problem"])

    def test_temp_dir_rule_uses_the_resolved_path_even_when_the_parent_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d)
            for bad in ("/tmp/hm-x/y/z", "/var/tmp/hm-x/y/z", str(Path(tempfile.gettempdir()) / "hm-x" / "y" / "z")):
                code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=bad, extra={"HARNESS_ALLOW_TMP_WORK": "0"})
                self.assertEqual(code, 2, (bad, data))
                self.assertIn("temp", data["errors"][0]["problem"])
                self.assertFalse(Path(bad).exists(), bad)

    def test_unwritable_work_dir_and_message_file_mode(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d)
            ro = Path(d) / "ro"
            ro.mkdir(mode=0o500)
            code, data = self.run_cli(*self.CMD, "--commit", "--repo", str(repo), work=ro / "w")
            self.assertEqual(code, 2, data)
            self.assertIn("work directory", data["errors"][0]["problem"])
            ro.chmod(0o700)
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / "w"
            with unittest.mock.patch.dict(os.environ, {"HARNESS_WORK_DIR": str(work), "HARNESS_ALLOW_TMP_WORK": "1"}):
                path = cm.commit_message_file("hello\n")
                self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
                self.assertEqual(oct(work.stat().st_mode & 0o777), "0o700")
                with unittest.mock.patch.object(os, "fdopen", side_effect=OSError("disk full")):
                    before = set(work.iterdir())
                    with self.assertRaises(OSError):
                        cm.commit_message_file("x")
                    self.assertEqual(set(work.iterdir()), before)

    def test_message_file_is_removed_on_sigterm(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self.staged(d, {"pre-commit": b"#!/bin/sh\nsleep 20\n"})
            work = Path(d) / "w"
            env = {**os.environ, "HARNESS_WORK_DIR": str(work), "HARNESS_ALLOW_TMP_WORK": "1", "GIT_AUTHOR_NAME": "t",
                   "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
            proc = subprocess.Popen([sys.executable, str(HOOKS / "commit_message.py"), *self.CMD, "--commit", "--repo", str(repo)],
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            import signal as sg
            import time
            deadline = time.time() + 20
            while time.time() < deadline and not (work.exists() and list(work.iterdir())):
                time.sleep(0.1)
            self.assertTrue(list(work.iterdir()), "the message file should exist while git runs")
            proc.send_signal(sg.SIGTERM)
            proc.wait(timeout=30)
            self.assertFalse(list(work.iterdir()))
            subprocess.run(["pkill", "-f", str(repo / ".git" / "hooks" / "pre-commit")], check=False)


if __name__ == "__main__":
    unittest.main()
