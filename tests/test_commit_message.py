"""harness/hooks/commit_message.py: field-built messages always validate; refusals are field-level; real refusal shapes
replay; --commit reports what git recorded, on every path including signals."""
import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import uuid
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
# Runs the real CLI with only the temp-dir rule replaced, because test directories live in the system temp dir.
BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); import commit_message as cm; cm._temp_roots = set; "
        "cm._entry()")
SCRIPT = [sys.executable, "-c", BOOT, str(HOOKS)]
REAL = [sys.executable, str(HOOKS / "commit_message.py")]
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
CMD = ["build", "--type", "chore", "--scope", "x", "--summary", "add a thing", "--why", "needed for the test",
       "--what", "adds the thing for the test", "--testing", "not run: docs only change", "--refs", "none (test fixture only)"]
TWO = dict(testing_command="", testing_result="")


def build(**over):
    return cm.build_message({**GOOD, **over}, POLICY)


def testing(text):
    return build(testing=text, **TWO)


def env_for(work=None, extra=None):
    env = {**os.environ, **GIT_ENV, **(extra or {})}
    if work is not None:
        env["HARNESS_WORK_DIR"] = str(work)
    return env


def cli(*args, work=None, extra=None, script=SCRIPT, stdin=None):
    r = subprocess.run([*script, *args], capture_output=True, text=True, env=env_for(work, extra), timeout=90, input=stdin)
    return r.returncode, json.loads(r.stdout)


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env_for()).stdout.strip()


def add_hooks(repo, hooks):
    for name, body in (hooks or {}).items():
        hook = Path(repo) / ".git" / "hooks" / name
        hook.write_bytes(body if isinstance(body, bytes) else body.encode())
        hook.chmod(0o755)


def fresh_repo(d, hooks=None, origin=None):
    """A repository with no commits and one staged file."""
    repo = Path(d) / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env_for())
    if origin:
        git(repo, "remote", "add", "origin", origin)
    (repo / "f").write_text("x")
    git(repo, "add", "f")
    add_hooks(repo, hooks)
    return repo


def history_repo(d, hooks=None):
    """A repository with history on branch 'feature', a branch 'base', and one staged change: HEAD can be compared."""
    repo = fresh_repo(d)
    git(repo, "commit", "-q", "-m", "the first commit")
    git(repo, "branch", "base")
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "g").write_text("y")
    git(repo, "add", "g")
    add_hooks(repo, hooks)
    return repo


# A commit that is not ours, made without touching the index: the shape of a hook or a peer committing meanwhile.
OTHER_COMMIT = 'c=$(git commit-tree "HEAD^{tree}" -p HEAD -m "someone else wrote this"); git update-ref HEAD "$c"\n'


def wait_for(path, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if Path(path).exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"{path} never appeared")


def gone(pid, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class Build(unittest.TestCase):
    def test_good_fields_build_a_message_that_validates(self):
        r = build()
        self.assertTrue(r["ok"], r["errors"])
        self.assertEqual(cp.validate(r["message"], policy=POLICY), [])
        self.assertIn("Refs: GoodQA #14552", r["message"])
        self.assertIn("Testing: `python3 -m unittest tests.test_x`: 14 tests OK", r["message"])

    def test_safe_normalizations_with_warnings(self):
        r = build(summary="Added a guard.", scope="Deliver", type="FIX")
        self.assertTrue(r["ok"], r["errors"])
        self.assertTrue(r["message"].startswith("fix(deliver): add a guard\n"))
        self.assertTrue(any("imperative" in w for w in r["warnings"]))
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


OK_SHAPES, REFUSED_SHAPES = 62, 76


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
        if s["refs_kind"] == "none":
            fields["refs"] = "none (documentation-only change, no ticket)"
        else:
            fields["ticket"] = "14552"
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
        # Pinned on purpose: a change here changes how many real messages go through. The refused ones have empty prose,
        # an over-long subject or a subject that does not parse. The fixture comes from tests/fixtures/extract_refusals.py.
        self.assertEqual((len(self.SHAPES), ok, refused), (138, OK_SHAPES, REFUSED_SHAPES))

    def test_unwrapped_evidence_in_the_real_shapes_gets_the_two_field_fix(self):
        bare = [s for s in self.SHAPES if s["sections"].get("Testing") and not s["testing_has_backticks"] and not s["testing_not_run"]]
        self.assertEqual(len(bare), 58)  # the form the builder used to rewrite by guessing
        r = testing("python3 -m unittest: 3 tests OK")
        self.assertFalse(r["ok"])
        self.assertEqual(r["errors"][0]["field"], "Testing")
        self.assertIn("--testing-command", r["errors"][0]["fix"])

    def test_the_fixture_holds_no_free_text(self):
        for s in self.SHAPES:
            self.assertNotIn("refs_form", s)
            self.assertIn(s["refs_kind"], (None, "none", "ticket", "pr", "other"))
            self.assertIn(s["type"], (None, "merge", *POLICY["subject"]["types"]))
            for value in s.values():
                self.assertIsInstance(value, (bool, int, str, dict, type(None)))

    def test_the_extractor_masks_quotes_and_writes_outside_the_tree(self):
        sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
        import extract_refusals as ex
        self.assertEqual(ex.category('subject got "wip stuff" and \'other\' and `x`'), 'subject got "X" and \'X\' and `X`')
        for value, kind in (("none (fixture only)", "none"), ("GoodQA #1", "ticket"), ("GoodQA a#1", "ticket"), ("PR #4", "pr"), ("whatever", "other")):
            self.assertEqual(ex.refs_kind(value), kind, value)
        self.assertEqual(set(ex.shape("fix: a\n\nRefs: none (private words here)\n")) & {"refs_form"}, set())
        self.assertNotIn("private", json.dumps(ex.shape("fix: a\n\nRefs: none (private words here)\n")))
        done = subprocess.run([sys.executable, str(ROOT / "tests" / "fixtures" / "extract_refusals.py")], capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("OUTPUT_DIR", done.stderr)

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


NEG_TESTING = ["tests: pass", "tested locally: ok", "manually checked everything: ok", "nothing: ok", "I eyeballed it - looks ok",
               "all tests pass"]


class SecondReview(unittest.TestCase):
    """Findings of the independent review of e42d903."""

    def test_prose_is_never_laundered_into_a_command(self):  # F1
        for text in NEG_TESTING:
            r = build(testing_command="", testing_result="", testing=text)
            self.assertFalse(r["ok"], text)
            self.assertEqual(r["errors"][0]["field"], "Testing", text)

    def test_real_evidence_is_kept_whole_in_the_structured_fields(self):  # F1
        for command, result in (("curl http://localhost:8080/health", "200 ok"), ("pytest tests/a.py::test_b", "1 passed"),
                                ("pytest -k 'a: b'", "1 passed"), ("curl -H Accept: application/json http://x", "200 ok"),
                                ("make FOO: BAR test", "ok"), ("make FOO=a->b test", "ok")):
            r = build(testing_command=command, testing_result=result)
            self.assertTrue(r["ok"], (command, r["errors"]))
            self.assertIn(f"Testing: `{command}`: {result}\n", r["message"])

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


class Cli(unittest.TestCase):
    ARGS = ["build", "--type", "fix", "--scope", "deliver", "--summary", "refuse a duplicate run", "--why",
            "two owners ran one suite twice", "--what", "reserve one run per head", "--testing-command", "make test",
            "--testing-result", "9 OK", "--ticket", "14552"]

    def test_exit_codes_and_no_write_on_refusal(self):
        code, data = cli(*self.ARGS)
        self.assertEqual((code, data["ok"]), (0, True))
        code, data = cli(*self.ARGS[:-1], "")
        self.assertEqual((code, data["ok"]), (2, False))
        self.assertEqual(data["errors"][0]["field"], "Refs")

    def test_commit_writes_a_0600_file_under_the_work_dir_and_commits(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = fresh_repo(d), Path(d) / "work"
            code, data = cli(*self.ARGS, "--commit", "--repo", str(repo), work=work)
            self.assertEqual((code, data["commit_exit"], data["committed"]), (0, 0, True), data)
            self.assertEqual(data["commit"], git(repo, "rev-parse", "HEAD"))
            self.assertFalse(list(work.iterdir()), "the message file is removed after the commit")
            self.assertEqual(oct(work.stat().st_mode & 0o777), "0o700")
            self.assertEqual(git(repo, "log", "-1", "--format=%s"), "fix(deliver): refuse a duplicate run")

    def test_the_file_mode_and_a_failed_write(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / "w"
            with unittest.mock.patch.dict(os.environ, {"HARNESS_WORK_DIR": str(work)}), unittest.mock.patch.object(cm, "_temp_roots", set):
                path = cm.commit_message_file("hello\n")
                self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
                self.assertEqual(oct(work.stat().st_mode & 0o777), "0o700")
                with unittest.mock.patch.object(os, "fdopen", side_effect=OSError("disk full")):
                    before = set(work.iterdir())
                    with self.assertRaises(OSError):
                        cm.commit_message_file("x")
                    self.assertEqual(set(work.iterdir()), before)

    def test_check_command_and_its_size_cap(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "m.txt"
            f.write_text("wip\n")
            code, data = cli("check", "--file", str(f))
            self.assertEqual((code, data["ok"]), (2, False))
            code, data = cli("check", "--file", str(Path(d) / "missing"))
            self.assertEqual((code, data["errors"][0]["field"]), (2, "input"))
            big = Path(d) / "big.txt"
            big.write_bytes(b"x" * (cm.MAX_CHECK_BYTES + 1))
            code, data = cli("check", "--file", str(big))
            self.assertEqual(code, 2)
            self.assertIn("larger than 16384", data["errors"][0]["problem"])
            fifo = Path(d) / "fifo"
            os.mkfifo(fifo)
            code, data = cli("check", "--file", str(fifo))
            self.assertEqual(code, 2)

    def test_check_at_the_cap_stays_fast_on_the_policy_quadratic_regex(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "m.txt"
            head = "fix(a): add b\n\nWhy: a real reason here\nWhat: a real change here\nTesting: not run: docs only change\nRefs: "
            f.write_text(head + "a." * ((cm.MAX_CHECK_BYTES - len(head)) // 2) + "\n")
            self.assertLessEqual(f.stat().st_size, cm.MAX_CHECK_BYTES)
            started = time.monotonic()
            code, _ = cli("check", "--file", str(f))
            self.assertEqual(code, 2)
            self.assertLess(time.monotonic() - started, 20)

    def test_bad_arguments(self):
        code, data = cli("build", "--bogus", "x")
        self.assertEqual((code, data["ok"]), (2, False))
        code, data = cli("build", "--comm")  # no abbreviation to --commit
        self.assertEqual(code, 2)


class Commit(unittest.TestCase):
    """The hook's rules are applied before git; a failure is reported as one."""

    def test_git_failure_is_an_error_not_ok_and_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = fresh_repo(d), Path(d) / "work"
            git(repo, "rm", "-q", "--cached", "f")
            code, data = cli(*Cli.ARGS, "--commit", "--repo", str(repo), work=work)
            self.assertEqual((code, data["ok"], data["committed"], data["message"]), (2, False, False, None), data)
            self.assertEqual(data["errors"][0]["field"], "git")
            self.assertIn("nothing", data["errors"][0]["problem"].lower())
            self.assertFalse(list(work.iterdir()))

    def test_not_a_repo_and_a_rejecting_hook(self):
        with tempfile.TemporaryDirectory() as d:
            code, data = cli(*Cli.ARGS, "--commit", "--repo", str(Path(d) / "nope"), work=Path(d) / "w")
            self.assertEqual((code, data["errors"][0]["field"], data["committed"]), (2, "git", False))
            repo, work = fresh_repo(d, {"commit-msg": "#!/bin/sh\necho 'hook says: no ticket id in the body' >&2\nexit 1\n"}), Path(d) / "work"
            code, data = cli(*Cli.ARGS, "--commit", "--repo", str(repo), work=work)
            self.assertEqual(code, 2)
            self.assertIn("hook says: no ticket id", data["errors"][0]["problem"])
            self.assertFalse(list(work.iterdir()))

    def test_the_ticket_rule_follows_the_repo_origin_like_the_hook(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = fresh_repo(d, origin="https://github.com/ericmacdougall/agent-harness.git"), Path(d) / "work"
            skip = ["build", "--type", "fix", "--scope", "deliver", "--summary", "refuse a duplicate run", "--why",
                    "two owners ran one suite twice", "--what", "reserve one run per head", "--testing-command", "make test",
                    "--testing-result", "9 OK", "--refs", "none (skip the ticket gate)", "--no-tickets", "--commit", "--repo", str(repo)]
            code, data = cli(*skip, work=work)
            self.assertEqual((code, data["committed"]), (2, False), data)
            self.assertEqual(data["errors"][0]["field"], "Refs")
            self.assertEqual(git(repo, "rev-list", "--count", "--all"), "0")

    def test_untracked_repo_does_not_demand_a_ticket_and_duplicates_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = fresh_repo(d), Path(d) / "work"
            args = ["build", "--type", "fix", "--scope", "deliver", "--summary", "refuse a duplicate run", "--why",
                    "two owners ran one suite twice", "--what", "reserve one run per head", "--testing-command", "make test",
                    "--testing-result", "9 OK", "--refs", "none (repo has no ticket system)", "--commit", "--repo", str(repo)]
            self.assertEqual(cli(*args, work=work)[0], 0)
            (repo / "g").write_text("y")
            git(repo, "add", "g")
            code, data = cli(*args, work=work)
            self.assertEqual(code, 2)
            self.assertEqual(data["errors"][0]["field"], "message")

    def test_duplicate_check_is_not_blinded_by_git_log_output_settings(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = fresh_repo(d), Path(d) / "work"
            git(repo, "config", "i18n.logOutputEncoding", "latin1")
            args = [*CMD[:7], "--why", "the café needs this for the test", *CMD[9:], "--commit", "--repo", str(repo)]
            self.assertEqual(cli(*args, work=work)[0], 0)
            (repo / "g").write_text("y")
            git(repo, "add", "g")
            code, data = cli(*args, work=work)
            self.assertEqual((code, data["errors"][0]["field"]), (2, "message"), data)

    def test_git_gets_no_stdin(self):  # K6: hooks get /dev/null from git itself, so this looks at git
        with tempfile.TemporaryDirectory() as d:
            repo, seen = fresh_repo(d), Path(d) / "stdin"
            real = shutil.which("git")
            fake = Path(d) / "bin"
            fake.mkdir()
            (fake / "git").write_text(f'#!/bin/sh\ncase " $* " in *" commit -F "*) cat > "{seen}";; esac\nexec "{real}" "$@"\n')
            (fake / "git").chmod(0o755)
            code, data = cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w", stdin="PIPED",
                             extra={"PATH": f"{fake}:{os.environ['PATH']}"})
            self.assertEqual((code, data["committed"]), (0, True), data)
            self.assertEqual(seen.read_text(), "")


class Outcome(unittest.TestCase):
    """Third review HIGH 1-3: the outcome is what git recorded. These all run in a repository WITH history."""

    def run_it(self, repo, d, **extra):
        return cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w", extra=extra)

    def assert_no_file(self, d):
        self.assertEqual(list((Path(d) / "w").iterdir()), [])

    def test_a_failing_commit_with_an_unchanged_head_is_not_landed(self):  # O1
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"pre-commit": "#!/bin/sh\necho 'cause: lint failed' >&2\nexit 1\n"})
            before = git(repo, "rev-parse", "HEAD")
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (2, False, False, 1), data)
            self.assertIsNone(data["message"])
            self.assertIn("cause: lint failed", data["errors"][0]["problem"])
            self.assertEqual(git(repo, "rev-parse", "HEAD"), before)
            self.assert_no_file(d)

    def test_a_hook_that_commits_something_else_and_fails_is_never_ok(self):  # finding 1, O4
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"pre-commit": "#!/bin/sh\n" + OTHER_COMMIT + "exit 1\n"})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (2, False, "unknown", 1), data)
            self.assertIsNone(data["message"])
            self.assertEqual(git(repo, "log", "-1", "--format=%s"), "someone else wrote this")
            self.assert_no_file(d)

    def test_a_peer_commit_then_a_hang_is_never_ok(self):  # finding 1
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"pre-commit": "#!/bin/sh\n" + OTHER_COMMIT + "sleep 30\n"})
            code, data = self.run_it(repo, d, HARNESS_COMMIT_TIMEOUT_S="1")
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (2, False, "unknown", None), data)
            self.assertIn("did not finish", data["errors"][0]["problem"])

    def test_our_commit_followed_by_a_hang_is_proven_ours(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"post-commit": "#!/bin/sh\nsleep 30\n"})
            code, data = self.run_it(repo, d, HARNESS_COMMIT_TIMEOUT_S="1")
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (0, True, True, None), data)
            self.assertTrue(any("did not finish" in w for w in data["warnings"]), data)
            self.assertEqual(git(repo, "log", "-1", "--format=%s"), "chore(x): add a thing")

    def test_a_timeout_before_the_commit_is_not_committed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"pre-commit": "#!/bin/sh\necho 'cause: stuck' >&2\nsleep 30\n"})
            code, data = self.run_it(repo, d, HARNESS_COMMIT_TIMEOUT_S="1")
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (2, False, False, None), data)
            self.assertIn("did not finish", data["errors"][0]["problem"])
            self.assertIn("cause: stuck", data["errors"][0]["problem"])

    def test_a_post_commit_checkout_does_not_hide_the_commit(self):  # finding 3
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"post-commit": "#!/bin/sh\ngit checkout -q base\n"})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (0, True, True, 0), data)
            self.assertTrue(any("HEAD is no longer" in w for w in data["warnings"]), data)
            self.assertEqual(data["commit"], git(repo, "rev-parse", "feature"))

    def test_exit_zero_never_reports_false(self):  # finding 3
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"post-commit": "#!/bin/sh\ngit reset -q --hard HEAD~1\n"})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (2, False, "unknown", 0), data)
            self.assertIn("did not move", data["errors"][0]["problem"])

    def test_commits_on_top_of_ours_still_prove_ours(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"post-commit": "#!/bin/sh\n" + OTHER_COMMIT})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"]), (0, True, True), data)
            self.assertTrue(any("later commit" in w for w in data["warnings"]), data)
            self.assertEqual(data["commit"], git(repo, "rev-parse", "HEAD~1"))

    def test_a_rewriting_hook_is_reported_not_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"commit-msg": '#!/bin/sh\necho wip > "$1"\n'})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"], data["committed_valid"]), (2, False, True, False), data)
            self.assertEqual(data["message"].strip(), "wip")
            self.assertTrue(any("differs" in w for w in data["warnings"]))

    def test_log_output_encoding_does_not_fake_a_difference(self):  # finding 2
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d)
            git(repo, "config", "i18n.logOutputEncoding", "latin1")
            code, data = cli(*CMD[:7], "--why", "the café needs this for the test", *CMD[9:], "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertEqual((code, data["ok"], data["committed"]), (0, True, True), data)
            self.assertFalse(any("differs" in w for w in data["warnings"]), data)
            self.assertIn("café", data["message"])
            self.assertNotIn("committed_valid", data)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is needed to make a signed commit")
    def test_a_signed_commit_reads_back_as_its_message(self):  # finding 2
        with tempfile.TemporaryDirectory() as d:
            repo, key = history_repo(d), Path(d) / "key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            for name, value in (("gpg.format", "ssh"), ("user.signingkey", str(key)), ("commit.gpgsign", "true"), ("log.showSignature", "true")):
                git(repo, "config", name, value)
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"]), (0, True, True), data)
            self.assertNotIn("committed_valid", data)
            self.assertIn("gpgsig", git(repo, "cat-file", "commit", "HEAD"))

    def fake_git(self, d, body):
        """A git wrapper for faults the real tool will not produce. MARK appears once `commit` has finished."""
        real, fake, mark = shutil.which("git"), Path(d) / "bin", Path(d) / "mark"
        fake.mkdir()
        (fake / "git").write_text(f'#!/bin/sh\nMARK="{mark}"\nREAL="{real}"\ncase " $* " in\n'
                                  f'  *" commit -F "*) "$REAL" "$@"; rc=$?; : > "$MARK"; exit $rc;;\n{body}\nesac\nexec "$REAL" "$@"\n')
        (fake / "git").chmod(0o755)
        return {"PATH": f"{fake}:{os.environ['PATH']}"}

    def test_a_failed_read_back_is_unknown_with_an_exit_of_two(self):  # finding 2
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d)
            path = self.fake_git(d, '  *" cat-file "*) [ -e "$MARK" ] && exit 128;;')
            code, data = self.run_it(repo, d, **path)
            self.assertEqual((code, data["ok"], data["committed"], data["commit_exit"]), (2, False, "unknown", 0), data)
            self.assertIn("read the new commit back", data["errors"][0]["problem"])
            self.assert_no_file(d)

    def test_a_hanging_git_after_the_commit_still_reports_an_outcome(self):  # finding 3
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d)
            path = self.fake_git(d, '  *" rev-parse "*) [ -e "$MARK" ] && exec sleep 30;;')
            code, data = self.run_it(repo, d, HARNESS_COMMIT_READ_TIMEOUT_S="1", **path)
            self.assertEqual((code, data["committed"], data["commit_exit"]), (2, "unknown", 0), data)
            self.assert_no_file(d)

    def test_a_hanging_git_before_launch_refuses_and_writes_no_file(self):  # finding 4
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d)
            path = self.fake_git(d, '  *" symbolic-ref -q "*) exec sleep 30;;')
            code, data = self.run_it(repo, d, HARNESS_COMMIT_READ_TIMEOUT_S="1", **path)
            self.assertEqual((code, data["committed"]), (2, False), data)
            self.assert_no_file(d)

    def test_a_bad_timeout_setting_is_refused_before_any_file_exists(self):  # finding 4
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d)
            before = git(repo, "rev-parse", "HEAD")
            (Path(d) / "w").mkdir(mode=0o700)
            for name in ("HARNESS_COMMIT_TIMEOUT_S", "HARNESS_COMMIT_READ_TIMEOUT_S"):
                for bad in ("abc", "-1", "0", "1.5"):
                    code, data = self.run_it(repo, d, **{name: bad})
                    self.assertEqual((code, data["ok"], data["committed"], data["errors"][0]["field"]), (2, False, False, "input"), (name, bad, data))
                    self.assert_no_file(d)
            self.assertEqual(git(repo, "rev-parse", "HEAD"), before)

    def test_undecodable_hook_output_does_not_turn_a_landed_commit_into_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"post-commit": b"#!/bin/sh\nprintf 'caf\\351' >&2\n"})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["ok"], data["committed"]), (0, True, True), data)

    def test_failing_hook_with_binary_output_keeps_the_cause(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"pre-commit": b"#!/bin/sh\necho 'cause: lint failed' >&2\nprintf '\\377\\376' >&2\nexit 1\n"})
            code, data = self.run_it(repo, d)
            self.assertEqual((code, data["committed"]), (2, False), data)
            self.assertIn("cause: lint failed", data["errors"][0]["problem"])

    def test_main_from_a_non_main_thread_works_and_leaves_no_file(self):  # finding 4
        with tempfile.TemporaryDirectory() as d:
            repo, work = history_repo(d), Path(d) / "w"
            out, result = io.StringIO(), []

            def target():
                with contextlib.redirect_stdout(out):
                    result.append(cm.main([*CMD, "--commit", "--repo", str(repo)]))
            with unittest.mock.patch.dict(os.environ, {**GIT_ENV, "HARNESS_WORK_DIR": str(work)}), unittest.mock.patch.object(cm, "_temp_roots", set):
                thread = threading.Thread(target=target)
                thread.start()
                thread.join(60)
            self.assertEqual(result, [0])
            self.assertTrue(json.loads(out.getvalue())["committed"])
            self.assertEqual(list(work.iterdir()), [])


class Signals(unittest.TestCase):
    """Finding 3 and 4: one JSON object, exit 0, 2 or 4, committed set, no message file, the hook's group ended."""

    SIGNUMS = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)

    def launch(self, repo, work, extra=None):
        return subprocess.Popen([*SCRIPT, *CMD, "--commit", "--repo", str(repo)], env=env_for(work, extra), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)

    def finish(self, proc):
        out, err = proc.communicate(timeout=45)
        self.assertEqual(err, "", "no traceback")
        self.assertEqual(len(out.strip().splitlines()), 1, out)
        return proc.returncode, json.loads(out)

    def during(self, d, hook_name, signum, twice=False):
        marker, pidfile = Path(d) / "ready", Path(d) / "pid"
        repo = history_repo(d, {hook_name: f'#!/bin/sh\necho $$ > "{pidfile}"\n: > "{marker}"\nsleep 30\n'})
        work = Path(d) / "w"
        proc = self.launch(repo, work)
        wait_for(marker)
        self.assertEqual(len(list(work.iterdir())), 1, "the message file exists while git runs, so this tests its removal")
        proc.send_signal(signum)
        if twice:
            proc.send_signal(signum)
        code, data = self.finish(proc)
        self.assertEqual(list(work.iterdir()), [], "the message file is gone")
        self.assertTrue(gone(int(pidfile.read_text())), "the hook was ended with git")
        return repo, code, data

    def test_every_signal_during_pre_commit(self):
        for signum in self.SIGNUMS:
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as d:
                repo, code, data = self.during(d, "pre-commit", signum)
                self.assertEqual((code, data["ok"], data["committed"], data["interrupted"]), (2, False, False, signal.Signals(signum).name), data)
                self.assertEqual(git(repo, "log", "-1", "--format=%s"), "the first commit")

    def test_every_signal_during_post_commit_reports_the_landed_commit(self):
        for signum in self.SIGNUMS:
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as d:
                repo, code, data = self.during(d, "post-commit", signum)
                self.assertEqual((code, data["ok"], data["committed"], data["interrupted"]), (0, True, True, signal.Signals(signum).name), data)
                self.assertEqual(data["commit"], git(repo, "rev-parse", "HEAD"))

    def test_a_second_signal_cannot_cut_the_result_short(self):
        with tempfile.TemporaryDirectory() as d:
            _, code, data = self.during(d, "pre-commit", signal.SIGTERM, twice=True)
            self.assertEqual((code, data["committed"]), (2, False), data)

    def test_a_signal_during_a_pre_launch_git_call_writes_no_file(self):  # finding 4
        # '--quiet' is the repo_facts call, before the work dir is made; '-q' is the capture of the branch, just after.
        for call in ("symbolic-ref --quiet", "symbolic-ref -q"):
            for signum in self.SIGNUMS:
                with self.subTest(call=call, signum=signum), tempfile.TemporaryDirectory() as d:
                    repo, marker, work = history_repo(d), Path(d) / "ready", Path(d) / "w"
                    real, fake = shutil.which("git"), Path(d) / "bin"
                    fake.mkdir()
                    (fake / "git").write_text(f'#!/bin/sh\ncase " $* " in *" {call} "*) : > "{marker}"; exec sleep 30;; esac\nexec "{real}" "$@"\n')
                    (fake / "git").chmod(0o755)
                    proc = self.launch(repo, work, {"PATH": f"{fake}:{os.environ['PATH']}"})
                    wait_for(marker)
                    proc.send_signal(signum)
                    code, data = self.finish(proc)
                    self.assertEqual((code, data["committed"], data["interrupted"]), (2, False, signal.Signals(signum).name), data)
                    self.assertEqual(list(work.iterdir()) if call.endswith("-q") else [], [])
                    self.assertEqual(work.exists(), call.endswith("-q"))

    def test_signals_at_every_moment_leave_no_file_and_a_contract_exit(self):  # the race the old test hit 2 of 10 times
        for step in range(12):  # a fixed grid, not random: a failure names its delay
            with self.subTest(delay_ms=step * 25), tempfile.TemporaryDirectory() as d:
                repo, work = history_repo(d), Path(d) / "w"
                proc = self.launch(repo, work)
                time.sleep(step * 0.025)
                proc.send_signal(signal.SIGTERM)
                out, _ = proc.communicate(timeout=45)
                # -15 is only possible before the interpreter reaches main(): nothing has happened yet, so no output
                self.assertTrue((proc.returncode == -signal.SIGTERM and out == "") or
                                (proc.returncode in (0, 2) and json.loads(out)["committed"] in (True, False)), (proc.returncode, out))
                self.assertEqual(list(work.iterdir()) if work.exists() else [], [])

    def test_the_cli_skips_interpreter_shutdown(self):  # shutdown restores default handlers: 143 after the JSON said 0
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "shutdown-ran"
            boot = (f"import atexit, sys; sys.path.insert(0, {str(HOOKS)!r}); import commit_message as cm; "
                    f"atexit.register(lambda: open({str(marker)!r}, 'w').close()); cm._entry()")
            done = subprocess.run([sys.executable, "-c", boot, *CMD], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue(json.loads(done.stdout)["ok"])
            self.assertFalse(marker.exists())

    def test_handlers_are_restored_for_an_in_process_caller(self):
        before = signal.getsignal(signal.SIGTERM)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cm.main(["check", "--file", "/nonexistent/none"]), 2)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)


class Children(unittest.TestCase):
    """Findings 12 and 15: output is capped, the child's exit counts rather than EOF, a timeout ends the whole group."""

    def test_output_is_capped_and_keeps_the_end(self):
        guard = cm._Guard()
        code, out = cm._run(["sh", "-c", "yes | head -c 5000000; echo THE-END"], guard, 60, merge=True)
        self.assertEqual(code, 0)
        self.assertLessEqual(len(out), cm.OUTPUT_TAIL_BYTES)
        self.assertTrue(out.endswith(b"THE-END\n"))

    def test_a_noisy_hook_keeps_the_cause(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"pre-commit": "#!/bin/sh\nyes | head -c 3000000\necho 'cause: the last line' >&2\nexit 1\n"})
            code, data = cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertEqual((code, data["committed"], data["commit_exit"]), (2, False, 1), data)
            self.assertIn("cause: the last line", data["errors"][0]["problem"])
            self.assertLess(len(json.dumps(data)), 8000)

    def test_a_background_child_holding_the_pipe_does_not_stall_the_result(self):
        for name, expect in (("pre-commit", (2, False, 1)), ("post-commit", (0, True, 0))):
            with self.subTest(hook=name), tempfile.TemporaryDirectory() as d:
                repo = history_repo(d, {name: f"#!/bin/sh\necho 'cause: from the hook' >&2\nsleep 6 &\nexit {expect[2]}\n"})
                started = time.monotonic()
                code, data = cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
                self.assertLess(time.monotonic() - started, 5, "git finished; the background sleep must not be waited for")
                self.assertEqual((code, data["committed"], data["commit_exit"]), expect, data)
                if name == "pre-commit":
                    self.assertIn("cause: from the hook", data["errors"][0]["problem"])

    def test_a_timeout_ends_the_hook_too(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / "pid"
            repo = history_repo(d, {"pre-commit": f'#!/bin/sh\necho $$ > "{pidfile}"\nsleep 30\n'})
            code, data = cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w", extra={"HARNESS_COMMIT_TIMEOUT_S": "1"})
            self.assertEqual((code, data["committed"]), (2, False), data)
            self.assertTrue(gone(int(pidfile.read_text())))


SECRETS = ("GITHUB_TOKEN=abcdefghi123", "AWS_SECRET_ACCESS_KEY=abcdefghi/123", "client_secret=abcdefghi123", "access_token: abcdefghi123",
           "https://bob:abcdefghi123@github.com/x.git", "github_pat_abcdefghi123abcdefghi123", "glpat-abcdefghi123abc",
           "AKIAABCDEFGHIJKLMNOP", "npm_abcdefghi123abcdefghi123abcdefghi123", "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefghi123",
           "Authorization: Bearer abcdefghi123", "PASSWORD='abcdefghi 123'", "sk-live-abcdefghi123")


class Redaction(unittest.TestCase):
    """Finding 10: the shared redactors, on every string that can hold hook output."""

    def leaks(self, data, secret):
        text = json.dumps(data)
        for fragment in ("abcdefghi", "ABCDEFGHIJ"):
            self.assertNotIn(fragment, text, secret)

    def test_hook_output_in_errors(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d)
            for secret in SECRETS:
                add_hooks(repo, {"pre-commit": "#!/bin/sh\ncat >&2 <<'EOF'\n" + secret + "\nEOF\nexit 1\n"})
                code, data = cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
                self.assertEqual((code, data["committed"]), (2, False), (secret, data))
                self.leaks(data, secret)
                self.assertIn("redacted", data["errors"][0]["problem"].lower(), secret)

    def test_a_rewritten_message_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            repo = history_repo(d, {"commit-msg": '#!/bin/sh\necho "wip GITHUB_TOKEN=abcdefghi123" > "$1"\n'})
            code, data = cli(*CMD, "--commit", "--repo", str(repo), work=Path(d) / "w")
            self.assertEqual((code, data["committed"]), (2, True), data)
            self.leaks(data, "read back")
            self.assertIn("wip", data["message"])

    def test_the_validated_message_itself_is_returned_exactly(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:  # the build path must stay usable as the message to commit
            self.assertEqual(cm.main([*CMD[:7], "--why", "rotate the session: token handling in x", *CMD[9:]]), 0)
        self.assertIn("rotate the session: token handling in x", json.loads(out.getvalue())["message"])


class WorkDir(unittest.TestCase):
    def test_temp_dirs_are_refused_by_the_real_cli_with_no_environment_switch(self):
        with tempfile.TemporaryDirectory() as d:
            repo = fresh_repo(d)
            unique = f"hm-{uuid.uuid4().hex}"
            for bad in (f"/tmp/{unique}/y/z", f"/var/tmp/{unique}/y/z", str(Path(tempfile.gettempdir()) / unique / "y" / "z")):
                code, data = cli(*CMD, "--commit", "--repo", str(repo), work=bad, script=REAL, extra={"HARNESS_ALLOW_TMP_WORK": "1"})
                self.assertEqual((code, data["committed"]), (2, False), (bad, data))
                self.assertIn("temp", data["errors"][0]["problem"])
                self.assertFalse(Path(bad).exists(), bad)

    def test_case_aliases_of_a_temp_dir_are_refused(self):  # finding 11
        unique = f"hm-{uuid.uuid4().hex}"
        aliases = ["/PRIVATE/TMP", "/Private/tmp", "/private/TMP", "/private/VAR/tmp", "/TMP", "/VAR/tmp"]
        live = [a for a in aliases if os.path.exists(a)]
        if not live:
            self.skipTest("a case-sensitive volume: these paths are simply not temp dirs here")
        with tempfile.TemporaryDirectory() as d:
            repo = fresh_repo(d)
            for alias in live:
                bad = f"{alias}/{unique}/y"
                code, data = cli(*CMD, "--commit", "--repo", str(repo), work=bad, script=REAL)
                self.assertEqual(code, 2, (bad, data))
                self.assertIn("temp", data["errors"][0]["problem"])
                self.assertFalse(Path(bad).exists(), bad)

    def test_another_owner_is_refused(self):  # K3
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / "w"
            work.mkdir(mode=0o700)
            with unittest.mock.patch.dict(os.environ, {"HARNESS_WORK_DIR": str(work)}), unittest.mock.patch.object(cm, "_temp_roots", set):
                self.assertEqual(cm.work_dir(), work)
                with unittest.mock.patch.object(os, "getuid", return_value=os.getuid() + 1), self.assertRaisesRegex(ValueError, "owned by you"):
                    cm.work_dir()

    def test_work_dir_rules(self):
        with tempfile.TemporaryDirectory() as d:
            repo = fresh_repo(d)
            base = [*CMD, "--commit", "--repo", str(repo)]
            code, data = cli(*base, work="relative/dir")
            self.assertEqual(code, 2, data)
            self.assertIn("absolute", data["errors"][0]["problem"])
            shared = Path(d) / "shared"
            shared.mkdir()
            os.chmod(shared, 0o755)
            code, data = cli(*base, work=shared)
            self.assertEqual(code, 2)
            self.assertEqual(oct(shared.stat().st_mode & 0o777), "0o755")  # refused, not chmod-ed
            link = Path(d) / "link"
            link.symlink_to(shared)
            code, data = cli(*base, work=link)
            self.assertEqual(code, 2)
            self.assertIn("symlink", data["errors"][0]["problem"])
            ro = Path(d) / "ro"
            ro.mkdir(mode=0o500)
            code, data = cli(*base, work=ro / "w")
            self.assertEqual(code, 2, data)
            self.assertIn("work directory", data["errors"][0]["problem"])
            ro.chmod(0o700)


class EvidenceForms(unittest.TestCase):
    """Findings 6, 7, 8: there is no prose detection. Evidence is two fields, 'not run:', or `cmd`: result."""

    def test_real_commands_pass_as_the_command_field(self):  # finding 7
        for command in ("make", "make all", "pytest -k all", "python3 run.py all", "./test.sh", "cargo", "FOO=1 make test", "cd sub && make test",
                        "bin/rails test", "cmake --build .", "rspec spec/", "shellcheck a.sh", "sudo make test", "npm test -- --grep fine",
                        "grep '<title>' page.html", "python3 -m unittest", "python3.11 -m pytest", "/usr/bin/make test", "../run.sh",
                        "make test | tail -3", "make test > out.txt 2>&1", "timeout 60 make test", "sudo -u bob make test", "(cd a && make)",
                        "bash -c 'make test'", "node --test", "node test.js", "ssh dev2 'cd x && make'", "uv run pytest"):
            r = build(testing_command=command, testing_result="9 passed")
            self.assertTrue(r["ok"], (command, r["errors"]))
            self.assertIn(f"Testing: `{command}`: 9 passed\n", r["message"])
            self.assertEqual(cp.validate(r["message"], policy=POLICY), [])

    def test_things_without_a_commands_shape_are_refused(self):  # finding 6
        for command in ("I eyeballed it", "tests pass", "looked at it", "python was not run", "node looks fine", "bash: ok", "python3", "make: ok",
                        "FOO=1", "n/a", "sudo was not run", "sudo", "make test && looks good", "unbalanced 'quote", "tests/", "$ make test", "a `b` c"):
            r = build(testing_command=command, testing_result="ok")
            self.assertFalse(r["ok"], command)
            self.assertEqual(r["errors"][0]["field"], "Testing", command)
            self.assertIn("--testing-command", r["errors"][0]["fix"] + r["errors"][0]["problem"], command)

    def test_the_stated_limit_shape_is_not_truth(self):  # finding 6, challenged in the docstring
        for syntactically_valid in ("make tests pass", "npm is happy", "git looks"):
            self.assertTrue(build(testing_command=syntactically_valid, testing_result="ok")["ok"], syntactically_valid)

    def test_unwrapped_text_is_always_refused_with_the_fix(self):  # findings 6 and 8
        for text in ("make sure: ok", "go through: ok", "git looks: ok", "make tests pass: ok", "docker looked great: ok", "python was not run: ok",
                     "npm is happy: ok", "python3 -m unittest: 14 passed", "python3 -m unittest -> 14 passed", "make FOO=a->b test -> ok",
                     "curl -H Accept: application/json http://x: 200 ok", "make test -> ok, npm test -> ok", "make FOO: BAR test: ok",
                     "make test: ok; npm test: ok", "make: ok", "not run because docs", "pytest passed"):
            r = testing(text)
            self.assertFalse(r["ok"], text)
            self.assertIsNone(r["message"])
            self.assertEqual(r["errors"][0]["field"], "Testing", text)
            self.assertIn("--testing-command", r["errors"][0]["fix"], text)

    def test_backticked_evidence_passes_the_same_check(self):  # finding 6
        for text in ("`make test`: 9 passed", "`make test` -> 9 passed", "`make test` 9 passed", "`make test`: 9 passed; `npm test`: 3 passed",
                     "`curl -H Accept: application/json http://x`: 200 ok"):
            r = testing(text)
            self.assertTrue(r["ok"], (text, r["errors"]))
            self.assertIn(f"Testing: {text}\n", r["message"])
        for text in ("`I eyeballed it`: looks ok", "`tests`: pass", "`make test`", "`make test`: done", "ran `make test`: ok",
                     "`make test` and `npm test`: both ok", "`make test: ok", "`make test`: ok, see `the log`"):
            r = testing(text)
            self.assertFalse(r["ok"], text)
            self.assertEqual(r["errors"][0]["field"], "Testing", text)

    def test_the_result_must_state_a_result_on_its_own(self):
        r = build(testing_command="pytest -k ok", testing_result="it was run")
        self.assertFalse(r["ok"])
        self.assertIn("state the result", r["errors"][0]["problem"])

    def test_the_known_tools_include_every_tool_the_policy_names(self):
        names = cp.COMMAND_HINT.pattern.split("(?:python3?|")[1].split("|\\./)")[0].split("|")
        self.assertGreater(len(names), 30)
        self.assertLessEqual(set(names), cm.KNOWN_TOOLS | {"python3?"})


class Placeholders(unittest.TestCase):
    """Findings 7 and 9, against the list documented at TEMPLATE_PHRASES."""

    def test_refused(self):
        for why in ("< reason >", "<1 reason>", "{problem or motivation}", "[problem or motivation]", "<problem or motivation>",
                    "the <problem or motivation> here", "TODO write this sentence later", "FIXME before merging this",
                    "<problem@or motivation>", "problem or motivation", "<a> <b> <c> <d> <e>", "[some words go in here]"):
            r = build(why=why)
            self.assertFalse(r["ok"], why)
            self.assertEqual(r["errors"][0]["field"], "Why", why)
        for over in (dict(testing="not run: reason goes here", **TWO), dict(testing="not run: <reason>", **TWO), dict(refs="none (reason here)", ticket="", type="chore"),
                     dict(refs="none (<reason>)", ticket="", type="chore"), dict(testing_result="<result, e.g. 14 passed>"), dict(testing_command="<exact command>"),
                     dict(testing_command="make <target here>"), dict(summary="<imperative summary>")):
            self.assertFalse(build(**over)["ok"], over)

    def test_every_string_the_policy_template_and_ready_message_produce(self):
        template = cp.template("", POLICY)
        for line in template.split("\n"):
            _, _, value = line.partition(": ")
            if value:
                self.assertTrue(cm._placeholder(value), line)
        ready = cm.ready_message([], "", {}, POLICY)
        for word in ("<imperative summary>", "<problem or motivation>", "<key changes>", "<exact command>", "<result>", "<scope>", "<ticket number>"):
            self.assertIn(word, ready)
            self.assertTrue(cm._placeholder(word), word)

    def test_not_refused(self):
        for why in ("the Promise<void> return was dropped", "render rows in the <table> element", "a Map<String, Integer> overflowed",
                    "when x < 3 and y > 2 it breaks", "the a[0] and {b} values are lost", "mail <a@b.c> bounced on delivery",
                    "todo items were lost on restart", "<b>bold</b> text was not escaped"):
            r = build(why=why)
            self.assertTrue(r["ok"], (why, r["errors"]))
            self.assertIn(why, r["message"])
        self.assertTrue(build(what="<table>" + " rows are rendered")["ok"])
        self.assertTrue(build(testing_result="<b>3 passed</b>")["ok"])
        self.assertTrue(build(testing_command="grep '<title>' x.html")["ok"])
        self.assertTrue(build(testing_command="grep '<a b>' x.html")["ok"])

    def test_invisible_filler(self):  # finding 9
        for over in (dict(why="abcdefgh" + "ㅤ" * 20), dict(testing_result="ok ㅤㅤ"), dict(what="abcdefghijkl⠀⠀"),
                     dict(why="abcdefghijkl️️️")):
            r = build(**over)
            self.assertFalse(r["ok"], over)
            self.assertIn("invisible", r["errors"][0]["problem"])
        self.assertTrue(build(why="the warning ⚠️ was lost on restart")["ok"])


class FieldTypes(unittest.TestCase):
    """Finding 15 and O5: both builders scan, and a non-text value is refused rather than skipped."""

    def test_non_text_fields_are_refused_by_both_builders(self):
        for bad in (["a real looking reason"], {"a": "b"}, b"a real looking reason", 12345678, True):
            for builder, extra in ((cm.build_message, {}), (cm.build_pr, {"title": "fix(a): add b"})):
                r = builder({**GOOD, **extra, "why": bad}, POLICY)
                self.assertFalse(r["ok"], bad)
                self.assertIn("must be text", r["errors"][0]["problem"])

    def test_build_pr_scans_its_fields(self):  # O5
        for over in (dict(why="a reason <problem or motivation>"), dict(why="a real reason \x1b[31m here"), dict(why="x" * 5000), dict(why="abcdefgh" + "ㅤ" * 20)):
            r = cm.build_pr({**GOOD, "title": "fix(a): add b", **over}, POLICY)
            self.assertFalse(r["ok"], over)
            self.assertEqual(r["errors"][0]["field"], "Why", over)

    def test_ready_message_refuses_secret_looking_scope_and_ticket(self):  # O6
        for scope in ("secret", "token.x", "my-password"):
            self.assertIn("'<scope>'", cm.ready_message([], "x", {"scope": scope}, POLICY), scope)
        for ticket in ("GoodQA secret#12", "GoodQA token#12", "GoodQA passw#12"):
            self.assertIn("'<ticket number>'", cm.ready_message([], "x", {"ticket": ticket}, POLICY), ticket)
        self.assertIn("--ticket 'GoodQA goodqa#12'", cm.ready_message([], "x", {"ticket": "GoodQA goodqa#12"}, POLICY))


class Wiring(unittest.TestCase):
    def test_installed_with_the_hooks(self):
        import install
        for name in ("commit_message.py", "integrate_local.py", "redact.py", "process.py", "safe_input.py"):
            self.assertIn(name, install.HOOKS, name)


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


if __name__ == "__main__":
    unittest.main()
