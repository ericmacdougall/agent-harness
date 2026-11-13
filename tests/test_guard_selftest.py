"""goodqa#15876: `ah guard-selftest`, a sanctioned live test of a guard rule. It runs a FIXED table through the INSTALLED hook in
disposable repositories of its own. These tests drive the Python API with a variant hooks directory and a fake home, and the
command line for the refusals; nothing here executes caller text."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import guard_selftest as gs  # noqa: E402
import command_guard as cg  # noqa: E402

NONEXISTENT = "a" * 64


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.hooks = self.root / "hooks"
        shutil.copytree(HOOKS, self.hooks, ignore=shutil.ignore_patterns("__pycache__"))

    # helpers
    def digest(self, hooks=None):
        return gs.manifest_digest(gs.manifest(hooks or self.hooks))

    def run_it(self, hooks=None, policy=None, rule="bulk_staging", **kw):
        hooks = hooks or self.hooks
        if policy is None:
            policy = gs.policy_state(hooks)[0]
        return gs.run_selftest(rule, self.digest(hooks), policy, hooks_dir=hooks, home=self.home, cli=False, **kw)

    def edit(self, name, old, new):
        path = self.hooks / name
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def leftovers(self):
        parent = self.home / ".agent-harness" / "tmp"
        return sorted(p.name for p in parent.iterdir()) if parent.exists() else []

    def audit_rows(self):
        path = self.home / ".agent-harness" / "guard-selftest-audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class RunsTheFixedTable(Base):
    # AC-1, AC-2
    def test_a_clean_run_matches_every_case_in_warn_mode_and_removes_its_directory(self):
        result = self.run_it()
        self.assertEqual((result["ok"], result["exit_code"], result["mode"]), (True, 0, "warn"), json.dumps(result)[:900])
        self.assertEqual(len(result["cases"]), 7)
        self.assertTrue(all(c["ok"] for c in result["cases"]), result["cases"])
        bulk = [c for c in result["cases"] if "bulk" in c["label"] and "dirty original" in c["label"]]
        self.assertTrue(bulk and all("[bulk_staging/bulk-staging]" in c["stdout"] and c["stderr"] == "" for c in bulk))
        quiet = [c for c in result["cases"] if c["label"].startswith(("explicit", "bulk add in the linked", "bulk add in the clean", "bulk add in a plain"))]
        self.assertEqual(len(quiet), 4)
        self.assertTrue(all(c["stdout"] == "" and c["stderr"] == "" and c["exit"] == 0 for c in quiet))
        self.assertTrue(result["removed"])
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(result["policy"], "absent")
        self.assertEqual(result["manifest"]["digest"], self.digest())

    def test_an_enforce_policy_expects_exit_two_with_the_finding_on_stderr(self):
        (self.hooks / "command_guard_policy.json").write_text(json.dumps({"modes": {"bulk_staging": "enforce"}}))
        result = self.run_it()
        self.assertEqual((result["ok"], result["mode"]), (True, "enforce"), json.dumps(result)[:900])
        bulk = [c for c in result["cases"] if c["expected"].startswith("exit 2")]
        self.assertEqual(len(bulk), 3)
        self.assertTrue(all(c["exit"] == 2 and "[bulk_staging/bulk-staging]" in c["stderr"] for c in bulk))

    def test_an_unknown_mode_in_the_policy_is_refused_not_guessed(self):
        (self.hooks / "command_guard_policy.json").write_text(json.dumps({"modes": {"bulk_staging": "maybe"}}))
        result = self.run_it()
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("unknown mode", result["refused"])
        self.assertEqual(self.leftovers(), [])

    # AC-10, NEG-5, NEG-6
    def test_a_guard_without_the_rule_fails_the_bulk_cases(self):
        self.edit("command_guard.py", "        self.bulk_staging(sub, rest, cwd_words, locations, alias_values)\n", "        pass\n")
        result = self.run_it()
        self.assertEqual((result["ok"], result["exit_code"]), (False, 1))
        failed = {c["label"] for c in result["cases"] if not c["ok"]}
        self.assertEqual(len(failed), 3, failed)
        self.assertEqual(self.leftovers(), [])

    def test_a_guard_that_flags_an_explicit_path_fails_the_quiet_cases(self):
        self.edit("command_guard.py", "        if everything and not pathspecs:\n            return True", "        if True:\n            return True")
        result = self.run_it()
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(any(not c["ok"] and c["label"].startswith("explicit") for c in result["cases"]))

    def test_a_crashing_analyser_behind_the_real_launcher_fails_every_case_including_the_negative_ones(self):
        self.edit("command_guard.py", "if __name__ == '__main__':\n    sys.exit(main())", "if __name__ == '__main__':\n    raise SystemExit(1)")
        result = self.run_it()
        self.assertEqual((result["ok"], result["exit_code"]), (False, 1), json.dumps(result)[:600])
        self.assertTrue(all(not c["ok"] for c in result["cases"]), [(c["label"], c["exit"], c["stderr"][:60]) for c in result["cases"]])
        self.assertTrue(any("analyser" in c["stderr"] for c in result["cases"]))  # the launcher's fallback note is what we caught

    def test_an_analyser_that_prints_garbage_fails_every_case(self):
        self.edit("command_guard.py", "if __name__ == '__main__':\n    sys.exit(main())", "if __name__ == '__main__':\n    sys.stdout.write('not json')\n    raise SystemExit(0)")
        result = self.run_it()
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(all(not c["ok"] for c in result["cases"]))

    def test_an_analyser_that_hangs_fails_every_case_by_the_tools_own_timeout(self):
        self.edit("command_guard.py", "if __name__ == '__main__':\n    sys.exit(main())", "if __name__ == '__main__':\n    import time\n    time.sleep(60)")
        launcher = self.hooks / "command_guard_hook.py"
        launcher.write_text(launcher.read_text().replace("CHILD_TIMEOUT = 10.0", "CHILD_TIMEOUT = 600.0"))  # the launcher's own watchdog is "broken"
        with mock.patch.object(gs, "TIMEOUT", 3):
            result = self.run_it()
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(all(not c["ok"] and c["timed_out"] for c in result["cases"]),
                        [(c["exit"], c["timed_out"], c["stderr"][:200]) for c in result["cases"]][:2])


class Evaluate(unittest.TestCase):
    # D3: the channels of the real hook, and a launcher fallback note is a failure
    def got(self, exit=0, stdout="", stderr="", timed_out=False):
        return {"exit": exit, "stdout": stdout, "stderr": stderr, "timed_out": timed_out}

    def test_the_expected_channels(self):
        warn = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "x [bulk_staging/bulk-staging] y"}})
        self.assertTrue(gs.evaluate("bulk", "warn", self.got(stdout=warn)))
        self.assertTrue(gs.evaluate("bulk", "enforce", self.got(exit=2, stderr="blocked [bulk_staging/bulk-staging]")))
        self.assertTrue(gs.evaluate("quiet", "warn", self.got()))
        self.assertTrue(gs.evaluate("quiet", "enforce", self.got()))

    def test_a_fallback_note_a_timeout_garbage_or_the_wrong_channel_is_a_failure(self):
        warn = json.dumps({"hookSpecificOutput": {"additionalContext": "[bulk_staging/bulk-staging]"}})
        note = "command_guard: analyser crashed (exit 1); the command looked harmless and was allowed\n"
        self.assertFalse(gs.evaluate("quiet", "warn", self.got(stderr=note)))  # exit 0 plus a note: a broken analyser
        self.assertFalse(gs.evaluate("bulk", "warn", self.got(stdout=warn, stderr=note)))
        self.assertFalse(gs.evaluate("quiet", "warn", self.got(timed_out=True, exit=None)))
        self.assertFalse(gs.evaluate("bulk", "warn", self.got(stdout="not json")))
        self.assertFalse(gs.evaluate("bulk", "warn", self.got(exit=2, stderr="[bulk_staging/bulk-staging]")))  # a block where a warn is expected
        self.assertFalse(gs.evaluate("bulk", "warn", self.got(stderr="[bulk_staging/bulk-staging]")))  # the finding on the wrong channel
        self.assertFalse(gs.evaluate("bulk", "enforce", self.got(stdout=warn)))
        self.assertFalse(gs.evaluate("quiet", "warn", self.got(stdout=warn)))  # a finding where none is expected


class Pins(Base):
    # AC-3, NEG-4
    def refused(self, result):
        self.assertEqual((result["ok"], result["exit_code"]), (False, 3), json.dumps(result)[:400])
        self.assertEqual(self.leftovers(), [])
        self.assertFalse((self.home / ".agent-harness" / "tmp").exists())  # no private directory was even made
        return result["refused"]

    def test_a_wrong_manifest_or_policy_is_refused_and_nothing_runs(self):
        with mock.patch.object(gs, "run_hook", side_effect=AssertionError("a hook ran")):
            why = self.refused(gs.run_selftest("bulk_staging", NONEXISTENT, "absent", hooks_dir=self.hooks, home=self.home, cli=False))
            self.assertIn("manifest digest", why)
            why = self.refused(gs.run_selftest("bulk_staging", self.digest(), NONEXISTENT, hooks_dir=self.hooks, home=self.home, cli=False))
            self.assertIn("policy", why)
            (self.hooks / "command_guard_policy.json").write_text("{}")
            why = self.refused(gs.run_selftest("bulk_staging", self.digest(), "absent", hooks_dir=self.hooks, home=self.home, cli=False))
            self.assertIn("policy", why)

    def test_a_stale_launcher_or_a_stale_sibling_changes_the_manifest(self):
        names = [n for n, _b in gs.manifest(self.hooks)]
        self.assertIn("command_guard_hook.py", names)
        self.assertIn("command_guard.py", names)
        self.assertIn("redact.py", names)  # a sibling the guard imports
        expected = self.digest()
        for name in ("command_guard_hook.py", "redact.py"):
            path = self.hooks / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n# one byte more\n")
            self.assertNotEqual(self.digest(), expected, name)
            self.assertIn("manifest digest", self.refused(gs.run_selftest("bulk_staging", expected, "absent", hooks_dir=self.hooks, home=self.home, cli=False)))
            path.write_bytes(original)

    def test_a_data_file_named_by_a_string_literal_is_pinned_too(self):
        (self.hooks / "selftest_probe.json").write_text("{}")
        before = self.digest()
        self.edit("command_guard.py", "#!/usr/bin/env python3\n", "#!/usr/bin/env python3\n_PROBE = 'selftest_probe.json'\n")
        self.assertIn("selftest_probe.json", [n for n, _b in gs.manifest(self.hooks)])
        self.assertNotEqual(self.digest(), before)

    def test_unknown_rule_and_malformed_hashes_are_refused(self):
        with mock.patch.object(gs, "run_hook", side_effect=AssertionError("a hook ran")):
            for rule, manifest, policy in (("nope", self.digest(), "absent"), ("bulk_staging; touch /tmp/x", self.digest(), "absent"),
                                           ("bulk_staging", "XYZ", "absent"), ("bulk_staging", self.digest() + " extra", "absent"),
                                           ("bulk_staging", self.digest(), "present"), ("bulk_staging", self.digest().upper(), "absent")):
                with self.subTest((rule, manifest[:8], policy)):
                    self.refused(gs.run_selftest(rule, manifest, policy, hooks_dir=self.hooks, home=self.home, cli=False))

    # D2, AC-3: only the installed copy
    def test_a_command_line_run_refuses_unless_this_is_the_installed_copy(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(gs, "run_hook", side_effect=AssertionError("a hook ran")):
            code = gs.cli_main(["--rule", "bulk_staging", "--expect-manifest", self.digest(), "--expect-policy", "absent"])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 3)
        self.assertIn("not the installed copy", data["refused"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gs.cli_main(["--print-manifest"])
        self.assertEqual(code, 3)
        self.assertIn("not the installed copy", json.loads(out.getvalue())["refused"])

    def test_a_run_passes_the_installed_copy_check_when_the_real_path_is_the_installed_directory(self):
        fake_home = self.root / "fakehome"
        (fake_home / ".claude").mkdir(parents=True)
        os.symlink(str(HOOKS), str(fake_home / ".claude" / "hooks"))
        digest = gs.manifest_digest(gs.manifest(HOOKS))
        result = gs.run_selftest("bulk_staging", digest, gs.policy_state(HOOKS)[0], home=fake_home, cli=True)
        self.assertEqual((result["ok"], result["exit_code"]), (True, 0), json.dumps(result)[:900])
        self.assertEqual(result["hooks_dir"], os.path.realpath(str(HOOKS)))

    def test_the_home_is_the_user_record_not_the_environment(self):
        with mock.patch.dict(os.environ, {"HOME": str(self.root / "elsewhere")}):
            self.assertEqual(gs.user_home(), Path(__import__("pwd").getpwuid(os.getuid()).pw_dir))


class NoCallerCommandText(Base):
    # AC-4, NEG-1
    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(gs, "run_hook", side_effect=AssertionError("a hook ran")), \
                mock.patch.object(subprocess, "run", side_effect=AssertionError("a subprocess ran")):
            code = gs.cli_main(list(argv))
        return code, json.loads(out.getvalue())

    def test_every_other_argument_is_refused_and_runs_nothing(self):
        good = ["--rule", "bulk_staging", "--expect-manifest", NONEXISTENT, "--expect-policy", "absent"]
        for extra in (["--command", "git add -A"], ["--hooks-dir", "/tmp/evil"], ["--tmp", "/"], ["extra"], ["--help"], ["-x"]):
            with self.subTest(extra):
                code, data = self.cli(*good, *extra)
                self.assertEqual((code, data["ok"]), (3, False))
        for argv in (["--rule", "bulk_staging; touch /tmp/x", "--expect-manifest", NONEXISTENT, "--expect-policy", "absent"],
                     ["--rule", "../x", "--expect-manifest", NONEXISTENT, "--expect-policy", "absent"],
                     ["--rule", "bulk_staging", "--expect-manifest", NONEXISTENT + " x", "--expect-policy", "absent"],
                     ["--rule", "bulk_staging", "--expect-manifest", "$(id)", "--expect-policy", "absent"],
                     ["--rule", "bulk_staging"], ["--expect-manifest", NONEXISTENT], []):
            with self.subTest(argv):
                self.assertEqual(self.cli(*argv)[0], 3)

    def test_abbreviations_are_not_accepted(self):
        for flag in ("--exp", "--expect-m", "--expect-man", "--ru", "--print"):
            with self.subTest(flag):
                code, data = self.cli("--rule", "bulk_staging", flag, NONEXISTENT, "--expect-policy", "absent")
                self.assertEqual(code, 3)

    def test_the_child_argv_environment_cwd_and_payload_are_exactly_the_documented_ones(self):
        calls = []
        real = subprocess.run

        def spy(argv, **kw):
            calls.append((list(argv), kw))
            return real(argv, **kw)
        with mock.patch.object(subprocess, "run", spy):
            result = self.run_it()
        self.assertTrue(result["ok"])
        hooks = [c for c in calls if c[0][:2] == [sys.executable, "-I"]]
        self.assertEqual(len(hooks), 7)
        git = gs.trusted_git()
        for argv, kw in hooks:
            self.assertEqual(argv, [sys.executable, "-I", str((self.hooks.resolve()) / "command_guard_hook.py"), "hook"])
            self.assertEqual(set(kw["env"]), {"PATH", "HOME", "LANG"})
            self.assertEqual(kw["env"]["PATH"], "%s:/usr/bin:/bin" % os.path.dirname(git))
            self.assertEqual(kw["env"]["HOME"], str(self.home))
            self.assertEqual(kw["timeout"], gs.TIMEOUT)
            payload = json.loads(kw["input"].decode())
            self.assertEqual(set(payload), {"tool_name", "tool_input", "cwd"})
            self.assertEqual(payload["tool_name"], "Bash")
            self.assertEqual(set(payload["tool_input"]), {"command"})
            self.assertEqual(payload["cwd"], str(kw["cwd"]))
            self.assertNotIn("shell", kw)
        for argv, kw in calls:
            self.assertIsInstance(argv, list)  # no shell string anywhere
            self.assertFalse(kw.get("shell"))
        gits = [c for c in calls if c[0][0] == git]
        self.assertTrue(gits)
        for argv, kw in gits:
            self.assertEqual(argv[:3], [git, "-c", "core.hooksPath=/dev/null"])
            self.assertFalse([k for k in kw["env"] if k.startswith("GIT_") and k not in (
                "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")])
            self.assertEqual(kw["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(kw["env"]["GIT_CONFIG_NOSYSTEM"], "1")
        inits = [c for c in gits if c[0][7] == "init"]
        self.assertTrue(inits and all("--template=" in c[0] for c in inits), [c[0] for c in gits][:4])

    # NEG-2
    def test_a_hostile_environment_changes_nothing_that_runs(self):
        marker = self.root / "MARKER"
        fake_bin = self.root / "fakebin"
        fake_bin.mkdir()
        fake = fake_bin / "git"
        fake.write_text("#!/bin/sh\necho ran >> %s\nexit 1\n" % marker)
        fake.chmod(0o755)
        script = self.root / "evil.sh"
        script.write_text("#!/bin/sh\necho ran >> %s\n" % marker)
        script.chmod(0o755)
        template = self.root / "tmpl"
        (template / "hooks").mkdir(parents=True)
        (template / "hooks" / "post-commit").write_text("#!/bin/sh\necho ran >> %s\n" % marker)
        (template / "hooks" / "post-commit").chmod(0o755)
        hostile = {"PATH": "%s:%s" % (fake_bin, os.environ.get("PATH", "")), "GIT_EXEC_PATH": str(fake_bin), "GIT_SSH_COMMAND": str(script),
                   "GIT_EXTERNAL_DIFF": str(script), "GIT_ASKPASS": str(script), "GIT_TEMPLATE_DIR": str(template), "PAGER": str(script),
                   "GIT_CONFIG_GLOBAL": str(script), "PYTHONPATH": str(self.root), "PYTHONSTARTUP": str(script), "TMPDIR": str(self.root / "elsewhere"),
                   "GIT_PAGER": str(script), "EDITOR": str(script), "GIT_EDITOR": str(script)}
        (self.root / "elsewhere").mkdir()
        (self.root / "elsewhere" / "keep.txt").write_text("keep")
        with mock.patch.dict(os.environ, hostile):
            result = self.run_it()
        self.assertTrue(result["ok"], json.dumps(result)[:600])
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")
        self.assertEqual(sorted(p.name for p in (self.root / "elsewhere").iterdir()), ["keep.txt"])  # TMPDIR was ignored


class RemovesOnlyItsOwnDirectory(Base):
    # AC-5, NEG-3, NEG-8
    def private(self):
        return self.home / ".agent-harness" / "tmp"

    def test_a_sentinel_beside_the_directory_survives_and_the_parent_is_private(self):
        parent = self.private()
        parent.mkdir(parents=True, mode=0o700)
        (parent / "sentinel.txt").write_text("keep")
        (parent / "sentinel-dir").mkdir()
        (parent / "sentinel-dir" / "x").write_text("keep")
        self.assertTrue(self.run_it()["ok"])
        self.assertEqual(self.leftovers(), ["sentinel-dir", "sentinel.txt"])
        self.assertEqual(stat.S_IMODE(os.stat(parent).st_mode), 0o700)

    def test_a_symlink_swapped_in_for_the_directory_is_not_followed(self):
        victim = self.root / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep")

        def swap(home, name):
            path = self.private() / name
            moved = self.private() / (name + ".moved")
            os.rename(str(path), str(moved))
            os.symlink(str(victim), str(path))
        result = self.run_it(_before_cleanup=swap)
        self.assertEqual((victim / "precious.txt").read_text(), "keep")
        self.assertFalse(result["removed"])
        self.assertIn("not the one", result["cleanup_refused"])

    def test_a_symlink_planted_inside_is_unlinked_not_followed(self):
        victim = self.root / "victim2"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep")

        def plant(home, name):
            os.symlink(str(victim), str(self.private() / name / "link-out"))
        result = self.run_it(_before_cleanup=plant)
        self.assertTrue(result["removed"])
        self.assertEqual((victim / "precious.txt").read_text(), "keep")
        self.assertEqual(self.leftovers(), [])

    def test_an_interrupt_still_removes_the_directory_and_writes_the_audit_row(self):
        with mock.patch.object(gs, "run_hook", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_it()
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(len(self.audit_rows()), 1)

    def test_an_exception_inside_the_run_still_removes_the_directory_and_writes_the_audit_row(self):
        with mock.patch.object(gs, "run_hook", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.run_it()
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(len(self.audit_rows()), 1)

    def test_a_private_parent_with_the_wrong_mode_or_owner_is_refused_with_exit_four(self):
        parent = self.private()
        parent.mkdir(parents=True, mode=0o755)
        os.chmod(parent, 0o755)
        result = self.run_it()
        self.assertEqual(result["exit_code"], 4)
        self.assertIn("mode 0700", result["setup_failed"])

    def test_git_missing_is_exit_four_with_nothing_left(self):
        with mock.patch.object(gs, "GIT_CANDIDATES", ("/nonexistent/git",)):
            result = self.run_it()
        self.assertEqual(result["exit_code"], 4)
        self.assertEqual(self.leftovers(), [])


class Audit(Base):
    # AC-6
    def test_a_row_names_the_run_and_a_refusal_bounds_caller_values(self):
        self.assertTrue(self.run_it(session="s1", agent="agent-x")["ok"])
        row = self.audit_rows()[-1]
        self.assertEqual((row["verdict"], row["rule"], row["session"], row["agent"], row["cases"]), ("ok", "bulk_staging", "s1", "agent-x", 7))
        self.assertEqual(row["manifest"], self.digest())
        self.assertEqual(row["policy"], "absent")
        self.assertTrue(row["removed"])
        gs.run_selftest("x" * 500 + "\n\x00evil", "y" * 500, "z\x07" * 300, hooks_dir=self.hooks, home=self.home, cli=False)
        refused = self.audit_rows()[-1]
        self.assertEqual(refused["verdict"], "refused")
        for key in ("rule", "expect_manifest", "expect_policy", "reason"):
            self.assertLessEqual(len(refused[key]), 80)
            self.assertTrue(refused[key].isascii() and "\n" not in refused[key])
        mode = stat.S_IMODE(os.stat(self.home / ".agent-harness" / "guard-selftest-audit.jsonl").st_mode)
        self.assertEqual(mode, 0o600)

    def test_a_failed_audit_write_is_a_warning_and_does_not_change_the_verdict_or_leave_the_directory(self):
        with mock.patch.object(gs, "write_audit", side_effect=OSError("disk full")):
            result = self.run_it()
        self.assertTrue(result["ok"])
        self.assertIn("audit", result["audit_warning"])
        self.assertEqual(self.leftovers(), [])

    def test_a_symlinked_audit_file_is_not_followed(self):
        victim = self.root / "victim3.txt"
        victim.write_text("keep\n")
        folder = self.home / ".agent-harness"
        folder.mkdir(parents=True)
        os.symlink(str(victim), str(folder / "guard-selftest-audit.jsonl"))
        result = self.run_it()
        self.assertIn("audit_warning", result)
        self.assertEqual(victim.read_text(), "keep\n")


class Install(Base):
    # AC-7, AC-8
    def test_the_invocation_text_passes_the_installed_guard_for_main_and_a_sub_agent(self):
        compiled = cg.Compiled(cg.load_policy())
        command = "python3 -I ~/.claude/hooks/ah.py guard-selftest --rule bulk_staging --expect-manifest %s --expect-policy absent" % NONEXISTENT
        verdict = cg.decide(command, compiled, marker=cg.Approvals(compiled=compiled))[0]
        self.assertEqual(verdict, "allow")
        self.assertNotIn("git", command.replace("guard-selftest", ""))

    def test_the_module_is_in_both_install_lists_and_ah_imports_it_lazily(self):
        repo = HOOKS.parents[1]
        self.assertIn('"guard_selftest.py"', (repo / "install.py").read_text())
        self.assertIn("'guard_selftest.py'", (repo / "install_codex.py").read_text())
        source = (HOOKS / "ah.py").read_text()
        self.assertIn("import guard_selftest", source)
        self.assertEqual(source.count("import guard_selftest"), 1)
        head = source.split("def main(argv=None)")[0]
        self.assertNotIn("import guard_selftest", head)  # nothing at module import time

    def test_ah_without_the_module_fails_with_a_clear_message(self):
        import ah
        out = io.StringIO()
        real_import = __import__

        def fail(name, *a, **k):
            if name == "guard_selftest":
                raise ImportError("no module")
            return real_import(name, *a, **k)
        with contextlib.redirect_stdout(out), mock.patch("builtins.__import__", fail):
            code = ah.main(["guard-selftest", "--print-manifest"])
        self.assertEqual(code, 4)
        self.assertIn("not installed", json.loads(out.getvalue())["message"])

    def test_ah_routes_the_command_to_the_module(self):
        import ah
        with mock.patch.object(gs, "cli_main", return_value=0) as called:
            self.assertEqual(ah.main(["guard-selftest", "--print-manifest"]), 0)
        called.assert_called_once_with(["--print-manifest"])


if __name__ == "__main__":
    unittest.main()
