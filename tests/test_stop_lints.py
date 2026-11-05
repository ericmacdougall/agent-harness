"""harness/hooks/stop_lints.py (rules W04, W06, W12, W17, S18, S26). Fixtures are data; git runs only in temp repos."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import stop_lints as sl  # noqa: E402

SESSION = "11111111-2222-3333-4444-555555555555"
AGENT = "a0123456789abcdef"
MODES = {rule: "warn" for rule in sl.RULES}


def row(event, at, **kw):
    return {"at": f"2026-11-05T03:{at:02d}:00+00:00", "event": event, **kw}


def write_tool(at):
    return row("pretool", at, tool="Edit", agent_id=AGENT)


class WalFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.dir = self.home / ".claude" / "wals" / SESSION
        self.dir.mkdir(parents=True)

    def wal(self, rows, subagent=False):
        path = self.dir / (f"agent-{AGENT}.jsonl" if subagent else "main.jsonl")
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def lint(self, subagent=False, message="", **extra):
        payload = {"session_id": SESSION, "agent_id": AGENT, "agent_type": "task-owner", "cwd": str(self.home),
                   "last_assistant_message": message, **extra}
        return sl.run_lints(payload, subagent, MODES, self.home)


class IntentResult(WalFixture):  # W04
    def test_edit_with_no_intent_and_no_result_warns_twice(self):
        self.wal([write_tool(5)])
        out = self.lint()
        self.assertEqual(len([w for w in out if w.startswith("W04")]), 2, out)

    def test_intent_before_and_result_after_is_clean(self):
        self.wal([row("intent", 1, note="x"), write_tool(5), row("result", 9, note="ok")])
        self.assertEqual(self.lint(), [])

    def test_intent_after_the_edit_does_not_count(self):
        self.wal([write_tool(5), row("intent", 6, note="late"), row("result", 9)])
        out = self.lint()
        self.assertEqual([w[:4] for w in out], ["W04:"])
        self.assertIn("before the first edit", out[0])

    def test_result_before_the_last_edit_does_not_count(self):
        self.wal([row("intent", 1), write_tool(3), row("result", 4), write_tool(8)])
        out = self.lint()
        self.assertIn("after the last edit", out[0])

    def test_no_edits_means_no_warning_and_bash_alone_is_not_an_edit(self):
        self.wal([row("pretool", 1, tool="Bash")])
        self.assertEqual(self.lint(), [])

    def test_subagent_uses_its_own_wal_not_the_main_one(self):
        self.wal([row("intent", 1), write_tool(5), row("result", 9)])  # main is clean
        self.wal([write_tool(5)], subagent=True)  # the subagent's is not
        self.assertEqual(self.lint(), [])
        self.assertEqual(len(self.lint(subagent=True)), 2)


class PendingTests(WalFixture):  # W06
    def test_dangling_pending_id_warns_and_reconciled_one_does_not(self):
        self.wal([row("check", 1, note="PENDING_REAL_TEST r1: live restore"),
                  row("check", 2, note="PENDING_REAL_TEST r2: other"),
                  row("check", 3, note="REALLY_TESTED r1: ran it")])
        out = self.lint(subagent=False)
        self.assertEqual(len(out), 1)
        self.assertIn("r2", out[0])
        self.assertNotIn("r1,", out[0])

    def test_all_reconciled_is_clean(self):
        self.wal([row("check", 1, note="PENDING_REAL_TEST a-1: x"), row("check", 2, note="REALLY_TESTED a-1: y")])
        self.assertEqual(self.lint(), [])

    def test_many_ids_are_capped_in_the_message(self):
        self.wal([row("check", 1, note=f"PENDING_REAL_TEST id{i}: x") for i in range(20)])
        self.assertIn("(+12 more)", self.lint()[0])


class DoneClaims(WalFixture):  # W12
    def test_claim_without_a_cite_warns(self):
        for msg in ("All the work is done.", "The migration is shipped.", "I've finished the change.",
                    "done. nothing else to do"):
            self.assertEqual([w[:4] for w in self.lint(message=msg)], ["W12:"], msg)

    def test_claims_with_a_cite_are_clean(self):
        for msg in ("The work is done at commit 87312c0db9a3.", "result: done, see REALLY_TESTED r1",
                    "it is merged: https://github.com/o/r/pull/61", "all done, PR #61 is ready"):
            self.assertEqual(self.lint(message=msg), [], msg)

    def test_plain_status_text_is_not_a_claim(self):
        for msg in ("Still working on the parser; tests are running.", "The doctor reports 10 of 10 hooks wired.",
                    "I will finish this after the review.", ""):
            self.assertEqual(self.lint(message=msg), [], msg)

    def test_a_word_that_is_only_digits_or_only_letters_is_not_a_sha(self):
        self.assertEqual([w[:4] for w in self.lint(message="done. 12345678")], ["W12:"])
        self.assertEqual([w[:4] for w in self.lint(message="done. deadbeef is not it".replace("deadbeef", "abcdefabcdef"))], ["W12:"])


class Chores(WalFixture):  # W17
    def test_chore_requests_warn(self):
        for msg in ("You will need to run the installer.", "Please restart the app and click Allow.",
                    "You must install the CLI first.", "Can you sign in to GoodQA?", "Then manually edit the file."):
            self.assertEqual([w[:4] for w in self.lint(message=msg)], ["W17:"], msg)

    def test_chore_with_a_stated_reason_or_no_chore_is_clean(self):
        for msg in ("You need to approve the prompt: no agent-doable path exists, only you can sign in.",
                    "The tests pass and I restarted the service myself.", "Run `make test` to see it (I already did)."):
            self.assertEqual(self.lint(message=msg), [], msg)


class RedTeam(WalFixture):  # S26
    def test_red_team_report_needs_worst_case_and_bound(self):
        none = self.lint(subagent=True, agent_type="red-team", message="Verdict BLOCK. Finding 1 ...")
        self.assertEqual([w[:4] for w in none], ["S26:"])
        self.assertIn("Worst-case or Bound", none[0])
        only = self.lint(subagent=True, agent_type="red-team", message="Worst-case: 55 short processes.")
        self.assertIn("no Bound", only[0])
        ok = self.lint(subagent=True, agent_type="red-team", message="Probe: worst case a 4 MB input. Bound: 120 s.")
        self.assertEqual(ok, [])

    def test_other_agent_types_and_the_main_session_are_not_checked(self):
        self.assertEqual(self.lint(subagent=True, agent_type="fixer", message="Verdict BLOCK."), [])
        self.assertEqual(self.lint(subagent=False, agent_type="red-team", message="Verdict BLOCK."), [])


def run_git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args], check=True,
                   capture_output=True, text=True)


class Unpushed(unittest.TestCase):  # S18
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.remote, self.repo = root / "remote.git", root / "repo"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        (self.repo / "a.txt").write_text("1")
        run_git(self.repo, "add", "a.txt")
        run_git(self.repo, "commit", "-q", "-m", "one")
        run_git(self.repo, "remote", "add", "origin", str(self.remote))
        run_git(self.repo, "push", "-q", "origin", "main")

    def test_pushed_clean_repo_is_clean(self):
        self.assertEqual(sl.lint_unpushed(str(self.repo)), [])

    def test_unpushed_commit_warns_with_branch_and_count(self):
        (self.repo / "a.txt").write_text("2")
        run_git(self.repo, "commit", "-q", "-am", "two")
        out = sl.lint_unpushed(str(self.repo))
        self.assertEqual(len(out), 1)
        self.assertIn("1 commit(s) on main", out[0])

    def test_uncommitted_changes_are_deliberately_not_checked_and_status_never_runs(self):
        (self.repo / "new.txt").write_text("x")
        (self.repo / "a.txt").write_text("changed")
        calls = []
        real = subprocess.run

        def spy(cmd, *a, **k):
            calls.append(cmd)
            return real(cmd, *a, **k)
        with mock.patch.object(subprocess, "run", spy):
            self.assertEqual(sl.lint_unpushed(str(self.repo)), [])
        self.assertTrue(calls)
        self.assertFalse(any("status" in c or "diff-index" in c or "diff-files" in c for c in calls), calls)
        self.assertTrue(all(c[0] == "git" for c in calls))

    def test_git_is_run_without_lazy_fetch_and_with_a_clean_environment(self):
        seen = []
        real = subprocess.run

        def spy(cmd, *a, **k):
            seen.append(k.get("env"))
            return real(cmd, *a, **k)
        with mock.patch.object(subprocess, "run", spy), mock.patch.dict(os.environ, {"GIT_DIR": "/nonexistent", "GIT_EXTERNAL_DIFF": "x"}):
            sl.lint_unpushed(str(self.repo))
        self.assertTrue(seen)
        for env in seen:
            self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
            self.assertFalse([k for k in env if k.startswith("GIT_") and k not in ("GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS",
                                                                                    "GIT_NO_LAZY_FETCH")])

    def test_not_a_repo_or_missing_dir_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(sl.lint_unpushed(d), [])
        self.assertEqual(sl.lint_unpushed("/nonexistent/dir"), [])
        self.assertEqual(sl.lint_unpushed(""), [])


class FailOpenAndPolicy(WalFixture):
    def hook(self, argv, raw, home=None):
        env = {**os.environ, "HOME": str(home or self.home)}
        return subprocess.run([sys.executable, "-I", str(ROOT / "harness" / "hooks" / "stop_lints.py"), *argv],
                              input=raw, capture_output=True, text=True, timeout=30, env=env)

    def test_garbage_input_prints_nothing_and_exits_zero(self):
        for raw in ("not json", "", "[1]", "null", "{" * 5000):
            r = self.hook(["stop"], raw)
            self.assertEqual((r.returncode, r.stdout), (0, ""), raw[:10])

    def test_bad_arguments_exit_three(self):
        self.assertEqual(self.hook([], "{}").returncode, 3)
        self.assertEqual(self.hook(["nope"], "{}").returncode, 3)

    def test_unsafe_session_and_agent_ids_read_no_wal(self):
        self.assertIsNone(sl.wal_path({"session_id": "../../etc"}, False, self.home))
        self.assertIsNone(sl.wal_path({"session_id": SESSION, "agent_id": "../x"}, True, self.home))
        self.assertEqual(sl.read_wal(None), [])

    def test_symlinked_wal_is_not_followed(self):
        target = self.home / "elsewhere.jsonl"
        target.write_text(json.dumps(write_tool(5)) + "\n")
        (self.dir / "main.jsonl").symlink_to(target)
        self.assertEqual(self.lint(), [])

    def test_end_to_end_warning_json_and_no_message_text_is_echoed(self):
        self.wal([write_tool(5)])
        secret = "sk-live-QRSTUVWXYZ-token"
        msg = f"All done. You will need to run the installer with token {secret}."
        r = self.hook(["stop"], json.dumps({"session_id": SESSION, "cwd": str(self.home), "last_assistant_message": msg}))
        out = json.loads(r.stdout)["systemMessage"]
        self.assertTrue(all(rule in out for rule in ("W04", "W12", "W17")), out)
        self.assertNotIn(secret, out)
        self.assertNotIn("installer", out)

    def test_clean_session_prints_nothing(self):
        self.wal([row("intent", 1), write_tool(5), row("result", 9)])
        r = self.hook(["stop"], json.dumps({"session_id": SESSION, "cwd": str(self.home),
                                            "last_assistant_message": "Still working."}))
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_modes_can_turn_a_lint_off_and_bad_policy_keeps_warn(self):
        policy = self.home / "p.json"
        policy.write_text(json.dumps({"modes": {"W12": "off", "W04": "enforce", "ZZ": "off"}}))
        modes = sl.load_modes(policy)
        self.assertEqual((modes["W12"], modes["W04"]), ("off", "warn"))
        policy.write_text("{bad")
        self.assertEqual(sl.load_modes(policy), MODES)
        self.assertEqual(sl.load_modes(self.home / "missing.json"), MODES)

    def test_shipped_policy_names_every_rule_as_warn(self):
        shipped = json.loads((ROOT / "harness" / "hooks" / "stop_lints_policy.json").read_text())
        self.assertEqual(shipped["modes"], MODES)

    def test_transcript_fallback_reads_only_under_claude_projects(self):
        proj = self.home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        t = proj / "t.jsonl"
        t.write_text(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "All done."}]}}) + "\n")
        env_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        try:
            self.assertEqual(sl.tail_message(str(t)), "All done.")
            outside = self.home / "outside.jsonl"
            outside.write_text(t.read_text())
            self.assertEqual(sl.tail_message(str(outside)), "")
        finally:
            os.environ["HOME"] = env_home


class Wiring(unittest.TestCase):
    def test_installer_registers_both_groups_and_ships_the_files(self):
        import install
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        stop = [g for g in hooks["Stop"] if "stop_lints.py" in json.dumps(g)]
        sub = [g for g in hooks["SubagentStop"] if "stop_lints.py" in json.dumps(g)]
        self.assertEqual(len(stop), 1)
        self.assertEqual(len(sub), 1)
        self.assertEqual(sub[0]["matcher"], install.SUBAGENT_MATCHER)
        self.assertIn("stop_lints.py", install.HOOKS)
        self.assertIn("stop_lints_policy.json", install.HOOKS)
        self.assertIn("/h/.claude/hooks/stop_lints.py", install.managed_scripts(Path("/h/.claude")))

    def test_other_hooks_stay_registered(self):
        import install
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        self.assertTrue(any("wal.py" in json.dumps(g) for g in hooks["SubagentStop"]))
        self.assertTrue(any("provenance_hooks.py" in json.dumps(g) for g in hooks["Stop"]))

    def test_rules_map_to_the_hook_in_the_registry(self):
        rules = json.loads((ROOT / "harness" / "hooks" / "rules.json").read_text())
        rules = rules if isinstance(rules, list) else rules["rules"]
        by_id = {r["id"]: r for r in rules}
        manifest = {h["id"] for h in json.loads((ROOT / "harness" / "hooks" / "hooks_manifest.json").read_text())["hooks"]}
        for rule in sl.RULES:
            self.assertTrue(by_id[rule]["mechanisms"], rule)
            self.assertTrue(set(by_id[rule]["mechanisms"]) <= manifest, rule)


class ReviewRegressions(WalFixture):
    """Findings of the independent review of fc32011."""

    def test_blank_line_flood_is_linear_not_quadratic(self):  # F1
        import time
        for msg in ("\n" * 59990 + "all is done", " " * 59990 + "done.", "\n" * 59990 + "result:"):
            start = time.monotonic()
            sl.lint_done_claim(msg)
            self.assertLess(time.monotonic() - start, 1.0, msg[-12:])

    def test_result_header_and_negations_are_not_done_claims(self):  # F3
        for msg in ("Result: BLOCK. Findings below.", "result: FAIL", "The tests are done running; 12 passed."):
            self.assertEqual(self.lint(message=msg), [], msg)

    def test_cite_must_name_an_id_not_just_the_word(self):  # F4
        self.assertEqual([w[:4] for w in self.lint(message="It is all done, no REALLY_TESTED evidence exists")], ["W12:"])
        self.assertEqual(self.lint(message="It is all done: REALLY_TESTED r1b recorded."), [])

    def test_pending_ids_ignore_prose_and_trailing_periods(self):  # F5
        self.wal([row("check", 1, note="a PENDING_REAL_TEST note; REALLY_TESTED T1: ok."),
                  row("check", 2, note="PENDING_REAL_TEST T1: x")])
        self.assertEqual(self.lint(), [])

    def test_main_stop_accepts_reallytested_recorded_in_an_owner_wal(self):  # F5
        self.wal([row("check", 1, note="PENDING_REAL_TEST own-1: x")])
        self.assertEqual(len(self.lint()), 1)
        self.wal([row("check", 2, note="REALLY_TESTED own-1: ran it")], subagent=True)
        self.assertEqual(self.lint(), [])

    def test_naive_timestamps_do_not_abort_the_other_lints(self):  # F6
        self.wal([{"at": "2026-11-05T03:01:00", "event": "intent"}, write_tool(5), row("result", 9),
                  row("check", 2, note="PENDING_REAL_TEST z9: x")])
        out = self.lint(message="All done.")
        self.assertTrue(any(w.startswith("W06") for w in out) and any(w.startswith("W12") for w in out), out)
        self.assertFalse(any(w.startswith("W04") for w in out), out)

    def test_curly_apostrophes_and_bound_wording(self):  # F8
        self.assertEqual([w[:4] for w in self.lint(message="You\u2019ll need to run the installer.")], ["W17:"])
        rt = dict(subagent=True, agent_type="red-team")
        self.assertIn("Bound", self.lint(message="Worst-case: x. We found an upper bound on nothing.", **rt)[0])
        self.assertEqual(self.lint(message="Worst-case: x. Bound: 5 s.", **rt), [])
        self.assertEqual(self.lint(message="Worst-case: x. Probes were bounded by 5 s.", **rt), [])


class UnpushedNoise(Unpushed):
    def test_repo_with_no_remote_is_skipped(self):  # F7
        run_git(self.repo, "remote", "remove", "origin")
        (self.repo / "a.txt").write_text("2")
        run_git(self.repo, "commit", "-q", "-am", "two")
        self.assertEqual(sl.lint_unpushed(str(self.repo)), [])

    def test_repo_config_that_names_commands_is_never_run(self):  # F2
        marker = Path(self.tmp.name) / "PWNED"
        run_git(self.repo, "config", "filter.x.clean", f"sh -c 'touch {marker}; cat'")
        (self.repo / ".gitattributes").write_text("a.txt filter=x\n")
        run_git(self.repo, "add", ".gitattributes")
        run_git(self.repo, "commit", "-q", "-m", "attrs")
        (self.repo / "a.txt").write_text("changed")
        marker.unlink(missing_ok=True)  # setup commands above may have run the filter themselves
        out = sl.lint_unpushed(str(self.repo))
        self.assertFalse(marker.exists())
        self.assertEqual(len(out), 1)  # the unpushed attrs commit is still reported


class SecondRound(WalFixture):
    """Findings of the delta review of cc3cff2."""

    def test_filter_in_worktree_config_is_never_run(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        remote, repo = root / "r.git", root / "repo"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        (repo / "f").write_text("1")
        run_git(repo, "add", "f")
        run_git(repo, "commit", "-q", "-m", "one")
        run_git(repo, "remote", "add", "origin", str(remote))
        run_git(repo, "push", "-q", "origin", "main")
        marker = root / "PWNED"
        run_git(repo, "config", "extensions.worktreeConfig", "true")
        (repo / ".git" / "config.worktree").write_text(f'[filter "ev"]\n\tclean = touch {marker}; cat\n')
        (repo / ".gitattributes").write_text("f filter=ev\n")
        run_git(repo, "add", ".gitattributes")
        run_git(repo, "commit", "-q", "-m", "attrs")
        run_git(repo, "push", "-q", "origin", "main")
        marker.unlink(missing_ok=True)
        (repo / "f").write_text("changed")
        self.assertEqual(sl.lint_unpushed(str(repo)), [])
        self.assertFalse(marker.exists())

    def test_user_level_git_config_does_not_switch_s18_off(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        repo = root / "repo"
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        remote = root / "r.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
        (repo / "f").write_text("1")
        run_git(repo, "add", "f")
        run_git(repo, "commit", "-q", "-m", "one")
        run_git(repo, "remote", "add", "origin", str(remote))
        (root / "gitconfig").write_text("[core]\n\tpager = less\n")
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(root / "gitconfig")}):
            self.assertIn("1 commit(s)", (sl.lint_unpushed(str(repo)) or [""])[0])

    def test_markdown_bound_declarations_count_but_upper_bound_does_not(self):
        rt = dict(subagent=True, agent_type="red-team")
        for good in ("Worst-case: x.\n**Bound**: 1 GB", "worst case x\n| Bound | 1GB |", "Worst-case: x. Bound (enforced): 1GB",
                     "Worst-case: x. Bound: 1GB", "Worst-case: x. Bound -- 5 s"):
            self.assertEqual(self.lint(message=good, **rt), [], good)
        self.assertIn("Bound", self.lint(message="Worst-case: x. Upper bound: 3", **rt)[0])

    def test_a_note_that_opens_a_pending_test_does_not_close_it(self):
        self.wal([row("check", 1, note="PENDING_REAL_TEST a1: will append REALLY_TESTED a1: after the run")])
        self.assertEqual(len(self.lint()), 1)
        self.wal([row("check", 1, note="PENDING_REAL_TEST a1: x"), row("check", 2, note="REALLY_TESTED a1: ran")])
        self.assertEqual(self.lint(), [])

    def test_more_real_cites_count(self):
        for msg in ("All done: PR 12 is open.", "It is all done at commit 1234567.", "all done, sha abcdef1"):
            self.assertEqual(self.lint(message=msg), [], msg)


class ThirdRound(WalFixture):
    def test_submodule_gitdir_config_filter_is_never_run(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        sub, sup, remote = root / "sm", root / "super", root / "r.git"
        for path in (sub, sup):
            subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
        (sub / "f.txt").write_text("1")
        (sub / ".gitattributes").write_text("* filter=f\n")
        run_git(sub, "add", "-A")
        run_git(sub, "commit", "-q", "-m", "sub")
        env = {**os.environ, "GIT_ALLOW_PROTOCOL": "file"}
        subprocess.run(["git", "-C", str(sup), "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "sm"],
                       check=True, capture_output=True, env=env)
        run_git(sup, "commit", "-q", "-m", "add sm")
        run_git(sup, "remote", "add", "origin", str(remote))
        run_git(sup, "push", "-q", "origin", "main")
        marker = root / "PWNED"
        cfg = next((sup / ".git" / "modules").glob("*/config"), sup / ".git" / "modules" / "sm" / "config")
        with open(cfg, "a") as fh:
            fh.write(f'[filter "f"]\n\tclean = touch {marker}; cat\n')
        (sup / "sm" / "f.txt").write_text("changed")
        marker.unlink(missing_ok=True)
        sl.lint_unpushed(str(sup))
        self.assertFalse(marker.exists())

    def test_a_note_can_close_one_id_and_open_another(self):
        self.wal([row("check", 1, note="PENDING_REAL_TEST a1: x"),
                  row("check", 2, note="REALLY_TESTED a1: ok; next PENDING_REAL_TEST a2: y"),
                  row("check", 3, note="REALLY_TESTED a2: ok")])
        self.assertEqual(self.lint(), [])
        self.wal([row("check", 1, note="PENDING_REAL_TEST a1: will append REALLY_TESTED a1: later")])
        self.assertEqual(len(self.lint()), 1)


class FourthRound(WalFixture):
    def test_prose_mentions_of_reallytested_never_close_an_id(self):
        for prose in ("REALLY_TESTED t1 NOT run, failed", "Still pending: REALLY_TESTED t1 is outstanding",
                      "reconcile: need REALLY_TESTED t1 before handoff"):
            self.wal([row("check", 1, note="PENDING_REAL_TEST t1: x"), row("check", 2, note=prose)])
            self.assertEqual(len(self.lint()), 1, prose)
        for good in ("REALLY_TESTED t1: ran make test, 12 passed", "ok; REALLY_TESTED t1: done", "x\nREALLY_TESTED t1: done"):
            self.wal([row("check", 1, note="PENDING_REAL_TEST t1: x"), row("check", 2, note=good)])
            self.assertEqual(self.lint(), [], good)

    def test_rules_registry_records_the_s18_gap(self):
        rules = json.loads((ROOT / "harness" / "hooks" / "rules.json").read_text())
        rules = rules if isinstance(rules, list) else rules["rules"]
        s18 = [r for r in rules if r["id"] == "S18"][0]
        self.assertIn("uncommitted", s18.get("partial_reason", ""))


class BoundedReads(unittest.TestCase):
    """The lints read the WAL, a transcript and the policy through safe_input: a window at most, never a FIFO."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_a_wal_over_the_cap_yields_only_whole_rows_from_the_tail(self):
        path = self.dir / "main.jsonl"
        pad = json.dumps({"event": "pad", "x": "y" * 900}) + "\n"
        last = json.dumps({"event": "last", "at": "2026-11-05T03:00:00+00:00"}) + "\n"
        with mock.patch.object(sl, "MAX_WAL", 5000):
            path.write_text(pad * 20 + last)
            rows = sl.read_wal(path)
        self.assertTrue(rows and rows[-1]["event"] == "last", rows[-1:] )
        self.assertLess(len(rows), 8)  # the head of the file was not read
        self.assertTrue(all(r["event"] in ("pad", "last") for r in rows))  # no half-cut first row survived as junk

    def test_a_fifo_wal_is_not_read(self):
        path = self.dir / "fifo.jsonl"
        os.mkfifo(path)
        self.assertEqual(sl.read_wal(path), [])

    def test_an_oversized_policy_file_falls_back_to_warn(self):
        path = self.dir / "policy.json"
        path.write_text(json.dumps({"modes": {"W04": "off"}, "pad": "x" * (sl.MAX_POLICY + 10)}))
        self.assertEqual(sl.load_modes(path)["W04"], "warn")
        small = self.dir / "small.json"
        small.write_text(json.dumps({"modes": {"W04": "off"}}))
        self.assertEqual(sl.load_modes(small)["W04"], "off")

    def test_missing_safe_input_fails_open(self):
        path = self.dir / "main.jsonl"
        path.write_text(json.dumps({"event": "x"}) + "\n")
        with mock.patch.object(sl, "safe_input", None):
            self.assertEqual(sl.read_wal(path), [])
            self.assertEqual(sl.load_modes(path)["W04"], "warn")


if __name__ == "__main__":
    unittest.main()
