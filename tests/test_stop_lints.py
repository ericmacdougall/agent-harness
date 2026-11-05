"""harness/hooks/stop_lints.py (rules W04, W06, W12, W17, S18, S26). Fixtures are data; git runs only in temp repos."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
        for msg in ("All the work is done.", "result: the migration shipped", "I've finished the change.",
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

    def test_uncommitted_tracked_change_warns_but_untracked_file_does_not(self):
        (self.repo / "new.txt").write_text("x")
        self.assertEqual(sl.lint_unpushed(str(self.repo)), [])
        (self.repo / "a.txt").write_text("changed")
        self.assertIn("1 tracked file(s)", sl.lint_unpushed(str(self.repo))[0])

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


if __name__ == "__main__":
    unittest.main()
