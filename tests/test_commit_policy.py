"""Commit policy: table-driven validator, shell analysis, hooks, ranges, tickets, waivers."""

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import commit_policy as cp  # noqa: E402
import ticket_adapters  # noqa: E402

POLICY = cp.load_policy()
GOOD = """fix(deliver): refuse non-compliant commit ranges before publication

Why: an agent reverted two production auth fixes with no recorded reason.
What: prepare runs the commit policy over the owner range and blocks.
Testing: `python3 -m unittest tests.test_commit_policy` -> 42 passed
Refs: GoodQA #14151

Co-Authored-By: Claude <noreply@anthropic.com>"""
REVERT = """revert(auth): restore step-up flow removed without reason

Why: commit abc1234 removed OAuth step-up without an explanation.
What: restores the step-up and grant-org v2 changes on main.
Testing: `pnpm test auth` -> 88 passed
Refs: GoodQA #14151
Reason: the earlier revert had no reason and broke production login
Authorized-by: Eric, recorded in GoodQA #14159"""
CHORE = """chore(deps): bump the lockfile for the test runner

Why: the pinned runner has a known crash on Python 3.12 imports.
What: updates the lockfile only; no source or behaviour change.
Testing: not run: lockfile-only change, CI runs the suite
Refs: none (dependency bump with no tracked ticket)"""


def sub(text, old, new):
    assert old in text, old
    return text.replace(old, new, 1)


# (name, message, kwargs, expected problem substring). Each bad case is a single
# mutation of a GOOD message, so the passing GOOD control proves the mutation is
# what the validator rejects.
BAD = [
    ("no type", sub(GOOD, "fix(deliver): ", ""), {}, "subject: must be"),
    ("unknown type", sub(GOOD, "fix(", "bugfix("), {}, "is not one of"),
    ("missing scope", sub(GOOD, "fix(deliver)", "fix"), {}, "needs a lowercase (scope)"),
    ("too long", sub(GOOD, "before publication", "before publication " + "x" * 30), {}, "limit 72"),
    ("trailing period", sub(GOOD, "publication\n", "publication.\n"), {}, "no trailing period"),
    ("past tense", sub(GOOD, "refuse non", "refused non"), {}, "imperative"),
    ("boilerplate update", sub(GOOD, "refuse non-compliant commit ranges before publication", "update"), {}, "boilerplate"),
    ("wip", sub(GOOD, "refuse non-compliant commit ranges before publication", "wip"), {}, "boilerplate"),
    ("various fixes", sub(GOOD, "refuse non-compliant commit ranges before publication", "various fixes"), {}, "boilerplate"),
    ("no blank line", sub(GOOD, "publication\n\nWhy", "publication\nWhy"), {}, "second line must be blank"),
    ("missing why", sub(GOOD, "Why: an agent reverted two production auth fixes with no recorded reason.\n", ""), {}, "Why: section missing"),
    ("empty what", sub(GOOD, "What: prepare runs the commit policy over the owner range and blocks.", "What:"), {}, "What: empty"),
    ("placeholder why", sub(GOOD, "Why: an agent reverted two production auth fixes with no recorded reason.", "Why: various fixes"), {}, "placeholder"),
    ("short why", sub(GOOD, "Why: an agent reverted two production auth fixes with no recorded reason.", "Why: bug"), {}, "too short"),
    ("tests pass only", sub(GOOD, "`python3 -m unittest tests.test_commit_policy` -> 42 passed", "tests pass"), {}, "exact command"),
    ("result without command", sub(GOOD, "`python3 -m unittest tests.test_commit_policy` -> 42 passed",
                                   "ran the whole unit suite, 42 passed"), {}, "name the exact command"),
    ("command without result", sub(GOOD, " -> 42 passed", ""), {}, "state the result"),
    ("not run without reason", sub(GOOD, "`python3 -m unittest tests.test_commit_policy` -> 42 passed", "not run:"), {}, "concrete reason"),
    ("missing testing", sub(GOOD, "Testing: `python3 -m unittest tests.test_commit_policy` -> 42 passed\n", ""), {}, "Testing: section missing"),
    ("fix with refs none", sub(GOOD, "GoodQA #14151", "none (no ticket exists for it)"), {}, "must reference a ticket"),
    ("fix with only R ref", sub(GOOD, "GoodQA #14151", "R-000368"), {}, "R- coordinator records"),
    ("unrecognized refs", sub(GOOD, "GoodQA #14151", "see slack thread"), {}, "Refs: name a ticket"),
    ("out of order", sub(sub(GOOD, "Why: an agent", "What: an agent"), "What: prepare", "Why: prepare"), {}, "order"),
    ("trailer in body", sub(GOOD, "Refs: GoodQA #14151\n", "Signed-off-by: A <a@b.c>\nRefs: GoodQA #14151\n"), {}, "trailers"),
    ("duplicate of previous", GOOD, {"previous": GOOD}, "identical to the previous commit"),
    ("fixup on published", "fixup! fix(deliver): x", {"allow_autosquash": False}, "unpublished branch"),
    ("revert without reason", sub(REVERT, "Reason: the earlier revert had no reason and broke production login\n", ""), {}, "Reason"),
    ("revert without authorizer", sub(REVERT, "\nAuthorized-by: Eric, recorded in GoodQA #14159", ""), {}, "Authorized-by"),
    ("revert authorizer without ticket", sub(REVERT, "recorded in GoodQA #14159", "said so in chat"), {}, "cite the ticket"),
    ("disguised revert", sub(GOOD, "Why: an agent", "This reverts commit abc1234def.\nWhy: an agent"), {}, "this is a revert"),
    ("empty", "", {}, "empty commit message"),
    ("subject only", "fix(deliver): refuse non-compliant ranges", {}, "body: missing"),
]
GOOD_CASES = [
    ("good fix", GOOD, {}),
    ("good revert", REVERT, {}),
    ("good chore none", CHORE, {}),
    ("fix with refs none in untracked repo", sub(GOOD, "GoodQA #14151", "none (repo has no ticket system)"),
     {"tickets_required": False}),
    ("project ref", sub(GOOD, "GoodQA #14151", "GoodQA work-tracker-automatic#35652"), {}),
    ("multi-line sections", sub(GOOD, "What: prepare runs the commit policy over the owner range and blocks.",
                                "What:\n- prepare runs the policy over the owner range\n- finish posts ticket comments"), {}),
    ("git merge", "Merge branch 'side' into main", {}),
    ("merge in progress", "Merge side into main", {"is_merge": True}),
    ("fixup unpublished", "fixup! fix(deliver): x", {"allow_autosquash": True}),
    ("risk section", sub(GOOD, "Refs: GoodQA #14151\n", "Refs: GoodQA #14151\nRisk: none beyond a new publish gate; revert the commit.\n"), {}),
    ("breaking bang", sub(GOOD, "fix(deliver):", "fix(deliver)!:"), {}),
]


class Validator(unittest.TestCase):
    def test_good_messages_pass(self):
        self.assertGreater(len(GOOD_CASES), 5)
        for name, message, kwargs in GOOD_CASES:
            with self.subTest(name):
                self.assertEqual(cp.validate(message, policy=POLICY, **kwargs), [])

    def test_each_bad_mutation_is_rejected_for_its_reason(self):
        self.assertGreater(len(BAD), 20)
        for name, message, kwargs, expected in BAD:
            with self.subTest(name):
                problems = cp.validate(message, policy=POLICY, **kwargs)
                self.assertTrue(any(expected in item for item in problems), (name, problems))

    def test_off_and_template(self):
        self.assertIn("Why:", cp.template("wip", POLICY))
        self.assertTrue(cp.template(GOOD, POLICY).startswith("fix(deliver): refuse"))

    def test_pr_title_and_body(self):
        body = GOOD.split("\n", 2)[2]
        self.assertEqual(cp.validate_pr("fix(deliver): refuse non-compliant ranges", body, POLICY), [])
        problems = cp.validate_pr("fix(deliver): " + "y" * 60, "Reviewed scope.\n", POLICY)
        self.assertTrue(any("squash subject" in item for item in problems), problems)
        self.assertTrue(any("Why: section missing" in item for item in problems), problems)


def msg_hd(message):
    return "git commit -m \"$(cat <<'EOF'\n" + message + "\nEOF\n)\""


class ShellAnalysis(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cp-shell-")
        self.addCleanup(shutil.rmtree, self.dir)
        Path(self.dir, "msg.txt").write_text(GOOD)

    def messages(self, command):
        return [item[0] for item in cp.analyze(command, self.dir)]

    def test_extracts_every_supported_form(self):
        cases = {
            "git commit -m 'wip'": "wip",
            "git commit -qam 'wip'": "wip",
            "git commit -m'wip'": "wip",
            "git commit --message=wip": "wip",
            "git commit --mess wip": "wip",
            "git commit -m a -m 'b c'": "a\n\nb c",
            "git -C . -c core.editor=true commit -m x": "x",
            "cd /tmp && git add -A && git commit -m wip": "wip",
            "FOO=1 env BAR=2 git commit -m x": "x",
            "bash -lc \"git commit -m 'inner'\"": "inner",
            "git commit -F msg.txt": GOOD,
            "git commit --file=msg.txt": GOOD,
            "git commit -F - <<'EOF'\n" + GOOD + "\nEOF": GOOD,
            msg_hd(GOOD): GOOD,
            "git commit --fixup HEAD~1": "fixup! HEAD~1",
            "gh pr merge 3 --squash --subject 's' --body 'b'": "s\n\nb",
        }
        for command, expected in cases.items():
            with self.subTest(command):
                self.assertEqual(self.messages(command), [expected])

    def test_non_commit_commands_are_ignored(self):
        for command in ("grep -n 'git commit' x.py", "echo git commit -m wip", "git log --grep commit",
                        "git status && git diff", "python3 -c 'print(\"commit\")'", "gh pr merge 3 --merge",
                        "git commit --dry-run", "git revert --no-commit HEAD", "git merge --no-ff side"):
            with self.subTest(command):
                self.assertEqual(self.messages(command), [])

    def test_unresolvable_forms_fail_closed(self):
        for command in ('git commit -m "$MSG"', "git commit -m \"`cat m`\"", "git commit", "git commit --amend",
                        "git commit -F missing.txt", "git commit -F -", "git revert HEAD",
                        "git commit -m \"$(git log -1 --format=%B)\"", "eval git commit -m x",
                        "git commit -m \"$(cat <<EOF\n$HOME\nEOF\n)\"", "git commit -m 'unterminated",
                        "git commit-tree HEAD^{tree} -m x", "gh pr merge 3 --squash",
                        "git commit --allow-empty-message -m ''", "bash -c \"$CMD\" && git commit"):
            with self.subTest(command):
                with self.assertRaises(cp.Unresolvable):
                    cp.analyze(command, self.dir)


class RemoteShell(unittest.TestCase):
    """Most owner commits run on dev2/T2 through ssh from this Mac."""

    def analyze(self, command):
        return cp.analyze(command, "/tmp")

    def test_ssh_remote_commands_are_analyzed(self):
        cases = {
            "ssh dev2 'cd ~/r && git commit -m wip'": "wip",
            "ssh -o BatchMode=yes -p 22 eric@100.86.166.93 \"cd r && git commit -qam 'wip'\"": "wip",
            "ssh t2 'ssh dev2 \"git commit -m wip\"'": "wip",
            "ssh dev2 'bash -lc \"cd r && git commit -m wip\"'": "wip",
            "ssh dev2 bash -s <<'EOF'\ncd r && git commit -m wip\nEOF": "wip",
            "ssh dev2 'cd r && git commit -F - <<\"MSG\"\n" + GOOD + "\nMSG'": GOOD,
        }
        for command, expected in cases.items():
            with self.subTest(command):
                found = self.analyze(command)
                self.assertEqual([item[0] for item in found], [expected])
                self.assertTrue(found[0][2]["remote"])

    def test_ssh_without_commit_is_ignored(self):
        for command in ("ssh dev2 'git log -1'", "ssh dev2 uptime", "ssh dev2", "ssh -t dev2 'tmux attach'"):
            with self.subTest(command):
                self.assertEqual(self.analyze(command), [])

    def test_remote_message_sources_fail_closed(self):
        for command in ("ssh dev2 'cd r && git commit -F msg.txt'", "ssh dev2 'git commit --amend --no-edit'",
                        "ssh dev2 'git commit -C HEAD~1'", "ssh dev2 \"git commit -m $MSG\"",
                        "ssh dev2 'gh pr create --title t --body b'", "ssh dev2 'git commit'",
                        "ssh dev2 \"git commit -m \\\"$(cat <<'EOF'\nx `id`\nEOF\n)\\\"\""):
            with self.subTest(command):
                with self.assertRaises(cp.Unresolvable):
                    self.analyze(command)

    def test_remote_commits_require_tickets(self):
        none_fix = sub(GOOD, "GoodQA #14151", "none (no tracker for this repo)")
        code, text = cp.run_hook({"session_id": "s", "cwd": "/tmp", "tool_input": {
            "command": "ssh dev2 'cd r && git commit -F - <<\"EOF\"\n" + none_fix + "\nEOF'"}}, POLICY)
        self.assertEqual(code, 2, text)
        self.assertIn("must reference a ticket", text)


class AnalyzerFuzz(unittest.TestCase):
    SEED = 20261104

    def test_random_shell_never_crashes(self):
        import random
        rng = random.Random(self.SEED)
        pieces = ["git", "commit", "-m", "-F", "-", "'wip'", '"x"', "$(cat <<'EOF'", "EOF", ")", "\n", "&&", "|",
                  ";", "ssh", "dev2", "bash", "-lc", "<<", "'", '"', "\\", "$X", "`id`", "cd", "/tmp", "gh", "pr",
                  "create", "--amend", "--no-edit", "-C", "HEAD", "revert", "(", "#", "env", "A=1", "-am", "<<-X"]
        outcomes = {"found": 0, "unresolvable": 0}
        prefixes = ["", "git commit -m 'fix(x): y' ", "ssh dev2 'git commit -m z' ", "git commit -am ok "]
        for case in range(3000):
            command = rng.choice(prefixes) + " ".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
            try:
                if cp.analyze(command, "/nonexistent"):
                    outcomes["found"] += 1
            except cp.Unresolvable:
                outcomes["unresolvable"] += 1
            except Exception as error:  # pragma: no cover - failure path
                self.fail(f"seed {self.SEED} case {case}: {type(error).__name__} for {command!r}")
        self.assertGreater(outcomes["found"], 100, outcomes)
        self.assertGreater(outcomes["unresolvable"], 100, outcomes)


def git(*args, cwd, env=None):
    result = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError((args, result.stdout, result.stderr))
    return result.stdout.strip()


class Fixture(unittest.TestCase):
    """A temp HOME, global git config, and a repo with a tracked GitHub origin."""

    ORIGIN = "https://github.com/ericmacdougall/demo.git"

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="cp-fixture-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / "home"
        self.home.mkdir()
        self.gitconfig = self.root / "gitconfig"
        self.gitconfig.write_text("[user]\n\tname = T\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = main\n")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "CLAUDE", "CODEX", "AI_AGENT"))}
        self.env.update(HOME=str(self.home), GIT_CONFIG_GLOBAL=str(self.gitconfig), GIT_CONFIG_NOSYSTEM="1",
                        PYTHONDONTWRITEBYTECODE="1")
        self.repo = self.root / "repo"
        git("init", "-q", str(self.repo), cwd=self.root, env=self.env)
        git("remote", "add", "origin", self.ORIGIN, cwd=self.repo, env=self.env)
        self.commit(CHORE)
        self.wal = self.home / ".claude" / "wals" / "sess-1" / "main.jsonl"

    def commit(self, message, extra_env=None):
        path = self.root / "m.txt"
        path.write_text(message)
        return subprocess.run(["git", "commit", "-q", "--allow-empty", "-F", str(path)], cwd=self.repo,
                              env={**self.env, **(extra_env or {})}, capture_output=True, text=True, timeout=60)

    def run_cli(self, *args, stdin=None, extra_env=None):
        return subprocess.run([sys.executable, str(HOOKS / "commit_policy.py"), *args], input=stdin,
                              env={**self.env, **(extra_env or {})}, capture_output=True, text=True, timeout=60)


class PreToolUseHook(Fixture):
    def payload(self, command, **extra):
        return json.dumps({"session_id": "sess-1", "cwd": str(self.repo), "hook_event_name": "PreToolUse",
                           "tool_name": "Bash", "tool_input": {"command": command, "description": "x"},
                           "tool_use_id": "toolu_1", "transcript_path": "/tmp/t.jsonl", **extra})

    def test_claude_payloads(self):
        blocked = self.run_cli("hook", stdin=self.payload("git commit -m 'wip'"))
        self.assertEqual(blocked.returncode, 2, blocked.stderr)
        self.assertIn("Problems:", blocked.stderr)
        self.assertIn("Why: <the problem", blocked.stderr)
        self.assertIn("waive --wal", blocked.stderr)
        self.assertIn(str(self.wal), blocked.stderr)
        allowed = self.run_cli("hook", stdin=self.payload(msg_hd(GOOD)))
        self.assertEqual((allowed.returncode, allowed.stderr), (0, ""))
        unrelated = self.run_cli("hook", stdin=self.payload("ls -la && npm test"))
        self.assertEqual(unrelated.returncode, 0)
        dynamic = self.run_cli("hook", stdin=self.payload('git commit -m "$MSG"'))
        self.assertEqual(dynamic.returncode, 2)
        self.assertIn("cannot be checked", dynamic.stderr)

    def test_codex_payload_shapes(self):
        base = {"session_id": "codex-1", "cwd": str(self.repo), "hook_event_name": "PreToolUse", "model": "m",
                "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "c1",
                "transcript_path": None, "turn_id": "t1"}
        for tool_input in ({"command": "git commit -m wip"}, "git commit -m wip",
                           ["bash", "-lc", "git commit -m wip"], {"command": ["git", "commit", "-m", "wip"]},
                           {"chars": "git commit -m wip\n", "session_id": 3}):
            with self.subTest(tool_input):
                result = self.run_cli("hook", stdin=json.dumps({**base, "tool_input": tool_input}))
                self.assertEqual(result.returncode, 2, result.stderr)
        good = self.run_cli("hook", stdin=json.dumps({**base, "tool_input": ["bash", "-lc", msg_hd(GOOD)]}))
        self.assertEqual(good.returncode, 0, good.stderr)

    def test_amend_no_edit_validates_head_and_duplicate(self):
        self.commit(GOOD)
        same = self.run_cli("hook", stdin=self.payload(msg_hd(GOOD)))
        self.assertEqual(same.returncode, 2)
        self.assertIn("identical to the previous", same.stderr)
        amend = self.run_cli("hook", stdin=self.payload("git commit --amend --no-edit"))
        self.assertEqual(amend.returncode, 0, amend.stderr)
        git("commit", "-q", "--allow-empty", "-m", "wip", cwd=self.repo, env=self.env)
        bad_amend = self.run_cli("hook", stdin=self.payload("git commit --amend --no-edit"))
        self.assertEqual(bad_amend.returncode, 2)

    def test_ticket_rule_only_in_tracked_repos(self):
        none_fix = sub(GOOD, "GoodQA #14151", "none (no tracker for this repo)")
        self.assertEqual(self.run_cli("hook", stdin=self.payload(msg_hd(none_fix))).returncode, 2)
        git("remote", "set-url", "origin", "https://github.com/someone-else/x.git", cwd=self.repo, env=self.env)
        self.assertEqual(self.run_cli("hook", stdin=self.payload(msg_hd(none_fix))).returncode, 0)

    def test_waiver_needs_wal_record_and_ledger(self):
        command = "git commit -m 'emergency: wip'"
        blocked = self.run_cli("hook", stdin=self.payload(command))
        digest = cp.digest("emergency: wip")
        self.assertIn(digest, blocked.stderr)
        # Ledger-only forgery (no WAL record) is not a waiver.
        ledger = self.home / ".agent-harness" / "commit-policy" / "waivers.jsonl"
        ledger.parent.mkdir(parents=True)
        ledger.write_text(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "id": "f" * 16,
                                      "kind": "message", "subject": digest, "wal": str(self.wal)}) + "\n")
        self.assertEqual(self.run_cli("hook", stdin=self.payload(command)).returncode, 2)
        short = self.run_cli("waive", "--wal", str(self.wal), "--kind", "message", "--subject", digest,
                             "--reason", "too short")
        self.assertNotEqual(short.returncode, 0)
        waived = self.run_cli("waive", "--wal", str(self.wal), "--kind", "message", "--subject", digest,
                              "--reason", "production outage hotfix authorized by Eric in GoodQA #14151")
        self.assertEqual(waived.returncode, 0, waived.stderr)
        self.assertIn('"event":"waiver"', self.wal.read_text())
        self.assertEqual(self.run_cli("hook", stdin=self.payload(command)).returncode, 0)
        other = self.run_cli("hook", stdin=json.dumps({**json.loads(self.payload(command)), "session_id": "other"}))
        self.assertEqual(other.returncode, 2, "a waiver is bound to its own session")
        audit = json.loads(self.run_cli("report", "--since", "2026-01-01").stdout)
        self.assertEqual(audit["count"], 2)
        self.assertEqual(audit["missing_wal_record"], 1)


class GitHubRoute(Fixture):
    """gh pr create publishes wherever the commits were made: check the range on GitHub."""

    def fake_gh(self, commits):
        state = self.root / "compare.json"
        state.write_text(json.dumps({"total_commits": len(commits), "commits": [
            {"sha": f"{index:040x}", "parents": [{"sha": "0" * 40}],
             "commit": {"message": text, "author": {"date": "2026-11-04T05:00:00Z"},
                        "committer": {"date": "2026-11-04T05:00:00Z"}}} for index, text in enumerate(commits, 1)]}))
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / "gh"
        script.write_text("#!" + sys.executable + "\nimport sys\nargs=sys.argv[1:]\n"
                          "if '--jq' in args: print('main')\n"
                          f"elif 'compare/' in args[1]: print(open({str(state)!r}).read())\n"
                          "else: sys.exit(1)\n")
        script.chmod(0o755)
        return {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"]}

    def payload(self, command):
        return json.dumps({"session_id": "sess-1", "cwd": str(self.repo), "tool_input": {"command": command}})

    def test_pr_create_checks_range_and_text(self):
        bad = self.fake_gh([CHORE, "wip"])
        blocked = self.run_cli("hook", stdin=self.payload("gh pr create --draft"), extra_env=bad)
        self.assertEqual(blocked.returncode, 2, blocked.stderr)
        self.assertIn("PR blocked", blocked.stderr)
        good = self.fake_gh([CHORE])
        allowed = self.run_cli("hook", stdin=self.payload("gh pr create --draft"), extra_env=good)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        body = CHORE.split("\n", 2)[2]
        titled = self.run_cli("hook", stdin=self.payload(f"gh pr create --title 'Update' --body '{body}'"),
                              extra_env=good)
        self.assertEqual(titled.returncode, 2)
        self.assertIn("PR title/body", titled.stderr)
        bad = self.fake_gh([CHORE, "wip"])
        remote = self.run_cli("hook", stdin=self.payload(
            "ssh dev2 'cd r && gh pr create -R ericmacdougall/demo --head feat/x --base main --draft'"),
            extra_env=bad)
        self.assertEqual(remote.returncode, 2, remote.stderr)
        cli = self.run_cli("check-github", "--repo", "ericmacdougall/demo", "--base", "main", "--head", "feat/x",
                           extra_env=bad)
        self.assertEqual(cli.returncode, 2, cli.stdout + cli.stderr)

    def test_unpushed_branch_fails_closed(self):
        env = self.fake_gh([])
        (self.root / "bin" / "gh").write_text("#!/bin/sh\nexit 1\n")
        result = self.run_cli("hook", stdin=self.payload("gh pr create --draft"), extra_env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not be checked", result.stderr)


class PeerReviewGate(Fixture):
    def test_pr_review_refuses_noncompliant_range_before_spending(self):
        import peer_review
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(os.environ.__setitem__, "HOME", old)
        base = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)
        git("update-ref", "refs/remotes/origin/main", base, cwd=self.repo, env=self.env)
        self.assertEqual(self.commit(sub(CHORE, "bump the lockfile", "bump the second lockfile")).returncode, 0)
        self.assertEqual(peer_review.commit_policy_gate(self.repo, None), (0, ""))
        self.assertEqual(self.commit("wip").returncode, 0)
        code, text = peer_review.commit_policy_gate(self.repo, None)
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED", text)
        git("remote", "remove", "origin", cwd=self.repo, env=self.env)
        self.assertEqual(peer_review.commit_policy_gate(self.repo, None)[0], 0, "no origin: nothing to publish")


class GitBackstop(Fixture):
    def install_hook(self):
        git("config", "--global", "hook.agent-harness-commit-policy.event", "commit-msg", cwd=self.repo, env=self.env)
        git("config", "--global", "hook.agent-harness-commit-policy.command",
            cp.git_hook_command(HOOKS / "commit_policy.py"), cwd=self.repo, env=self.env)

    def test_backstop_scope_and_chaining(self):
        self.install_hook()
        hook = self.repo / ".git" / "hooks" / "commit-msg"
        hook.write_text("#!/bin/sh\necho REPO-HOOK >&2\n")
        hook.chmod(0o755)
        agent = {"CLAUDECODE": "1"}
        bad = self.commit("wip", agent)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("Problems:", bad.stderr)
        self.assertIn("REPO-HOOK", self.commit(sub(GOOD, "two production", "two prod"), agent).stderr)
        self.assertEqual(self.commit("wip", {"CODEX_THREAD_ID": "t"}).returncode, 1)
        self.assertEqual(self.commit("human wip").returncode, 0, "humans are never blocked")
        git("remote", "set-url", "origin", "file:///tmp/fixture.git", cwd=self.repo, env=self.env)
        self.assertEqual(self.commit("fixture wip", agent).returncode, 0, "untracked repos stay silent")

    def test_merge_exempt_only_with_merge_head(self):
        self.install_hook()
        agent = {**self.env, "CLAUDECODE": "1"}
        git("checkout", "-q", "-b", "side", cwd=self.repo, env=self.env)
        self.commit(sub(CHORE, "bump the lockfile", "bump the side lockfile"))
        git("checkout", "-q", "main", cwd=self.repo, env=self.env)
        git("merge", "-q", "--no-ff", "--no-commit", "side", cwd=self.repo, env=agent)
        merged = subprocess.run(["git", "commit", "-q", "-m", "Merge side into main"], cwd=self.repo, env=agent,
                                capture_output=True, text=True)
        self.assertEqual(merged.returncode, 0, merged.stderr)
        control = self.commit("Merge side into main", {"CLAUDECODE": "1"})
        self.assertEqual(control.returncode, 1, "without MERGE_HEAD the same text is not a merge")

    def test_missing_script_never_breaks_commits(self):
        copy = self.root / "hooks-copy"
        shutil.copytree(HOOKS, copy)
        git("config", "--global", "hook.agent-harness-commit-policy.event", "commit-msg", cwd=self.repo, env=self.env)
        git("config", "--global", "hook.agent-harness-commit-policy.command",
            cp.git_hook_command(copy / "commit_policy.py"), cwd=self.repo, env=self.env)
        self.assertEqual(self.commit("wip", {"CLAUDECODE": "1"}).returncode, 1)
        shutil.rmtree(copy)
        self.assertEqual(self.commit("wip", {"CLAUDECODE": "1"}).returncode, 0)


class FakeGoodQA:
    """Loopback MCP endpoint with scripted issues and comments."""

    def __init__(self):
        self.issues, self.comments, self.posted, self.fail = {}, {}, [], None
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["content-length"])))
                if outer.fail == "reset":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                if self.headers.get("authorization") != "Bearer test-key":
                    self.send_response(401)
                    self.end_headers()
                    return
                name, args = request["params"]["name"], request["params"]["arguments"]
                result, error = outer.handle(name, args)
                text = json.dumps(result if error is None else {"error": {"code": error}})
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}],
                                                                        "isError": error is not None}})
                payload = ("event: message\ndata: " + body + "\n\n").encode()
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/mcp"

    def handle(self, name, args):
        if name == "list_orgs":
            return {"orgs": [{"id": "org-1"}]}, None
        if name == "get_issue_by_number":
            issue = self.issues.get((args["projectSlug"], args["number"]))
            return (issue, None) if issue else (None, "not_found")
        if name == "get_issue_comments":
            items = sorted(self.comments.get(args["issueId"], []), key=lambda c: c["createdAt"], reverse=True)
            return {"comments": items, "hasMore": False, "nextCursor": None}, None
        if name == "comment_on_issue":
            if not any(p["operationId"] == args["operationId"] for p in self.posted):
                self.posted.append(args)
            return {"comment": {"id": "c"}}, None
        return None, "unknown_tool"

    def add_issue(self, number, project="goodqa"):
        issue_id = f"00000000-0000-4000-8000-{number:012d}"
        self.issues[(project, number)] = {"id": issue_id, "number": number, "title": f"Issue {number}", "status": "todo"}
        return issue_id

    def comment(self, issue_id, body, when):
        self.comments.setdefault(issue_id, []).append({"createdAt": when.isoformat().replace("+00:00", "Z"),
                                                       "body": body, "archivedAt": None})

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TicketVerification(Fixture):
    def setUp(self):
        super().setUp()
        self.fake = FakeGoodQA()
        self.addCleanup(self.fake.close)
        key = self.home / "member.key"
        key.write_text("test-key\n")
        key.chmod(0o600)
        self.policy = json.loads(json.dumps(POLICY))
        self.policy["ticket_systems"]["goodqa"].update(endpoint=self.fake.url, key_file=str(key), org_id=None,
                                                       attempts=2, timeout_seconds=5, total_deadline_seconds=20)
        self.base = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)
        self.issue = self.fake.add_issue(14151)
        self.assertEqual(self.commit(GOOD).returncode, 0)
        self.head = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)

    def check(self, **kwargs):
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        try:
            cp.LEDGER = self.home / ".agent-harness" / "commit-policy" / "waivers.jsonl"
            return cp.check_range(str(self.repo), self.base, self.head, self.policy, verify_tickets=True, **kwargs)
        finally:
            os.environ["HOME"] = old

    def test_states(self):
        stale = self.check()
        self.assertEqual(stale["status"], "BLOCKED")
        self.assertEqual(stale["tickets"][0]["status"], "STALE")
        self.assertIn(self.head[:12], stale["tickets"][0]["fix"])
        now = datetime.now(timezone.utc)
        self.fake.comment(self.issue, "unrelated note about deadbeefcafe", now)
        self.assertEqual(self.check()["status"], "BLOCKED", "a comment must name this commit")
        self.fake.comment(self.issue, f"Fixed in {self.head[:9]} on the branch", now)
        fresh = self.check()
        self.assertEqual((fresh["status"], fresh["tickets"][0]["status"]), ("PASS", "UPDATED"))

    def test_branch_comment_must_be_newer_than_commit(self):
        self.fake.comment(self.issue, "work continues on claude/x-1", datetime.now(timezone.utc) - timedelta(hours=3))
        self.assertEqual(self.check(branch="claude/x-1")["status"], "BLOCKED")
        self.fake.comment(self.issue, "pushed claude/x-1 for review", datetime.now(timezone.utc))
        self.assertEqual(self.check(branch="claude/x-1")["status"], "PASS")

    def test_missing_ticket_and_unreachable(self):
        self.fake.issues.clear()
        missing = self.check()
        self.assertEqual((missing["status"], missing["tickets"][0]["status"]), ("BLOCKED", "MISSING"))
        self.fake.fail = "reset"
        down = self.check()
        self.assertEqual((down["status"], down["tickets"][0]["status"]), ("UNVERIFIED", "UNVERIFIED"))
        self.assertIn("unreachable", down["tickets"][0]["error"])
        self.policy["ticket_systems"]["goodqa"]["endpoint"] = "http://127.0.0.1:9/none"
        self.assertEqual(self.check()["status"], "UNVERIFIED")

    def test_upstream_commits_are_excluded(self):
        upstream = self.head
        self.assertEqual(self.commit("wip upstream by someone").returncode, 0)
        bad_tip = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)
        self.assertEqual(self.commit(sub(CHORE, "bump the lockfile", "bump the owner lockfile")).returncode, 0)
        self.head = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)
        control = self.check()
        self.assertEqual(control["status"], "BLOCKED", "control: without exclusion the upstream wip is judged")
        excluded = self.check(exclude=[bad_tip])
        self.assertEqual(excluded["status"], "PASS", excluded)
        self.assertNotIn(upstream, [c["sha"] for c in excluded["commits"]])

    def test_legacy_cutover_uses_author_time(self):
        old = {"GIT_AUTHOR_DATE": "2026-10-01T00:00:00+00:00"}
        self.assertEqual(self.commit("old wip", old).returncode, 0)
        self.head = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)
        self.fake.comment(self.issue, f"see {self.head[:8]} and earlier", datetime.now(timezone.utc))
        report = self.check()
        legacy = [c for c in report["commits"] if c["subject"] == "old wip"][0]
        self.assertTrue(legacy["legacy"])
        self.policy["enforce_after"] = None
        self.assertEqual(self.check()["status"], "BLOCKED", "control: without the cutover the wip blocks")

    def test_notify_is_idempotent_and_labels_stage(self):
        for _ in range(2):
            results = cp.notify(str(self.repo), self.base, self.head, self.policy, operation_seed="gen-1",
                                evidence="- Check passed: `x`", stage="merged",
                                adapters={"goodqa": ticket_adapters.adapter_for(self.policy["ticket_systems"]["goodqa"])})
            self.assertEqual([r["status"] for r in results], ["COMMENTED"])
        self.assertEqual(len(self.fake.posted), 1)
        self.assertTrue(self.fake.posted[0]["body"].startswith("**Merged (not yet deployed or live)**"))
        cp.notify(str(self.repo), self.base, self.head, self.policy, operation_seed="gen-1", evidence="live",
                  stage="deployed")
        self.assertEqual(len(self.fake.posted), 2)
        self.fake.fail = "reset"
        failed = cp.notify(str(self.repo), self.base, self.head, self.policy, operation_seed="gen-2",
                           evidence="x")
        self.assertEqual(failed[0]["status"], "FAILED")

    def test_credential_file_must_be_private(self):
        key = Path(self.policy["ticket_systems"]["goodqa"]["key_file"])
        key.chmod(0o644)
        report = self.check()
        self.assertEqual(report["status"], "UNVERIFIED")
        self.assertIn("private", report["tickets"][0]["error"])
        self.assertNotIn("test-key", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
