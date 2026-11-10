"""Commit policy: table-driven validator, shell analysis, hooks, ranges, tickets, waivers."""

import http.server
import json
import os
import shlex
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

os.environ["AGENT_HARNESS_POLICY_LOCAL"] = str(Path(__file__).resolve().parent / "data" / "policy_profile_fixture.json")  # hermetic profile (GoodQA #14538)
POLICY = cp.load_policy()

# Hermetic: no test may reach the real Secret Manager. A fake gcloud first on PATH fails and
# logs each call; tests that need a secret point GCLOUD_FAKE_KEY at a value.
FAKE_BIN = Path(tempfile.mkdtemp(prefix="cp-fake-bin-"))
GCLOUD_LOG = FAKE_BIN / "gcloud-calls.txt"
(FAKE_BIN / "gcloud").write_text(
    "#!/bin/sh\n"
    f"echo \"$*\" >> {shlex.quote(str(GCLOUD_LOG))}\n"
    "[ -z \"$GCLOUD_FAKE_STDERR\" ] || { echo \"$GCLOUD_FAKE_STDERR\" >&2; exit 3; }\n"
    "[ -n \"$GCLOUD_FAKE_KEY\" ] || exit 1\n"
    "printf '%s\\n' \"$GCLOUD_FAKE_KEY\"\n")
(FAKE_BIN / "gcloud").chmod(0o755)
os.environ["PATH"] = str(FAKE_BIN) + os.pathsep + os.environ["PATH"]
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
    ("merge-looking single parent", "Merge branch main into feat: rewrite auth", {}, "subject: must be"),
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
    ("git merge", "Merge branch 'side' into main", {"is_merge": True}),
    ("merge in progress", "Merge side into main", {"is_merge": True}),
    ("fixup unpublished", "fixup! fix(deliver): x", {"allow_autosquash": True}),
    ("risk section", sub(GOOD, "Refs: GoodQA #14151\n", "Refs: GoodQA #14151\nRisk: none beyond a new publish gate; revert the commit.\n"), {}),
    ("breaking bang", sub(GOOD, "fix(deliver):", "fix(deliver)!:"), {}),
]


_OFFLINE = None


def setUpModule():  # tests never call the ticket tracker; restored in tearDownModule so it cannot leak into other modules
    global _OFFLINE
    _OFFLINE = __import__("unittest.mock", fromlist=["patch"]).patch.dict(os.environ, {"HARNESS_PROVENANCE_OFFLINE": "1"})
    _OFFLINE.start()


def tearDownModule():
    _OFFLINE.stop()


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
        Path(self.dir, "m").write_text(GOOD)

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
            "bash <<'EOF'\ngit commit -m wip\nEOF": "wip",
            "sh -s <<'EOF'\ncd /tmp && git commit -m wip\nEOF": "wip",
            "bash -l -c 'git commit -m wip'": "wip",
            "bash -xc 'git commit -m wip'": "wip",
            "sh -euc 'git commit -m wip'": "wip",
            "if git diff --cached --quiet; then echo none; else git commit -m wip; fi": "wip",
            "for f in a; do git commit -m wip; done": "wip",
            "{ git add -A; git commit -m wip; }": "wip",
            "! git commit -m wip": "wip",
            "git commit --cleanup=verbatim -m wip": "wip",
            "bash -o pipefail -c 'git commit -m wip'": "wip",
            "bash --rcfile x -c 'git commit -m wip'": "wip",
            "bash +o posix -c 'git commit -m wip'": "wip",
            "nice -n 10 git commit -m wip": "wip",
            "timeout --signal KILL 30 git commit -m wip": "wip",
            "cat msg.txt && git commit -F msg.txt": GOOD,
            "printf x > other.txt && git commit -F msg.txt": GOOD,
            "cd /tmp && git commit -m wip > /dev/null": "wip",
            "cd /tmp && echo hi > out.txt && git commit -m wip": "wip",
            "git -C /tmp status > s.txt && git commit -m wip": "wip",
            "bash -euo pipefail -c 'git commit -m wip'": "wip",
            "bash -c -- 'git commit -m wip'": "wip",
            "ksh -c 'git commit -m wip'": "wip",
            "git commit -F m": GOOD,
            "git -C . commit -F msg.txt": GOOD,
            "git -C . add msg.txt && git -C . commit -F msg.txt": GOOD,
            "git -c core.quotepath=off commit -F msg.txt": GOOD,
            "GIT_AUTHOR_DATE=$(date) git commit -m wip": "wip",
            "git commit -m wip && sudo systemctl restart nginx": "wip",
            "bash -c 'cat <(echo hi)' && git -C . commit -F msg.txt": GOOD,
            "timeout 30 git commit -m wip": "wip",
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
                        "git commit --allow-empty-message -m ''", "bash -c \"$CMD\" && git commit",
                        "git -c alias.ci=commit ci -m wip", "xargs -I{} git commit -m {}",
                        "find . -name x -exec git commit -m wip \\;", "parallel git commit -m ::: a", "sudo -u eric git commit -m wip",
                        "cd \"$REPO\" && git commit -F msg.txt",
                        "printf 'wip\\n' > msg.txt && git commit -F msg.txt",
                        "git commit --cleanup=strip -m x", "git commit -e -m x", "git commit --edit -m x",
                        "env -S 'git commit -m wip'", "watch git commit -m wip",
                        "OUT=$(git commit -m 'wip' 2>&1)", "echo \"$(git commit -m wip)\"", "X=`git commit -m wip`",
                        "bash -O extglob script.sh commit", "cd \"$R\" && git ci -m wip",
                        "cp /tmp/m.txt msg.txt && git commit -F msg.txt",
                        "printf x | tee msg.txt && git commit -F msg.txt",
                        "printf x > \"$F\" && git commit -F msg.txt", "git history reword HEAD",
                        "sed -i '' 's/a/b/' msg.txt && git commit -F msg.txt",
                        "python3 -c \"open('msg.txt','w')\" && git commit -F msg.txt",
                        "echo wip >| msg.txt && git commit -F msg.txt", "truncate -s0 msg.txt && git commit -F msg.txt",
                        "git config alias.zz commit && git zz -m wip",
                        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.zz GIT_CONFIG_VALUE_0=commit git zz -m wip",
                        "echo 'git commit -m wip' | bash", "bash <<EOF\ngit commit -m $X\nEOF",
                        "G=git; $G commit -m wip", "$(echo git) commit -m wip",
                        "echo \"$(gi''t commit -m wip)\"",
                        "bash <<< 'git commit -m wip'", "bash <(echo 'git commit -m wip')",
                        "echo 'git commit -m wip' | sudo bash", "echo wip 1<>msg.txt && git commit -F msg.txt",
                        "git diff --output=msg.txt && git commit -F msg.txt",
                        "bash<<<\"git commit -m wip\"", "sh<<<'git commit -m wip'",
                        "rsync -a src/ ./ && git commit -F msg.txt"):
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
            "ssh -o BatchMode=yes -p 22 user@dev.example.invalid \"cd r && git commit -qam 'wip'\"": "wip",
            "ssh t2 'ssh dev2 \"git commit -m wip\"'": "wip",
            "ssh dev2 'bash -lc \"cd r && git commit -m wip\"'": "wip",
            "ssh dev2 bash -s <<'EOF'\ncd r && git commit -m wip\nEOF": "wip",
            "ssh -qi ~/.ssh/k dev2 git commit -m wip": "wip",
            "ssh -tp 22 dev2 'git commit -m wip'": "wip",
            "ssh -o BatchMode=yes -J t2 dev2 'git commit -m wip'": "wip",
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
                  "create", "--amend", "--no-edit", "-C", "HEAD", "revert", "(", "#", "env", "A=1", "-am", "<<-X",
                  ">", ">>", "out.txt", "tee", "cp", "|&", "<<<", "$(git", "`"]
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

    ORIGIN = "https://github.com/example-org/demo.git"

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
        # Range checks treat commits authored before the shipped enforce_after as legacy. Pin
        # fixture author dates after it so the tests do not depend on the wall clock.
        cutover = POLICY.get("enforce_after")
        if cutover and datetime.fromisoformat(cutover) > datetime.now(timezone.utc) - timedelta(hours=1):
            self.env["GIT_AUTHOR_DATE"] = (datetime.fromisoformat(cutover) + timedelta(hours=1)).isoformat()
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

    def test_inline_stdin_heredoc_runs_full_policy_in_same_invocation(self):
        command = "git add -A && git commit -F - <<'EOF'\n" + GOOD + "\nEOF"
        allowed = self.run_cli("hook", stdin=self.payload(command))
        self.assertEqual((allowed.returncode, allowed.stderr), (0, ""))

        missing_testing = GOOD.replace("Testing: `python3 -m unittest tests.test_commit_policy` -> 42 passed\n", "")
        blocked = self.run_cli("hook", stdin=self.payload("git commit -F - <<'EOF'\n" + missing_testing + "\nEOF"))
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("Testing: section missing", blocked.stderr)

        missing_ticket = GOOD.replace("GoodQA #14151", "none (no tracked ticket for this change)")
        blocked = self.run_cli("hook", stdin=self.payload("git commit -F - <<'EOF'\n" + missing_ticket + "\nEOF"))
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("must reference a ticket", blocked.stderr)

    def test_inline_stdin_heredoc_still_fails_closed(self):
        dynamic = self.run_cli("hook", stdin=self.payload("git commit -F - <<EOF\n" + GOOD + "\n$HOME\nEOF"))
        self.assertEqual(dynamic.returncode, 2)
        self.assertIn("cannot be checked", dynamic.stderr)
        malformed = self.run_cli("hook", stdin=self.payload("git commit -F - <<'EOF'\n" + GOOD))
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("unterminated heredoc", malformed.stderr)
        (self.repo / "msg.txt").write_text(GOOD)
        race = self.run_cli("hook", stdin=self.payload("printf x > msg.txt && git commit -F msg.txt"))
        self.assertEqual(race.returncode, 2)
        self.assertIn("same command", race.stderr)

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
        cutover = POLICY.get("enforce_after") or "2026-11-04T00:00:00+00:00"
        when = (datetime.fromisoformat(cutover) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        state.write_text(json.dumps({"total_commits": len(commits), "commits": [
            {"sha": f"{index:040x}", "parents": [{"sha": "0" * 40}],
             "commit": {"message": text, "author": {"date": when},
                        "committer": {"date": when}}} for index, text in enumerate(commits, 1)]}))
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / "gh"
        calls = self.root / "gh-calls.txt"
        body = ("import sys\nargs=sys.argv[1:]\n"
                f"open({str(calls)!r}, 'a').write(' '.join(args) + '\\n')\n"
                "if '--jq' in args: print('main')\n"
                f"elif 'compare/' in args[1]: print(open({str(state)!r}).read())\n"
                "else: sys.exit(1)\n")
        # Quote managed Python paths containing spaces; a direct macOS shebang cannot represent them.
        script.write_text("#!/bin/sh\nexec %s -c %s \"$@\"\n" % (shlex.quote(sys.executable), shlex.quote(body)))
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
            "ssh dev2 'cd r && gh pr create -R example-org/demo --head feat/x --base main --draft'"),
            extra_env=bad)
        self.assertEqual(remote.returncode, 2, remote.stderr)
        cli = self.run_cli("check-github", "--repo", "example-org/demo", "--base", "main", "--head", "feat/x",
                           extra_env=bad)
        self.assertEqual(cli.returncode, 2, cli.stdout + cli.stderr)
        fork = self.run_cli("check-github", "--repo", "example-org/demo", "--base", "main", "--head",
                            "someone:feat/x", "--no-tickets", extra_env=bad)
        self.assertEqual(fork.returncode, 2, fork.stdout + fork.stderr)
        self.assertIn("main...someone:feat/x", (self.root / "gh-calls.txt").read_text())

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


class InspectionRegressions(Fixture):
    def test_git_alias_in_config_fails_closed(self):
        git("config", "alias.ci", "commit", cwd=self.repo, env=self.env)
        with self.assertRaises(cp.Unresolvable):
            cp.analyze("git ci -m wip", str(self.repo))
        # Any non-built-in subcommand next to a commit is refused: the alias could be redefined
        # by the same command. Without a commit word the prefilter never runs analysis at all.
        with self.assertRaises(cp.Unresolvable):
            cp.analyze("git st && git log --grep commit", str(self.repo))
        self.assertEqual(cp.analyze("git log --grep commit", str(self.repo)), [])

    def test_unknown_repo_requires_tickets(self):
        none_feat = sub(GOOD, "GoodQA #14151", "none (no tracker reason given)")
        payload = {"session_id": "sess-1", "cwd": str(self.repo),
                   "tool_input": {"command": 'cd "$REPO" && ' + msg_hd(none_feat)}}
        code, text = cp.run_hook(payload, POLICY)
        self.assertEqual(code, 2, text)
        self.assertIn("must reference a ticket", text)

    def test_waiver_without_session_is_ignored(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(os.environ.__setitem__, "HOME", old)
        cp.LEDGER = self.home / ".agent-harness" / "commit-policy" / "waivers.jsonl"
        self.addCleanup(setattr, cp, "LEDGER", Path.home() / ".agent-harness" / "commit-policy" / "waivers.jsonl")
        digest = cp.digest("emergency: wip")
        self.wal.parent.mkdir(parents=True, exist_ok=True)
        cp.record_waiver(self.wal, "message", digest, "production outage hotfix authorized in GoodQA #14151", POLICY)
        with_session = {"session_id": "sess-1", "cwd": str(self.repo), "tool_input": {"command": "git commit -m 'emergency: wip'"}}
        self.assertEqual(cp.run_hook(with_session, POLICY)[0], 0)
        self.assertEqual(cp.run_hook({**with_session, "session_id": None}, POLICY)[0], 2)

    def test_bad_policy_file_only_affects_commits(self):
        copy = self.root / "hooks-bad"
        shutil.copytree(HOOKS, copy, ignore=shutil.ignore_patterns("__pycache__"))
        with open(copy / "commit_policy.json", "a") as handle:
            handle.write(",")
        def run(command, tool="Bash"):
            return subprocess.run([sys.executable, str(copy / "commit_policy.py"), "hook"], text=True,
                                  input=json.dumps({"session_id": "s", "cwd": str(self.repo), "tool_name": tool,
                                                    "tool_input": {"command": command}}),
                                  capture_output=True, env=self.env, timeout=60)
        self.assertEqual(run("ls -la && npm test").returncode, 0)
        broken = run("git commit -m wip")
        self.assertEqual(broken.returncode, 2)
        self.assertIn("enforcement", broken.stderr)

    def test_edit_tools_mentioning_commit_are_not_blocked(self):
        payload = {"session_id": "s", "cwd": str(self.repo), "tool_name": "apply_patch",
                   "tool_input": {"input": "*** docs: run git commit -m wip"}}
        self.assertEqual(cp.run_hook(payload, POLICY)[0], 0)
        self.assertEqual(cp.run_hook({**payload, "tool_name": "write_stdin"}, POLICY)[0], 2)

    def test_agent_markers_exclude_codex_home(self):
        self.assertIn("CODEX_TOOL_CALL_ID", cp.AGENT_MARKERS)
        self.assertNotIn("CODEX_HOME", cp.AGENT_MARKERS)


@unittest.skipUnless((cp.git_version() or (0, 0)) >= (2, 54),
                     "config-based hooks need git 2.54+ (dev2/T2 run 2.43); the backstop is inactive there")
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

    def test_amend_no_edit_passes_and_codex_home_is_not_an_agent(self):
        self.install_hook()
        agent = {**self.env, "CLAUDECODE": "1"}
        self.assertEqual(self.commit(GOOD, {"CLAUDECODE": "1"}).returncode, 0)
        amend = subprocess.run(["git", "commit", "-q", "--amend", "--no-edit", "--allow-empty"], cwd=self.repo,
                               env=agent, capture_output=True, text=True)
        self.assertEqual(amend.returncode, 0, amend.stderr)
        self.assertEqual(self.commit("person wip", {"CODEX_HOME": "/Users/x/.codex"}).returncode, 0)

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
        # AGENT_HARNESS_POLICY_LOCAL is inert for a script outside a source checkout
        # (_override_allowed), so give the copy the same profile as the production local
        # overlay beside the script: the backstop must be able to block before its
        # script goes missing, or the missing-script half proves nothing.
        shutil.copy(Path(__file__).resolve().parent / "data" / "policy_profile_fixture.json",
                    copy / cp.LOCAL_PROFILE_NAME)
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
        self.projects = {"goodqa"}
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
            if args["projectSlug"] not in self.projects:
                return None, "project_not_found"
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
        footer = cp.format_report(down)
        self.assertIn("could not be verified", footer)
        self.assertNotIn("reword", footer)
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

    def out_of_scope_head(self, slug="eric-app"):
        self.assertEqual(self.commit(sub(GOOD, "GoodQA #14151", f"GoodQA {slug}#7")).returncode, 0)
        self.head = git("rev-parse", "HEAD", cwd=self.repo, env=self.env)
        self.fake.comment(self.issue, f"see {self.head[:9]}", datetime.now(timezone.utc))
        self.base = git("rev-parse", "HEAD~1", cwd=self.repo, env=self.env)

    def test_unreachable_project_blocks_by_default(self):
        self.out_of_scope_head()
        self.policy["ticket_systems"]["goodqa"].pop("unreachable_projects", None)
        report = self.check()
        self.assertEqual((report["status"], report["tickets"][0]["status"]), ("UNVERIFIED", "UNVERIFIED"))
        self.assertIn("eric-app", report["tickets"][0]["error"])

    def test_unreachable_project_warns_with_logged_reason(self):
        self.out_of_scope_head()
        self.policy["ticket_systems"]["goodqa"].update(unreachable_projects=["eric-app"],
                                                       unreachable_reason="member key reaches ExampleOrg only")
        report = self.check()
        self.check()  # a second gate run on the same head must not add a second ledger row
        self.assertEqual((report["status"], report["tickets"][0]["status"]), ("PASS", "OUT_OF_SCOPE"))
        self.assertIn("ExampleOrg only", cp.format_report(report))
        ledger = self.home / ".agent-harness" / "commit-policy" / "warnings.jsonl"
        rows = [json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual([(r["kind"], r["ticket"], r["head"]) for r in rows],
                         [("ticket-out-of-scope", "goodqa:eric-app#7", self.head)])
        self.assertEqual([r["ticket"] for r in cp.list_warnings(datetime.now(timezone.utc) - timedelta(hours=1))],
                         ["goodqa:eric-app#7"])
        results = cp.notify(str(self.repo), self.base, self.head, self.policy, operation_seed="gen-oos",
                            evidence="x")
        self.assertEqual([r["status"] for r in results], ["OUT_OF_SCOPE"])
        self.assertEqual(self.fake.posted, [])

    def test_unlisted_or_default_project_stays_fail_closed(self):
        self.out_of_scope_head("no-such-project")
        self.policy["ticket_systems"]["goodqa"]["unreachable_projects"] = ["eric-app"]
        report = self.check()
        self.assertEqual((report["status"], report["tickets"][0]["status"]), ("UNVERIFIED", "UNVERIFIED"))
        for value in ("warn", "block", None):
            self.policy["ticket_systems"]["goodqa"]["unreachable_projects"] = value
            self.assertEqual(self.check()["status"], "UNVERIFIED", value)
        # The key's org changed: even the default project answers project_not_found.
        self.fake.projects.clear()
        self.policy["ticket_systems"]["goodqa"]["unreachable_projects"] = ["goodqa", "no-such-project"]
        self.base = git("rev-parse", "HEAD~2", cwd=self.repo, env=self.env)
        report = self.check()
        statuses = {t["ticket"]: t["status"] for t in report["tickets"]}
        self.assertEqual(statuses["goodqa:goodqa#14151"], "UNVERIFIED")
        self.assertEqual(report["status"], "UNVERIFIED")

    def test_warning_ledger_never_waits_on_a_fifo(self):
        self.out_of_scope_head()
        self.policy["ticket_systems"]["goodqa"]["unreachable_projects"] = ["eric-app"]
        ledger = self.home / ".agent-harness" / "commit-policy" / "warnings.jsonl"
        ledger.parent.mkdir(parents=True)
        os.mkfifo(ledger)
        result = {}
        worker = threading.Thread(target=lambda: result.update(report=self.check()), daemon=True)
        worker.start()
        worker.join(20)
        self.assertFalse(worker.is_alive(), "the gate hung opening a FIFO ledger")
        self.assertEqual(result["report"]["status"], "PASS")

    def test_missing_ticket_in_reachable_project_still_blocks_when_warning(self):
        self.policy["ticket_systems"]["goodqa"]["unreachable_projects"] = ["eric-app"]
        self.fake.issues.clear()
        report = self.check()
        self.assertEqual((report["status"], report["tickets"][0]["status"]), ("BLOCKED", "MISSING"))

    def secret_source(self, value):
        Path(self.policy["ticket_systems"]["goodqa"]["key_file"]).unlink()
        self.policy["ticket_systems"]["goodqa"]["key_secret"] = {"name": "goodqa-api-key-example",
                                                                  "project": "example-gcp-project"}
        if value is None:
            os.environ.pop("GCLOUD_FAKE_KEY", None)
        else:
            os.environ["GCLOUD_FAKE_KEY"] = value
        self.addCleanup(os.environ.pop, "GCLOUD_FAKE_KEY", None)
        GCLOUD_LOG.unlink(missing_ok=True)

    def test_secret_manager_key_verifies_tickets_read_only(self):
        self.secret_source("test-key")
        self.fake.comment(self.issue, f"Fixed in {self.head[:9]}", datetime.now(timezone.utc))
        before = sorted(str(path) for path in self.home.rglob("*"))
        report = self.check()
        self.assertEqual((report["status"], report["tickets"][0]["status"]), ("PASS", "UPDATED"))
        calls = GCLOUD_LOG.read_text()
        self.assertIn("secrets versions access latest --secret=goodqa-api-key-example --project=example-gcp-project",
                      calls)
        self.assertNotIn("test-key", calls, "the secret value never appears in argv")
        self.assertEqual(sorted(str(path) for path in self.home.rglob("*")), before, "nothing cached on disk")
        adapter = ticket_adapters.adapter_for(self.policy["ticket_systems"]["goodqa"])
        ticket = adapter.lookup("goodqa", 14151)
        for write in (lambda: adapter.comment(ticket, "x", "00000000-0000-4000-8000-000000000001"),
                      lambda: adapter.set_status(ticket, "done"),
                      lambda: adapter.call("create_issue", {})):
            with self.assertRaisesRegex(ticket_adapters.TicketSystemUnavailable, "read-only"):
                write()
        self.assertEqual(self.fake.posted, [], "no write reached GoodQA")
        results = cp.notify(str(self.repo), self.base, self.head, self.policy, operation_seed="gen-sm",
                            evidence="x", adapters={"goodqa": adapter})
        self.assertEqual([r["status"] for r in results], ["FAILED"])
        self.assertIn("read-only", results[0]["error"])

    def test_key_file_wins_and_unreadable_secret_fails_closed(self):
        self.secret_source(None)
        report = self.check()
        self.assertEqual(report["status"], "UNVERIFIED")
        self.assertIn("Secret Manager credential", report["tickets"][0]["error"])
        key = self.home / "member.key"
        key.write_text("test-key\n")
        key.chmod(0o600)
        GCLOUD_LOG.unlink(missing_ok=True)
        adapter = ticket_adapters.adapter_for(self.policy["ticket_systems"]["goodqa"])
        adapter.comment(adapter.lookup("goodqa", 14151), "y", "00000000-0000-4000-8000-000000000002")
        self.assertEqual(len(self.fake.posted), 1, "the member key file keeps write access")
        self.assertFalse(GCLOUD_LOG.exists(), "gcloud is not consulted when the key file exists")

    def test_secret_value_never_reaches_reports(self):
        self.secret_source(None)
        os.environ["GCLOUD_FAKE_STDERR"] = "leaked-secret-value-123"
        self.addCleanup(os.environ.pop, "GCLOUD_FAKE_STDERR", None)
        report = self.check()
        text = json.dumps(report) + cp.format_report(report)
        self.assertEqual(report["status"], "UNVERIFIED")
        self.assertIn("gcloud exit 3", report["tickets"][0]["error"])
        self.assertNotIn("leaked-secret-value-123", text)

    def test_missing_ticket_hint_names_project_qualified_form(self):
        self.fake.issues.clear()
        self.assertIn("GoodQA <project-slug>#14151", self.check()["tickets"][0]["fix"])

    def test_credential_file_must_be_private(self):
        key = Path(self.policy["ticket_systems"]["goodqa"]["key_file"])
        key.chmod(0o644)
        report = self.check()
        self.assertEqual(report["status"], "UNVERIFIED")
        self.assertIn("private", report["tickets"][0]["error"])
        self.assertNotIn("test-key", json.dumps(report))


class CrashFailsClosed(Fixture):
    """GoodQA #35694: Codex and Claude let a PreToolUse call through on exit 1, so a crash must not be exit 1."""

    RUNNER = """import sys
sys.path.insert(0, sys.argv[1])
import commit_policy as cp
def boom(*args, **kwargs):
    raise RuntimeError("injected crash")
setattr(cp, sys.argv[2], boom)
sys.exit(cp.entry(sys.argv[3:]))
"""

    def crash(self, where, command, *argv):
        runner = self.root / "crash_runner.py"
        runner.write_text(self.RUNNER)
        payload = json.dumps({"session_id": "s", "cwd": str(self.repo), "tool_name": "Bash",
                              "tool_input": {"command": command}})
        return subprocess.run([sys.executable, str(runner), str(HOOKS), where, *(argv or ("hook",))],
                              input=payload, text=True, capture_output=True, env=self.env, timeout=60)

    def test_crash_on_a_commit_blocks(self):
        result = self.crash("run_hook", "git commit -m x")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("internal error (RuntimeError); refusing", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_crash_in_prefilter_blocks_git_but_allows_ls(self):
        self.assertEqual(self.crash("may_commit", "git commit -m x").returncode, 2)
        self.assertEqual(self.crash("may_commit", "GIT status").returncode, 2)
        allowed = self.crash("may_commit", "ls -la && npm test")
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertIn("not a commit, allowing it", allowed.stderr)

    def test_non_commit_call_never_reaches_the_crash(self):
        self.assertEqual(self.crash("run_hook", "ls -la").returncode, 0)

    def test_other_subcommands_keep_the_traceback_exit(self):
        result = self.crash("validate", "", "check-message")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Traceback", result.stderr)

    def test_script_entry_point_uses_the_crash_boundary(self):
        source = (HOOKS / "commit_policy.py").read_text(encoding="utf-8")
        self.assertTrue(source.rstrip().endswith("_exit(entry())"))

    def test_escaped_git_in_crashed_prefilter_blocks(self):
        # \u0067it decodes to git; the raw-text fallback alone would allow it.
        runner = self.root / "crash_runner.py"
        runner.write_text(self.RUNNER)
        payload = '{"tool_name":"Bash","tool_input":{"command":"\\u0067it commit -m x"}}'
        result = subprocess.run([sys.executable, str(runner), str(HOOKS), "may_commit", "hook"], input=payload,
                                text=True, capture_output=True, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_state_from_a_previous_call_is_not_reused(self):
        runner = self.root / "stale_runner.py"
        runner.write_text("""import io, json, sys
sys.path.insert(0, sys.argv[1])
import commit_policy as cp
cp._HOOK_STATE.update(raw="ls", payload={}, may_commit=False)  # left over from an earlier call
def boom(*a, **k):
    raise RuntimeError("injected")
cp.main = boom
sys.exit(cp.entry(["hook"]))
""")
        result = subprocess.run([sys.executable, str(runner), str(HOOKS)], input="", text=True,
                                capture_output=True, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_closed_stderr_keeps_the_block_exit(self):
        runner = self.root / "pipe_runner.py"
        runner.write_text(self.RUNNER)
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}})
        script = (f"import subprocess, sys\n"
                  f"p = subprocess.Popen([sys.executable, {str(HOOKS / 'commit_policy.py')!r}, 'hook'],\n"
                  f"    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)\n"
                  f"p.stderr.close()\n"
                  f"p.stdin.write({payload.encode()!r}); p.stdin.close()\n"
                  f"sys.exit(p.wait())\n")
        result = subprocess.run([sys.executable, "-c", script], env=self.env, cwd=self.repo, timeout=60)
        self.assertEqual(result.returncode, 2)

    def test_undecodable_stdin_is_a_json_error_not_a_crash(self):
        result = subprocess.run([sys.executable, str(HOOKS / "commit_policy.py"), "hook"], input=b"\xff\xfe",
                                capture_output=True, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"not JSON", result.stderr)



class AuthorTrailerHarness(unittest.TestCase):
    """goodqa#15253 #134 red-team B1: the author trailer is review evidence, so it must name the committing harness."""
    BODY = ("fix(x): change a thing\n\nWhy: a reason that is long enough.\n\nWhat: describe the intended fixture change.\n\n"
            "Testing: `python3 -m unittest tests.test_x` 3 OK\n\nRefs: GoodQA #1234\n\n")

    def problems(self, harness, trailer):
        old = cp.HARNESS_OVERRIDE
        cp.HARNESS_OVERRIDE = harness
        try:
            return [p for p in cp.validate(self.BODY + trailer + "\n", policy=cp.load_policy())
                    if "harness" in p]
        finally:
            cp.HARNESS_OVERRIDE = old

    def test_a_trailer_naming_the_other_harness_is_refused(self):
        self.assertTrue(self.problems("claude", "Co-Authored-By: Codex <noreply@openai.com>"))
        self.assertTrue(self.problems("claude", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n"
                                                "Co-Authored-By: GPT-5 Codex <noreply@openai.com>"))
        self.assertTrue(self.problems("openai", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"))

    def test_the_own_harness_or_an_uninstalled_checkout_is_fine(self):
        self.assertFalse(self.problems("claude", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"))
        self.assertFalse(self.problems("openai", "Co-Authored-By: GPT-5 Codex <noreply@openai.com>"))
        self.assertFalse(self.problems("", "Co-Authored-By: Codex <noreply@openai.com>"))

    def test_harness_comes_from_the_committing_process(self):
        # delta red-team D-F1
        self.assertEqual(cp.commit_harness({"CLAUDECODE": "1"}), "claude")
        self.assertEqual(cp.commit_harness({"CODEX_THREAD_ID": "t1"}), "openai")
        self.assertIsNone(cp.commit_harness({"CLAUDECODE": "1", "CODEX_SANDBOX": "seatbelt"}))
        self.assertIsNone(cp.commit_harness({"AI_AGENT": "1"}))
        self.assertIsNone(cp.commit_harness({}))

    def test_both_installed_copies_accept_the_committing_harness_trailer(self):
        # delta red-team D-F1: the ~/.claude and ~/.codex hooks both run on every commit; neither may refuse the
        # trailer of the harness actually committing, and both refuse the other one.
        # A synthetic marker is not the actual test-host origin: provide an
        # explicit genuine-Claude/no-native or verified-native test condition.
        # This in-process fixture exists only inside disposable helper copies;
        # production gains no origin CLI/config/provider override.
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            copies = [Path(home) / ".claude" / "hooks", Path(home) / ".codex" / "agent-harness"]
            for dest in copies:
                shutil.copytree(HOOKS, dest, ignore=shutil.ignore_patterns("__pycache__"))
            msg = Path(home) / "msg.txt"
            base = {"HOME": home, "PATH": "/usr/bin:/bin"}
            claude = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
            codex = "Co-Authored-By: GPT-5 Codex <noreply@openai.com>"
            cases = (("legacy", {"CLAUDECODE": "1"}, claude, False),
                     ("legacy", {"CODEX_THREAD_ID": "t1"}, codex, False),
                     ("legacy", {"CLAUDECODE": "1"}, codex, True),
                     ("legacy", {"CODEX_THREAD_ID": "t1"}, claude, True),
                     ("native", {"CLAUDECODE": "1"}, codex, False),
                     ("native", {"CLAUDECODE": "1"}, claude, True),
                     ("native", {"CODEX_THREAD_ID": "t1"}, codex, False),
                     ("native", {"CODEX_THREAD_ID": "t1"}, claude, True))
            for origin, marker, trailer, refused in cases:
                msg.write_text(self.BODY + trailer + "\n")
                observation = ("nc.OriginObservation('unknown',False,'no_native_runtime')" if origin == "legacy"
                               else "nc.OriginObservation('openai',True,'running_code_verified')")
                fixture = ("import sys; sys.path.insert(0,sys.argv[1]); import commit_policy as cp,native_context as nc; "
                           "cp.probe_runtime_origin=lambda: " + observation + "; raise SystemExit(cp.main(sys.argv[2:]))")
                for dest in copies:
                    with self.subTest(copy=dest.parent.name, origin=origin, marker=marker, trailer=trailer):
                        out = subprocess.run([sys.executable, "-I", "-B", "-c", fixture, str(dest), "check-message",
                                              "--file", str(msg)], capture_output=True, text=True, timeout=60,
                                             env=dict(base, **marker))
                        self.assertEqual("this commit is made from the" in out.stdout, refused, out.stdout[-400:])
                        self.assertEqual(out.returncode, 2 if refused else 0, out.stderr[-400:])

if __name__ == "__main__":
    unittest.main()
