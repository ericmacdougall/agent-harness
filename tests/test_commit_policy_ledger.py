"""Commit policy and the local ledger: the N11 tracked-repo rule (T0-9) and the fail-closed shim (N19-1).

The real-binary cases build `harness` from this checkout once per run (skipped without Go); the shim
cases use small fake binaries so every failure shape (missing, old, hanging, malformed) is exercised.
"""

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

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import commit_policy as cp  # noqa: E402
import ticket_adapters  # noqa: E402

FEAT = """feat(ledger): reference a local ledger ticket from a commit

Why: offline repos need a ticket reference before GoodQA exists for them.
What: the commit names a ticket from this machine's local ledger only.
Testing: `python3 -m unittest test_commit_policy_ledger` -> 1 passed
Refs: {ref}"""

TRACKED = "https://github.com/ericmacdougall/x.git"
UNTRACKED = "https://example.invalid/someone/x.git"
FORK = "https://github.com/someone-else/x.git"


def run(args, *, cwd, env, check=True, stdin=""):
    result = subprocess.run(args, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        raise AssertionError((args, result.returncode, result.stdout, result.stderr))
    return result


class LedgerWorld(unittest.TestCase):
    """A temp HOME, a dev build of harness on PATH, and a repo with an initialized ledger."""

    bin_dir = None

    @classmethod
    def setUpClass(cls):
        go = shutil.which("go")
        if not go:
            raise unittest.SkipTest("go toolchain not installed; real-binary ledger cases need it")
        cls.bin_dir = Path(tempfile.mkdtemp(prefix="cp-ledger-bin-"))
        out = subprocess.run([go, "build", "-o", str(cls.bin_dir / "harness"), "./cmd/harness"], cwd=ROOT,
                             capture_output=True, text=True, timeout=600)
        if out.returncode:
            shutil.rmtree(cls.bin_dir, True)
            raise AssertionError("go build failed: " + out.stderr[-2000:])

    @classmethod
    def tearDownClass(cls):
        if cls.bin_dir:
            shutil.rmtree(cls.bin_dir, True)

    def setUp(self):
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="cp-ledger-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        home = self.root / "home"
        home.mkdir(mode=0o700)
        gitconfig = self.root / "gitconfig"
        gitconfig.write_text("[user]\n\tname = T\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = main\n")
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "CLAUDE", "CODEX", "AI_AGENT", "HARNESS_"))}
        self.env.update(HOME=str(home), GIT_CONFIG_GLOBAL=str(gitconfig), GIT_CONFIG_NOSYSTEM="1",
                        PATH=f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}", TZ="UTC",
                        HARNESS_LEDGER_FAKE_MACHINE_ID="machine-A", PYTHONDONTWRITEBYTECODE="1")
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("remote", "add", "origin", UNTRACKED)
        self.git("commit", "-q", "--allow-empty", "-m", "base")
        self.harness("init", "--slug", "demo")
        self.handle = self.new_ticket("first local ticket")
        self.ref = f"Ledger demo#{self.handle}"

    def git(self, *args):
        return run(["git", *args], cwd=self.repo, env=self.env).stdout.strip()

    def harness(self, *args):
        return run([str(self.bin_dir / "harness"), "tickets", *args], cwd=self.repo, env=self.env).stdout

    def new_ticket(self, title):
        return json.loads(self.harness("new", "--title", title, "--json"))["ticket"]["handle"]

    def check_message(self, message, *, repo=True):
        path = self.root / "msg.txt"
        path.write_text(message)
        args = [sys.executable, str(HOOKS / "commit_policy.py"), "check-message", "--file", str(path)]
        if repo:
            args += ["--repo", str(self.repo)]
        result = run(args, cwd=self.root, env=self.env, check=False)
        return result.returncode, json.loads(result.stdout or "{}").get("problems", [result.stderr])

    def in_process(self, message, policy=None):
        """validate() exactly as check-message --repo runs it, with an editable policy."""
        policy = policy or cp.load_policy()
        policy["ticket_systems"]["ledger"]["binary"] = str(self.bin_dir / "harness")
        with mock.patch.dict(os.environ, {"HOME": self.env["HOME"], "HARNESS_LEDGER_FAKE_MACHINE_ID": "machine-A",
                                          "GIT_CONFIG_GLOBAL": self.env["GIT_CONFIG_GLOBAL"],
                                          "GIT_CONFIG_NOSYSTEM": "1"}):
            context = cp.repo_ticket_context(str(self.repo), policy)
            return cp.validate(message, policy=policy, tickets_required=context["tracked"],
                               ledger=cp.ledger_checker(policy, context, int(time.time() * 1000)))


class TrackedRepoRule(LedgerWorld):
    """T0-9: Ledger refs count only in untracked or allowlisted repos; N11 sees every remote URL."""

    def test_untracked_repo_accepts_ledger_ref(self):
        code, problems = self.check_message(FEAT.format(ref=self.ref))
        self.assertEqual((code, problems), (0, []))
        # Control: without --repo the default (tracked) rule applies and the same message fails.
        code, problems = self.check_message(FEAT.format(ref=self.ref), repo=False)
        self.assertEqual(code, 2)
        self.assertTrue(any("must reference a GoodQA ticket" in p for p in problems), problems)

    def assert_rejected(self, wording="must reference a GoodQA ticket"):
        code, problems = self.check_message(FEAT.format(ref=self.ref))
        self.assertEqual(code, 2, problems)
        self.assertTrue(any(wording in p for p in problems), problems)

    def test_tracked_origin_rejects(self):
        self.git("remote", "set-url", "origin", TRACKED)
        self.assert_rejected()
        # GoodQA behaviour is unchanged: a GoodQA ref passes the offline check in the same repo.
        code, problems = self.check_message(FEAT.format(ref="GoodQA #14151"))
        self.assertEqual((code, problems), (0, []))

    def test_rename_origin_still_tracked(self):
        self.git("remote", "set-url", "origin", TRACKED)
        self.git("remote", "rename", "origin", "upstream")
        self.assert_rejected()

    def test_fork_url_with_tracked_pushurl_still_tracked(self):
        self.git("remote", "set-url", "origin", FORK)
        self.git("remote", "set-url", "--push", "origin", TRACKED)
        self.assert_rejected()

    def test_second_remote_tracked(self):
        self.git("remote", "add", "mirror", TRACKED)
        self.assert_rejected()

    def test_insteadof_rewrite_tracked(self):
        self.git("config", "url.https://github.com/ericmacdougall/.insteadOf", "eric:")
        self.git("remote", "set-url", "origin", "eric:x.git")
        self.assert_rejected()

    def test_remote_removed_needs_allowed_repos(self):
        self.git("remote", "remove", "origin")
        self.assert_rejected("Ledger refs count only in untracked repos or repos listed in ledger.allowed_repos")
        policy = cp.load_policy()
        policy["ticket_systems"]["ledger"]["allowed_repos"] = [re_escape(str(self.repo))]
        self.assertEqual(self.in_process(FEAT.format(ref=self.ref), policy), [])
        # A prefix-only match is not enough: allowed_repos patterns must match the whole path.
        policy["ticket_systems"]["ledger"]["allowed_repos"] = [re_escape(str(self.root))]
        self.assertNotEqual(self.in_process(FEAT.format(ref=self.ref), policy), [])

    def test_seven_hex_and_unknown_handles_rejected(self):
        code, problems = self.check_message(FEAT.format(ref=f"Ledger demo#{self.handle[:7]}"))
        self.assertEqual(code, 2)
        self.assertTrue(any("Refs: name a ticket" in p for p in problems), problems)
        unknown = "0123abcd" if not self.handle.startswith("0123abcd") else "fedc4321"
        code, problems = self.check_message(FEAT.format(ref=f"Ledger demo#{unknown}"))
        self.assertEqual(code, 2)
        self.assertTrue(any("does not exist" in p for p in problems), problems)
        code, problems = self.check_message(FEAT.format(ref=f"Ledger other#{self.handle}"))
        self.assertEqual(code, 2, "a handle in another ledger's slug must not resolve here")

    def test_range_resolves_as_of_author_date(self):
        later = self.new_ticket("created after the commit was authored")
        past = "2026-01-02T00:00:00+00:00"
        path = self.root / "m.txt"
        path.write_text(FEAT.format(ref=f"Ledger demo#{later}"))
        run(["git", "commit", "-q", "--allow-empty", "-F", str(path)], cwd=self.repo,
            env={**self.env, "GIT_AUTHOR_DATE": past})
        policy = cp.load_policy()
        policy["enforce_after"] = None
        with mock.patch.dict(os.environ, {"PATH": self.env["PATH"], "HOME": self.env["HOME"],
                                          "HARNESS_LEDGER_FAKE_MACHINE_ID": "machine-A"}):
            report = cp.check_range(str(self.repo), "HEAD~1", "HEAD", policy)
        self.assertEqual(report["status"], "BLOCKED", report)
        self.assertIn("before the commit date", json.dumps(report))
        # Control: the same reference authored now resolves.
        path.write_text(FEAT.format(ref=f"Ledger demo#{later}").replace("offline repos", "offline repositories"))
        run(["git", "commit", "-q", "--allow-empty", "-F", str(path)], cwd=self.repo, env=self.env)
        with mock.patch.dict(os.environ, {"PATH": self.env["PATH"], "HOME": self.env["HOME"],
                                          "HARNESS_LEDGER_FAKE_MACHINE_ID": "machine-A"}):
            report = cp.check_range(str(self.repo), "HEAD~1", "HEAD", policy)
        self.assertEqual(report["status"], "PASS", report)
        # Ledger refs never reach the remote-ticket verification or delivery comments.
        self.assertEqual(cp._commit_refs(FEAT.format(ref=self.ref), policy), [])

    def test_push_url_counts_toward_tracking(self):
        policy = cp.load_policy()
        self.assertFalse(cp.repo_ticket_context(str(self.repo), policy)["tracked"])
        self.assertTrue(cp.repo_ticket_context(str(self.repo), policy, push_url=TRACKED)["tracked"])

    def test_failing_control_origin_url_only_check(self):
        """With the pre-N11 origin-fetch-URL-only rule both bypasses pass; the N11 rule rejects them."""
        none_feat = FEAT.format(ref="none (no ticket exists for this change)")

        def origin_fetch_only(repo):
            return cp.git(repo, "remote", "get-url", "origin", check=False).split()
        self.git("remote", "set-url", "origin", FORK)
        self.git("remote", "set-url", "--push", "origin", TRACKED)
        with mock.patch.object(cp, "remote_urls", origin_fetch_only):
            self.assertEqual(self.in_process(FEAT.format(ref=self.ref)), [], "control: pushurl bypass")
        self.assertNotEqual(self.in_process(FEAT.format(ref=self.ref)), [])
        self.git("remote", "set-url", "origin", TRACKED)
        self.git("remote", "rename", "origin", "upstream")
        with mock.patch.object(cp, "remote_urls", origin_fetch_only):
            self.assertEqual(self.in_process(none_feat), [], "control: rename bypass")
        self.assertTrue(any("must reference a ticket" in p for p in self.in_process(none_feat)))


def re_escape(path):
    import re
    return re.escape(path)


class ShimFailsClosed(unittest.TestCase):
    """N19-1: missing, old, hanging and malformed binaries are 'could not verify', never a pass."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cp-shim-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "remote", "add", "origin", UNTRACKED], check=True)

    def fake(self, script):
        path = self.dir / "harness"
        path.write_text("#!/bin/sh\n" + script)
        path.chmod(stat.S_IRWXU)
        return str(path)

    def problems(self, binary):
        policy = cp.load_policy()
        policy["ticket_systems"]["ledger"]["binary"] = binary
        context = cp.repo_ticket_context(str(self.repo), policy)
        self.assertTrue(context["ledger_allowed"])
        started = time.monotonic()
        result = cp.validate(FEAT.format(ref="Ledger demo#0123abcd"), policy=policy, tickets_required=False,
                             ledger=cp.ledger_checker(policy, context, int(time.time() * 1000)))
        return result, time.monotonic() - started

    def good_json(self, version="0.1.0", created=1):
        return json.dumps({"project": "proj_x", "slug": "demo", "ledger_version": version,
                           "ticket": {"id": "tk_01M6JNX4XRMZPWXWGPKKNVXCNH", "handle": "0123abcd",
                                      "title": "t", "status": "todo", "created_ms": created}})

    def assert_unverified(self, binary):
        problems, _ = self.problems(binary)
        self.assertTrue(any("could not verify Ledger demo#0123abcd" in p for p in problems), problems)

    def test_control_well_formed_answer_passes(self):
        problems, _ = self.problems(self.fake(f"cat <<'EOF'\n{self.good_json()}\nEOF\n"))
        self.assertEqual(problems, [])

    def test_missing_binary(self):
        self.assert_unverified(str(self.dir / "no-such-harness"))
        self.assert_unverified("harness-binary-that-is-not-on-path")

    def test_old_binary(self):
        self.assert_unverified(self.fake('echo \'{"error":"usage","message":"older"}\'; exit 2\n'))
        self.assert_unverified(self.fake(f"cat <<'EOF'\n{self.good_json(version='0.0.9')}\nEOF\n"))

    def test_hanging_binary_times_out(self):
        problems, elapsed = self.problems(self.fake("sleep 30\n"))
        self.assertTrue(any("could not verify" in p and "within" in p for p in problems), problems)
        self.assertLess(elapsed, 10)

    def test_malformed_output(self):
        self.assert_unverified(self.fake("echo not json\n"))
        self.assert_unverified(self.fake('echo \'["list"]\'\n'))
        self.assert_unverified(self.fake(f"cat <<'EOF'\n{self.good_json().replace('demo', 'other')}\nEOF\n"))
        self.assert_unverified(self.fake(f"cat <<'EOF'\n{self.good_json(created=10**15)}\nEOF\n"))

    def test_not_found_and_ambiguous_fail(self):
        problems, _ = self.problems(self.fake('echo \'{"error":"not_found","message":"x"}\'; exit 3\n'))
        self.assertTrue(any("does not exist" in p for p in problems), problems)
        problems, _ = self.problems(self.fake('echo \'{"error":"ambiguous","message":"x"}\'; exit 3\n'))
        self.assertTrue(any("ambiguous" in p for p in problems), problems)

    def test_generic_paths_never_call_the_ledger(self):
        adapter = ticket_adapters.adapter_for({"adapter": "ledger"})
        with self.assertRaises(ticket_adapters.TicketSystemUnavailable):
            adapter.lookup("demo", "0123abcd")
        with self.assertRaises(ticket_adapters.TicketSystemUnavailable):
            adapter.comment(None, "x", "op")


if __name__ == "__main__":
    unittest.main()
