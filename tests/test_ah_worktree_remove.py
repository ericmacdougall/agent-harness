"""`ah worktree-remove` and the verifier it runs (goodqa#15565): real temporary repositories, fake network and ssh.

The removal under test only ever touches temporary directories under a temporary HOME."""
import errno
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
os.environ["AH_LOCAL_CONFIG"] = str(Path(__file__).resolve().parent / "data" / "local_fixture.json")  # hermetic hosts
import ah  # noqa: E402
import ah_worktree  # noqa: E402

URL = "https://github.com/acme/widgets.git"
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")


def git(cwd, *args):
    done = subprocess.run(["git", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError("git %s: %s" % (" ".join(args), done.stderr))
    return done.stdout.strip()


class FakeRun:
    """Stands in for subprocess.run: records argv, returns scripted answers."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return subprocess.CompletedProcess(argv, answer.get("code", 0), answer.get("out", ""), answer.get("err", ""))


def verdict(**kw):
    base = {"removable": True, "removed": True, "head": "a" * 40, "reason": None, "urls": {"origin": [URL]},
            "freed_bytes": 10, "verifier": ah_worktree.VERIFIER_VERSION}
    base.update(kw)
    return {"out": json.dumps(base)}


class Delegation(unittest.TestCase):
    PATH = "/Users/u/tools/wt-one"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def remove(self, runner, host="worker-1", path=None, reason="merged and published", authenticated=False):
        return ah_worktree.remove(host, path or self.PATH, reason, authenticated, "s1", "agent-x", self.home, runner)

    def audit_rows(self):
        file = self.home / ".agent-harness" / "worktree-audit.jsonl"
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def test_a_remote_removal_runs_one_fixed_verifier_over_ssh_and_audits_before_and_after(self):
        run = FakeRun(verdict())
        result = self.remove(run)
        self.assertTrue(result["ok"] and result["removed"])
        argv = run.calls[0][0]
        self.assertEqual(argv[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--"])
        self.assertEqual(argv[6], "worker-1")
        self.assertEqual(argv[7], "python3 -I .claude/hooks/ah_worktree.py free-worktree --path " + self.PATH)
        self.assertNotIn("--force", " ".join(argv))
        self.assertEqual([row["event"] for row in self.audit_rows()], ["start", "result"])
        self.assertEqual(len(run.calls), 1)

    def test_remote_auth_adds_one_flag_and_never_any_refs(self):
        run = FakeRun(verdict())
        self.remove(run, authenticated=True)
        # 2026-11-24: the free-worktree verifier reads no remote, so --remote-auth is accepted and adds nothing
        self.assertEqual(run.calls[0][0][7], "python3 -I .claude/hooks/ah_worktree.py free-worktree --path " + self.PATH)
        self.assertNotIn("input", run.calls[0][1])
        self.assertNotIn("ls-remote", " ".join(run.calls[0][0]))

    def test_local_runs_the_verifier_from_the_hooks_directory_with_isolation(self):
        run = FakeRun(verdict())
        self.remove(run, host="local")
        argv = run.calls[0][0]
        self.assertEqual(argv[1], "-I")
        self.assertTrue(argv[2].endswith("ah_worktree.py"))  # the verifier moved here in release 1001
        self.assertEqual(argv[3:], ["free-worktree", "--path", self.PATH])

    def test_bad_requests_fail_before_any_process_or_audit_row(self):
        for kwargs in ({"host": "worker-2"}, {"host": "worker-1; id"}, {"path": "relative/p"}, {"path": "/a/../b"},
                       {"path": "/a/b/"}, {"path": "/a/b c"}, {"path": "/a/$(x)"}, {"path": "/a/b;rm"}, {"path": "/"},
                       {"path": "/a//b"}, {"path": "/a/é"}):  # a reason is optional since 2026-11-24
            with self.subTest(kwargs=str(kwargs)[:40]):
                run = FakeRun()
                with self.assertRaises(ah_worktree.WorktreeError):
                    self.remove(run, **kwargs)
                self.assertEqual(run.calls, [])
                self.assertEqual(self.audit_rows(), [])

    def test_there_is_no_force_second_path_or_caller_supplied_refs_flag(self):
        parser = ah.build_parser()
        base = ["worktree-remove", "--host", "worker-1", "--path", self.PATH, "--reason", "r"]
        parser.parse_args(base)
        parser.parse_args(base + ["--remote-auth"])
        for extra in (["--force"], ["-f"], ["--forc"], ["--no-verify"], ["--heads-stdin"], ["--remote-heads-from", "local"],
                      ["--remote-aut"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), redirect_stderr_null():
                parser.parse_args(base + extra)

    def test_an_unknown_outcome_after_the_runner_started_is_recorded_as_unknown_never_as_not_removed(self):
        for answer in ({"out": ""}, {"out": "not json"}, {"out": "[]"}, {"out": json.dumps({"removed": True})},
                       {"out": json.dumps({"removable": "yes", "verifier": ah_worktree.VERIFIER_VERSION})}, OSError("ssh failed"),
                       subprocess.TimeoutExpired("ssh", 1),
                       {"out": json.dumps({"removable": True, "removed": "maybe", "verifier": ah_worktree.VERIFIER_VERSION})}):
            with self.subTest(answer=str(answer)[:40]):
                before = len(self.audit_rows())
                with self.assertRaises(ah_worktree.WorktreeError) as caught:
                    self.remove(FakeRun(answer))
                self.assertNoRemovalClaim(str(caught.exception))
                rows = self.audit_rows()[before:]
                self.assertEqual([row["event"] for row in rows], ["start", "result"])
                self.assertIsNone(rows[1]["removed"])  # unknown: the remote command may have run
                self.assertIn("unknown", rows[1]["why"])

    def assertNoRemovalClaim(self, text):
        """After the runner started the host may already have removed the tree: the message must say the outcome is
        unknown and point at the host, and must never say that nothing was removed (red-team r4 F1)."""
        lowered = text.lower()
        for claim in ("nothing removed", "nothing was removed", "nothing is assumed removed", "not removed"):
            self.assertNotIn(claim, lowered)
        self.assertIn("unknown", lowered)
        self.assertIn("check the host", lowered)

    # red-team r4 F2: a null `removed` beside removable true is not a definite answer
    def test_a_null_removed_beside_removable_true_is_an_unknown_outcome_not_a_failure(self):
        for removed in (None, "missing"):
            body = {"removable": True, "verifier": ah_worktree.VERIFIER_VERSION, "head": "a" * 40}
            if removed != "missing":
                body["removed"] = None
            with self.subTest(removed=removed):
                result = self.remove(FakeRun({"out": json.dumps(body)}))
                row = self.audit_rows()[-1]
                self.assertIsNone(row["removed"])
                self.assertIsNone(result["removed"])
                self.assertFalse(result["ok"])
                self.assertIn("unknown", (row["why"] or "").lower())
        # removable false with no removed key is a definite refusal: False
        result = self.remove(FakeRun({"out": json.dumps({"removable": False, "verifier": ah_worktree.VERIFIER_VERSION, "reason": "not clean"})}))
        self.assertIs(self.audit_rows()[-1]["removed"], False)
        self.assertIs(result["removed"], False)

    # receipt r5 N1: a self-contradicting answer is malformed, so the outcome is unknown
    def test_removable_false_with_removed_true_is_a_malformed_answer_and_an_unknown_outcome(self):
        before = len(self.audit_rows())
        with self.assertRaises(ah_worktree.WorktreeError) as caught:
            self.remove(FakeRun(verdict(removable=False, removed=True, reason="not clean")))
        self.assertNoRemovalClaim(str(caught.exception))
        rows = self.audit_rows()[before:]
        self.assertIsNone(rows[-1]["removed"])
        self.assertIn("unknown", rows[-1]["why"])

    # receipt r5 N2: a removal that started and did not complete may have deleted part of the tree
    def test_a_removal_that_started_and_did_not_complete_is_recorded_as_unknown_not_as_not_removed(self):
        answer = verdict(removable=True, removed=False, directory_removed=False, registry_entry_left=True,
                         reason="git worktree remove did not complete cleanly (TimeoutExpired; directory still there, "
                                "registry entry left): ")
        result = self.remove(FakeRun(answer))
        row = self.audit_rows()[-1]
        self.assertIsNone(row["removed"])
        self.assertIsNone(result["removed"])
        self.assertFalse(result["ok"])
        self.assertIs(result["directory_removed"], False)
        self.assertIs(result["registry_entry_left"], True)
        for text in (row["why"], result["reason"]):
            self.assertIn("partly deleted", text)
            self.assertIn("check the host", text)
        # a verifier refusal (nothing ran) stays a definite False
        self.remove(FakeRun(verdict(removable=False, removed=False, reason="not clean")))
        self.assertIs(self.audit_rows()[-1]["removed"], False)

    def test_a_definite_answer_is_recorded_as_a_definite_outcome(self):
        self.remove(FakeRun(verdict(removable=False, removed=False, reason="the working tree is not clean")))
        self.assertIs(self.audit_rows()[-1]["removed"], False)
        self.remove(FakeRun(verdict()))
        self.assertIs(self.audit_rows()[-1]["removed"], True)

    def test_the_call_timeout_covers_the_verifiers_own_worst_case(self):
        self.assertGreater(ah_worktree.CALL_TIMEOUT, ah_worktree.VERIFY_SECONDS + ah_worktree.REMOVE_SECONDS + 20 + 10)
        run = FakeRun(verdict())
        self.remove(run)
        self.assertEqual(run.calls[0][1]["timeout"], ah_worktree.CALL_TIMEOUT)

    def test_an_old_verifier_on_the_target_is_refused_by_version(self):
        for answer in (verdict(verifier=1), {"out": json.dumps({"removable": True, "removed": True})},
                       verdict(verifier="2")):
            with self.subTest(answer=str(answer)[:50]):
                with self.assertRaises(ah_worktree.WorktreeError) as caught:
                    self.remove(FakeRun(answer))
                self.assertEqual(caught.exception.code, "verifier_outdated")
                self.assertNoRemovalClaim(str(caught.exception))  # {"removed": true} said it WAS removed
                self.assertEqual(self.audit_rows()[-1]["removed"], None)

    def test_a_refusal_from_the_verifier_is_reported_not_overridden(self):
        run = FakeRun(verdict(removable=False, removed=False, reason="the working tree is not clean"))
        result = self.remove(run)
        self.assertFalse(result["ok"])
        self.assertFalse(result["removed"])
        self.assertIn("not clean", result["reason"])
        self.assertEqual(len(run.calls), 1)

    def test_the_outcome_row_redacts_the_reason_and_survives_a_failing_audit_after_the_removal(self):
        run = FakeRun(verdict(removable=False, removed=False, reason="failed: token=ghp_abc123 bad"))
        result = self.remove(run)
        self.assertNotIn("ghp_abc123", json.dumps(self.audit_rows()))
        self.assertNotIn("ghp_abc123", json.dumps(result))
        real, calls = ah_worktree.audit, []

        def second_fails(home, record):
            calls.append(record["event"])
            if record["event"] == "result":
                raise OSError("disk full")
            return real(home, record)
        with mock.patch.object(ah_worktree, "audit", second_fails):
            result = self.remove(FakeRun(verdict()))
        self.assertTrue(result["removed"])  # the removal happened and is still reported
        self.assertIn("audit_warning", result)

    def test_the_audit_start_row_is_written_before_the_verifier_runs_and_a_failed_audit_stops_everything(self):
        seen = []

        def spying(argv, **kwargs):
            seen.append([row["event"] for row in self.audit_rows()])
            return subprocess.CompletedProcess(argv, 0, verdict()["out"], "")
        self.remove(spying)
        self.assertEqual(seen, [["start"]])
        run = FakeRun(verdict())
        with mock.patch.object(ah_worktree, "audit", side_effect=OSError("disk full")):
            with self.assertRaises(ah_worktree.WorktreeError):
                self.remove(run)
        self.assertEqual(run.calls, [])

    def test_the_current_directory_inside_a_local_target_is_refused(self):
        run = FakeRun()
        with mock.patch.object(os, "getcwd", return_value=self.PATH + "/sub"):
            with self.assertRaises(ah_worktree.WorktreeError):
                self.remove(run, host="local")
        self.assertEqual(run.calls, [])

    def test_the_command_is_wired_into_ah_and_installed(self):
        with mock.patch.object(ah_worktree, "remove", return_value={"ok": True}) as remove:
            out = io.StringIO()
            with redirect_stdout(out):
                code = ah.main(["worktree-remove", "--host", "local", "--path", self.PATH, "--reason", "why",
                                "--remote-auth"])
        self.assertEqual(code, 0)
        self.assertEqual(remove.call_args[0][:4], ("local", self.PATH, "why", True))
        text = (ROOT / "install.py").read_text() + (ROOT / "install_codex.py").read_text()
        self.assertIn("ah_worktree.py", text)


class redirect_stderr_null:
    def __enter__(self):
        self.old, sys.stderr = sys.stderr, io.StringIO()

    def __exit__(self, *exc):
        sys.stderr = self.old
        return False


if __name__ == "__main__":
    unittest.main()
