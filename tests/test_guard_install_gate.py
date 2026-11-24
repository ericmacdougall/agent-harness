"""PR 326a (goodqa#16944): no agent route installs or downgrades a guard file, except main's reviewed-release branch.

`ah install-files` runs here against the fixtures of tests/test_ah_install.py (a local bare repository stands in for
the canonical URL and a fake ssh runs the real remote program against a temporary host home). The human check gets a
fake process view; the stamp is the real one main's mission_gate hook writes; the receipt check runs with a fake `gh`
and a real merge-gate waiver log in a temporary state directory. Nothing here touches a real host or hooks directory."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ah_install import TICKET, Base, git, sha  # noqa: E402

import ah_install as ai  # noqa: E402
import caller_identity  # noqa: E402
import guard_files  # noqa: E402
import human_proof  # noqa: E402
import merge_gate  # noqa: E402
import mission_gate  # noqa: E402
import release_receipt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
SESSION = "0c0c0c0c-1111-4222-8333-444455556666"
H40 = "b" * 40


class FakeEnv(human_proof.Env):
    """A process view. The default is a person in Terminal: login -> zsh -> python3."""

    def __init__(self, tty=True, environ=None, table=None, pid=300, table_error=None):
        self.tty, self.env, self.error, self._pid = tty, environ or {}, table_error, pid
        self.table = table if table is not None else {300: (200, "python3 ah.py install-files"), 200: (100, "-zsh"),
                                                      100: (1, "login -pf eric"), 1: (0, "/sbin/launchd")}

    def stdin_is_tty(self):
        return self.tty

    def environ(self):
        return dict(self.env)

    def process_table(self):
        if self.error:
            raise self.error
        return dict(self.table)

    def pid(self):
        return self._pid


AGENT = FakeEnv(tty=False, environ={"CLAUDECODE": "1"},
                table={300: (200, "python3 ah.py install-files"), 200: (100, "/bin/zsh -c ..."), 100: (1, "claude --resume"),
                       1: (0, "/sbin/launchd")})


class HumanProof(unittest.TestCase):
    def test_a_person_in_a_terminal_passes(self):
        self.assertIsNone(human_proof.refusal(FakeEnv()))

    def test_each_missing_fact_refuses(self):
        cases = {
            "stdin not a terminal": FakeEnv(tty=False),
            "agent variable": FakeEnv(environ={"CLAUDECODE": "1"}),
            "codex variable": FakeEnv(environ={"CODEX_THREAD_ID": "t"}),
            "agent ancestor": FakeEnv(table={300: (200, "python3 x"), 200: (150, "-zsh"), 150: (100, "/usr/local/bin/claude"),
                                             100: (1, "login"), 1: (0, "launchd")}),
            "codex ancestor": FakeEnv(table={300: (200, "python3 x"), 200: (100, "codex exec"), 100: (1, "sshd: eric"),
                                             1: (0, "init")}),
            "detached (no session ancestor)": FakeEnv(table={300: (1, "python3 x"), 1: (0, "/sbin/launchd")}),
            "process table unreadable": FakeEnv(table_error=OSError("ps")),
        }
        for label, env in cases.items():
            with self.subTest(label):
                self.assertIsInstance(human_proof.refusal(env), str)

    def test_a_surprise_fails_closed(self):
        env = FakeEnv()
        env.environ = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.assertIn("RuntimeError", human_proof.refusal(env))

    def test_this_test_process_is_not_a_person(self):
        """The real Env, here: the suite runs under an agent or a pipe, so the human branch must not hold."""
        self.assertIsNotNone(human_proof.refusal())


class GuardSet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.closure = guard_files.guard_closure(HOOKS)

    def guard(self, name):
        return guard_files.is_guard_file(name) or name in self.closure

    def test_registered_guard_hooks_and_named_files_are_guard_files(self):
        names = ("command_guard_hook.py", "merge_gate.py", "mission_gate.py", "ah.py", "ah_install.py",
                 "guard_files.py", "human_proof.py", "release_receipt.py", "run_probe.py", "run_capped.py",
                 "ahc_release.json", "dropbox_budget.conf", "installer_scan.py", "deliver.py")
        self.assertEqual(guard_files.guard_subset(names, HOOKS), sorted(names))
        for name in ("run_probe.py", "ahc_release.json", "dropbox_budget.conf"):  # found by the closure as well as listed
            with self.subTest(name):
                self.assertIn(name, self.closure)

    def test_a_file_no_guard_reaches_is_not_a_guard_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "hooks_manifest.json").write_text(json.dumps({"hooks": [{"script": "g.py", "event": "PreToolUse"}]}))
            (d / "g.py").write_text("import h\nX = 'data.conf'\n")
            (d / "h.py").write_text("")
            (d / "data.conf").write_text("")
            (d / "free.py").write_text("")
            self.assertEqual(guard_files.guard_subset(["g.py", "h.py", "data.conf", "free.py"], d),
                             ["data.conf", "g.py", "h.py"])

    def test_every_file_a_guard_names_in_its_source_is_a_guard_file(self):
        """Independent of the AST walk: a plain text scan of every closure module for names of files in the hooks dir."""
        import re
        self.assertIsNotNone(self.closure)
        present = {p.name for p in HOOKS.iterdir() if p.is_file()}
        missed, checked = set(), 0
        for name in sorted(n for n in self.closure if n.endswith(".py") and n in present):
            text = (HOOKS / name).read_text(errors="replace")
            for found in set(re.findall(r"[A-Za-z0-9_.-]+\.(?:py|json|conf|mjs|md)\b", text)):
                base = found.rsplit("/", 1)[-1]
                if base in present:
                    checked += 1
                    if not self.guard(base):
                        missed.add((name, base))
        self.assertGreater(checked, 50)  # the scan saw real names, so an empty result means something
        self.assertEqual(missed, set())

    def test_unreadable_manifest_or_module_makes_every_name_a_guard_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "hooks_manifest.json").write_text("{not json")
            self.assertEqual(guard_files.guard_subset(["free.py"], d), ["free.py"])
            (d / "hooks_manifest.json").write_text(json.dumps({"hooks": [{"script": "g.py", "event": "Stop"}]}))
            (d / "g.py").write_text("pass\n")
            self.assertEqual(guard_files.guard_subset(["free.py"], d), [])  # positive control
            (d / "g.py").chmod(0)
            try:
                if os.access(d / "g.py", os.R_OK):
                    self.skipTest("running as a user who can read a mode-000 file")
                self.assertEqual(guard_files.guard_subset(["free.py"], d), ["free.py"])
            finally:
                (d / "g.py").chmod(0o600)


class Receipt(unittest.TestCase):
    REF, HEAD = "a" * 40, "c" * 40

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.pulls = [self.pr()]
        self.exit = 0

    def pr(self, **over):
        pr = {"number": 7, "merged_at": "2026-11-24T00:00:00Z", "merge_commit_sha": self.REF,
              "base": {"ref": "main", "repo": {"full_name": "ericmacdougall/agent-harness"}}, "head": {"sha": self.HEAD}}
        pr.update(over)
        return pr

    def gh(self, argv, **kw):
        self.assertEqual(argv[1:], ["api", "repos/ericmacdougall/agent-harness/commits/%s/pulls" % self.REF])
        self.assertNotIn("GH_TOKEN", kw["env"])
        return subprocess.CompletedProcess(argv, self.exit, json.dumps(self.pulls), "")

    def waive(self, source="hook", pr=7, head=None, repo="ericmacdougall/agent-harness"):
        if source == "settled-review":
            merge_gate._append_waiver_record(self.state, {"event": "waive", "id": "mgw-review-x", "ts": 1.0, "repo": repo,
                                                          "pr": pr, "head": head or self.HEAD, "approval_source": source})
        else:
            merge_gate.add_waiver(self.state, repo, pr, head or self.HEAD, TICKET, "exact HEAD review PASS", "main:session-x(hook)", source)

    def verify(self):
        return release_receipt.verify(self.REF, runner=self.gh, state_dir=self.state)

    def refused(self):
        with self.assertRaises(release_receipt.ReceiptError):
            self.verify()

    def test_a_hook_or_settled_review_waiver_for_the_merged_pr_head_passes(self):
        for source in ("hook", "settled-review"):
            with self.subTest(source):
                self.setUp()
                self.waive(source)
                self.assertEqual(self.verify()["pr"], 7)
                self.assertEqual(self.verify()["source"], source)

    def test_no_merged_pr_or_the_wrong_pr_is_refused(self):
        self.waive()
        for label, pulls in {"no PR": [], "not merged": [self.pr(merged_at=None)],
                             "other merge commit": [self.pr(merge_commit_sha="d" * 40)],
                             "into another branch": [self.pr(base={"ref": "dev", "repo": {"full_name": "ericmacdougall/agent-harness"}})],
                             "a fork's PR": [self.pr(base={"ref": "main", "repo": {"full_name": "someone/agent-harness"}})],
                             "two PRs": [self.pr(), self.pr(number=8)], "short head": [self.pr(head={"sha": "c" * 12})]}.items():
            with self.subTest(label):
                self.pulls = pulls
                self.refused()

    def test_gh_failure_or_garbage_is_refused(self):
        self.waive()
        self.exit = 1
        self.refused()
        self.exit = 0
        self.gh = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "not json", "")
        self.refused()

    def test_no_receipt_of_record_is_refused(self):
        self.refused()  # no log at all
        for label, kw in {"asserted only": {"source": "asserted"}, "other head": {"head": "e" * 40},
                          "other pr": {"pr": 9}, "other repo": {"repo": "ericmacdougall/goodqa"}}.items():
            with self.subTest(label):
                self.setUp()
                self.waive(**kw)
                self.refused()

    def test_an_edited_waiver_log_is_refused(self):
        self.waive("asserted")
        log = self.state / merge_gate.WAIVER_FILE
        log.write_text(log.read_text().replace('"asserted"', '"hook"'))
        self.refused()

    def test_a_ref_that_is_not_a_full_sha_is_refused(self):
        with self.assertRaises(release_receipt.ReceiptError):
            release_receipt.verify("abc", runner=self.gh, state_dir=self.state)


class Gate(Base):
    """The per-file route with the gate: the agent cases use AGENT; Base installs ah.py (a guard file) and extra.py."""

    def setUp(self):
        super().setUp()
        self.receipts = []
        self.receipt_ok = True
        for p in (mock.patch.object(ai, "PROOF_ENV", AGENT), mock.patch.object(ai, "RECEIPT", self.receipt)):
            p.start()
            self.addCleanup(p.stop)
        proj = self.mac / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        self.transcript = proj / (SESSION + ".jsonl")
        self.transcript.write_text('{"type":"user"}\n')
        self.calls_seen = 0

    def receipt(self, ref):
        self.receipts.append(ref)
        if not self.receipt_ok:
            raise release_receipt.ReceiptError("%s is not the merge commit of exactly one merged PR (found 0)" % ref[:12])
        return {"pr": 1, "head": "c" * 40, "waiver": "mgw-x", "source": "hook"}

    def stamp(self, line, agent=None):
        """mission_gate's real PreToolUse hook on main's Bash line."""
        self.calls_seen += 1
        payload = {"tool_name": "Bash", "tool_input": {"command": line}, "session_id": SESSION,
                   "transcript_path": str(self.transcript), "tool_use_id": "toolu_%08d" % self.calls_seen,
                   "hook_event_name": "PreToolUse"}
        if agent:
            payload.update(agent_id=agent, agent_type="task-owner")
        env = {"HOME": str(self.mac), "AH_HOME": str(self.mac), "CLAUDE_CONFIG_DIR": str(self.mac / ".claude")}
        with mock.patch.dict(os.environ, env):
            mission_gate.cmd_pretool(payload)

    def line(self, ref=None, files=("ah.py", "extra.py"), extra=""):
        return ("python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --from-ref %s %s --ticket \"%s\"%s"
                % (ref or self.c1, " ".join("--file " + f for f in files), TICKET, extra))

    def before(self):
        return {n: self.live(n) for n in ("ah.py", "extra.py")}, len(self.rows("start"))

    def assert_refused_unchanged(self, before, **kw):
        err = self.refused(**kw)
        self.assertEqual(err.code, "guard_file")
        self.assertEqual(self.before(), before)
        return err

    # --- positive controls

    def test_main_installs_a_reviewed_merged_commit(self):
        self.stamp(self.line())
        out = self.install()
        self.assertEqual(out["result"], "installed")
        self.assertEqual(self.receipts, [self.c1])
        gate = self.rows("start")[-1]["guard_gate"]
        self.assertEqual((gate["branch"], gate["guard_files"], gate["waiver"]), ("main-release", ["ah.py"], "mgw-x"))

    def test_the_user_in_his_terminal_needs_no_stamp_or_receipt(self):
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()):
            self.assertEqual(self.install()["result"], "installed")
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.rows("start")[-1]["guard_gate"]["branch"], "human")

    def test_a_non_guard_file_needs_neither(self):
        self.assertEqual(self.install(files=("extra.py",))["result"], "installed")
        self.assertIsNone(self.rows("start")[-1]["guard_gate"])

    def test_a_dry_run_needs_neither(self):
        self.assertEqual(self.install(dry_run=True)["result"], "dry_run")

    # --- must-fail cases

    def test_a_sub_agent_gets_no_stamp_and_is_refused(self):
        self.stamp(self.line(), agent="a1234567890abcdef")
        self.assert_refused_unchanged(self.before())
        self.assertEqual(self.receipts, [])

    def test_no_stamp_is_refused(self):
        err = self.assert_refused_unchanged(self.before())
        self.assertIn("python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev", str(err))

    def test_a_stamp_covers_only_its_exact_command(self):
        self.stamp(self.line(files=("ah.py",)))
        self.assert_refused_unchanged(self.before())  # ah.py + extra.py is another command
        self.stamp(self.line(ref=self.c0))
        self.assert_refused_unchanged(self.before())  # another ref

    def test_a_stamp_is_single_use(self):
        self.stamp(self.line())
        self.assertEqual(self.install()["result"], "installed")
        (self.work / "harness" / "hooks" / "ah.py").write_text("# c2\n")
        git(self.work, "commit", "-qam", "c2")
        c2 = git(self.work, "rev-parse", "HEAD")
        git(self.tmp, "--git-dir", str(self.origin), "fetch", "-q", str(self.work), "+main:main")
        before = self.before()
        with self.assertRaises(ai.InstallError):
            self.install(ref=c2)
        self.assertEqual(self.before(), before)

    def test_a_merged_ref_with_no_receipt_is_refused(self):
        self.stamp(self.line())
        self.receipt_ok = False
        err = self.assert_refused_unchanged(self.before())
        self.assertIn("merge commit", str(err))

    def test_an_unmerged_ref_is_refused_even_with_a_receipt(self):
        git(self.work, "checkout", "-qb", "side")
        (self.work / "harness" / "hooks" / "ah.py").write_text("# side\n")
        git(self.work, "commit", "-qam", "side")
        side = git(self.work, "rev-parse", "HEAD")
        git(self.tmp, "--git-dir", str(self.origin), "fetch", "-q", str(self.work), "+side:side")
        self.stamp(self.line(ref=side))
        before = self.before()
        with self.assertRaises(ai.InstallError) as caught:
            self.install(ref=side)
        self.assertRegex(str(caught.exception), "not (a commit of|an ancestor of) the canonical main")
        self.assertEqual(self.before(), before)

    def test_a_downgrade_is_refused_even_with_stamp_and_receipt(self):
        self.stamp(self.line(ref=self.c0, extra=" --allow-older"))
        before = self.before()
        with self.assertRaises(ai.InstallError) as caught:
            ai.install_files("t2-dev", self.c0, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner,
                             lambda t, x: None, allow_older=True)
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertIn("--allow-older", str(caught.exception))
        self.assertEqual(self.before(), before)

    def test_a_downgrade_without_allow_older_is_refused_by_the_fetch(self):
        self.stamp(self.line(ref=self.c0, files=("ah.py",)))
        with self.assertRaises(ai.InstallError) as caught:
            ai.install_files("t2-dev", self.c0, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.code, "older_ref")

    def test_the_source_is_the_commit_never_the_working_tree(self):
        (self.work / "harness" / "hooks" / "ah.py").write_text("# uncommitted edit\n")
        self.stamp(self.line())
        self.install()
        want = subprocess.run(["git", "-C", str(self.work), "show", "%s:harness/hooks/ah.py" % self.c1],
                              capture_output=True).stdout
        self.assertEqual(self.live("ah.py"), sha(want))

    def test_resume_and_rollback_of_a_guard_file_are_the_users(self):
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()):
            run = self.install()["run"]
        before = self.before()
        self.stamp(self.line())  # even a live stamp and a good receipt do not let an agent roll back
        with self.assertRaises(ai.InstallError) as caught:
            ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertEqual(self.before(), before)
        # a finished run cannot be resumed at all, so the resume branch of the gate is called directly
        with self.assertRaises(ai.InstallError) as caught:
            ai.guard_gate("t2-dev", self.c1, ["ah.py", "extra.py"], TICKET, self.mac, "resume")
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertEqual(self.receipts, [])
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()):  # positive control: the user may roll back
            self.assertIn(ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)["result"],
                          ("rolled_back", "restored"))
        self.assertNotEqual(self.before(), before)


class Stamps(unittest.TestCase):
    def test_only_a_plain_new_install_is_stamped(self):
        base = "python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --from-ref %s --file ah.py --ticket \"%s\"" % (H40, TICKET)
        self.assertEqual(mission_gate.install_files_stamps(base),
                         [guard_files.install_stamp_parts("t2-dev", H40, ["ah.py"], TICKET)])
        for extra in (" --dry-run", " --allow-older"):
            with self.subTest(extra):
                self.assertEqual(mission_gate.install_files_stamps(base + extra), [])
        for line in ("python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --resume ins-0123456789ab --ticket \"%s\"" % TICKET,
                     base.replace("ah.py --ticket", "$(echo ah.py) --ticket"),
                     "echo " + base.replace("python3 -I ", "")):
            with self.subTest(line[:60]):
                self.assertEqual(mission_gate.install_files_stamps(line), [])


if __name__ == "__main__":
    unittest.main()
