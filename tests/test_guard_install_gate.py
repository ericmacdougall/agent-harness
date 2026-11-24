"""PR 326a (goodqa#16944): guard-file installs need main's reviewed-release branch, or the not-agent-launched branch,
which is a speed bump against careless agents and not a boundary (PR 345 review F1).

`ah install-files` runs here against the fixtures of tests/test_ah_install.py (a local bare repository stands in for
the canonical URL and a fake ssh runs the real remote program against a temporary host home). The launch check gets a
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
from test_ah_install import NAMES, TICKET, Base, git, sha  # noqa: E402

import ah_install as ai  # noqa: E402
import caller_identity  # noqa: E402
import guard_files  # noqa: E402
import launch_check  # noqa: E402
import merge_gate  # noqa: E402
import mission_gate  # noqa: E402
import release_receipt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
SESSION = "0c0c0c0c-1111-4222-8333-444455556666"
H40 = "b" * 40

# captured shapes of `ps -axo pid=,ppid=,command=` (numbers right-aligned; commands with spaces; kernel threads in brackets)
PS_MACOS = ("    1     0 /sbin/launchd\n  100     1 /usr/libexec/logd\n  412     1 /System/Applications/Utilities/Terminal.app"
            "/Contents/MacOS/Terminal\n  900   412 login -pf eric\n  901   900 -zsh\n  950   901 python3 -I ah.py install-files\n")
PS_LINUX = ("      1       0 /sbin/init\n      2       0 [kthreadd]\n    700       1 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 "
            "startups\n   7001     700 sshd-session: eric [priv]\n   7002    7001 sshd-session: eric@pts/3\n   7003    7002 -bash\n"
            "   7010    7003 python3 -I ah.py install-files\n")


class FakeEnv(launch_check.Env):
    """A process view. The default is a person in Terminal: login -> zsh -> python3."""

    def __init__(self, tty=True, environ=None, table=None, pid=300, table_error=None):
        self.tty, self.env, self.error, self._pid = tty, environ or {}, table_error, pid
        self.table = table if table is not None else {300: (200, "python3 ah.py install-files"), 200: (100, "-zsh"),
                                                      100: (1, "login -pf eric"), 1: (0, "/sbin/launchd")}

    def stdin_is_tty(self):
        return self.tty

    def tty_name(self):
        return "/dev/ttys009"

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
VIA_SSH = FakeEnv(environ={"SSH_CONNECTION": "10.0.0.2 5555 10.0.0.3 22"},
                  table={300: (200, "python3 ah.py install-files"), 200: (110, "-bash"), 110: (100, "sshd-session: eric@pts/1"),
                         100: (1, "sshd: /usr/sbin/sshd -D"), 1: (0, "/sbin/init")})
IN_TMUX = FakeEnv(environ={"TMUX": "/tmp/tmux-1000/default,1,0"},
                  table={300: (200, "python3 ah.py install-files"), 200: (150, "-zsh"), 150: (1, "tmux: server (/tmp/x)"),
                         1: (0, "/sbin/launchd")})


class LaunchCheck(unittest.TestCase):
    def test_a_terminal_with_no_agent_launcher_passes_and_records_its_facts(self):
        reason, facts = launch_check.check(FakeEnv())
        self.assertIsNone(reason)
        self.assertEqual(facts["qualifying_ancestor"], [100, "login"])
        self.assertEqual((facts["tty"], facts["ssh_env"], facts["mux_env"], facts["ssh_ancestor"], facts["mux_ancestor"]),
                         ("/dev/ttys009", [], [], [], []))

    def test_each_missing_fact_refuses(self):
        cases = {
            "stdin not a terminal": FakeEnv(tty=False),
            "agent variable": FakeEnv(environ={"CLAUDECODE": "1"}),
            "codex variable": FakeEnv(environ={"CODEX_THREAD_ID": "t"}),
            "agent ancestor": FakeEnv(table={300: (200, "python3 x"), 200: (150, "-zsh"), 150: (100, "/usr/local/bin/claude"),
                                             100: (1, "login"), 1: (0, "launchd")}),
            "codex ancestor": FakeEnv(table={300: (200, "python3 x"), 200: (100, "codex exec"), 100: (1, "login"),
                                             1: (0, "init")}),
            "detached (no session ancestor)": FakeEnv(table={300: (1, "python3 x"), 1: (0, "/sbin/launchd")}),
            "process table unreadable": FakeEnv(table_error=OSError("ps")),
        }
        for label, env in cases.items():
            with self.subTest(label):
                self.assertIsInstance(launch_check.refusal(env), str)
        self.assertIn("process table", launch_check.refusal(cases["process table unreadable"]))

    def test_ssh_or_a_multiplexer_refuses_unless_the_user_typed_the_flag(self):
        """F1: the ordinary routes by which an agent reaches the user's terminal. Each signal alone refuses."""
        login_chain = {300: (200, "python3 x"), 200: (100, "-zsh"), 100: (1, "login"), 1: (0, "launchd")}
        cases = {
            "ssh session": VIA_SSH, "tmux session": IN_TMUX,
            "SSH_CONNECTION alone": FakeEnv(environ={"SSH_CONNECTION": "a b c d"}, table=login_chain),
            "SSH_TTY alone": FakeEnv(environ={"SSH_TTY": "/dev/pts/1"}, table=login_chain),
            "STY (screen) alone": FakeEnv(environ={"STY": "123.pts-1"}, table=login_chain),
            "sshd ancestor alone": FakeEnv(table={300: (200, "python3 x"), 200: (110, "-bash"), 110: (1, "sshd-session: e"),
                                                  1: (0, "init")}),
            "screen ancestor alone": FakeEnv(table={300: (200, "python3 x"), 200: (150, "-zsh"), 150: (100, "screen"),
                                                    100: (1, "login"), 1: (0, "launchd")}),
        }
        for label, env in cases.items():
            with self.subTest(label):
                reason, facts = launch_check.check(env)
                self.assertIn("ssh connection or a terminal multiplexer", reason or "")
                self.assertFalse(facts["allow_remote"])
                reason, facts = launch_check.check(env, allow_remote=True)
                self.assertIsNone(reason)
                self.assertTrue(facts["allow_remote"])
        self.assertEqual(launch_check.check(VIA_SSH)[1]["ssh_ancestor"], ["sshd-session", "sshd"])
        self.assertEqual(launch_check.check(IN_TMUX)[1]["mux_env"], ["TMUX"])

    def test_the_flag_never_admits_an_agent(self):
        env = FakeEnv(environ={"SSH_CONNECTION": "a b c d", "CLAUDECODE": "1"})
        self.assertIn("agent session variable", launch_check.refusal(env, allow_remote=True))

    def test_only_the_listed_agent_variables_count(self):
        """F6: the exact names, not every CLAUDE_CODE_* or CODEX_* variable (the user may set those in his profile)."""
        self.assertIsNone(launch_check.refusal(FakeEnv(environ={"CLAUDE_CODE_USE_BEDROCK": "1", "CODEX_HOME": "/x"})))
        for name in launch_check.AGENT_ENV:
            with self.subTest(name):
                self.assertIsNotNone(launch_check.refusal(FakeEnv(environ={name: "1"})))

    def test_a_surprise_fails_closed(self):
        env = FakeEnv()
        env.environ = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.assertIn("RuntimeError", launch_check.refusal(env))

    def test_ps_output_of_both_systems_parses_into_the_chain(self):
        """F7: the real parser, on captured macOS and Linux shapes."""
        mac = launch_check.parse_ps(PS_MACOS)
        self.assertEqual(mac[950], (901, "python3 -I ah.py install-files"))
        self.assertEqual(launch_check.ancestors(mac, 950)[:3], [(901, "zsh"), (900, "login"), (412, "Terminal")])
        self.assertEqual(launch_check.interactive_ancestor(mac, 950), (900, "login"))
        linux = launch_check.parse_ps(PS_LINUX)
        self.assertEqual(linux[2], (0, "[kthreadd]"))
        self.assertEqual([n for _, n in launch_check.ancestors(linux, 7010)][:4], ["bash", "sshd-session", "sshd-session", "sshd"])

    def test_this_test_process_under_a_pipe_or_an_agent_is_refused(self):
        """The real Env. When the suite runs under a pipe or an agent, the branch must not hold; when the user runs it in
        his own terminal the answer legitimately differs, so the assertion is skipped there (F7)."""
        if launch_check.Env().stdin_is_tty():
            self.skipTest("stdin is a terminal here")
        self.assertIsNotNone(launch_check.refusal())


class GuardSet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.closure = guard_files.guard_closure(HOOKS)

    def guard(self, name):
        return guard_files.is_guard_file(name) or name in self.closure

    def test_files_guards_read_or_run_are_listed_without_the_closure(self):
        """F-A4 and F9: these stay guard files even where no hooks directory is given (the static list alone)."""
        for name in ("ahc_release.json", "dropbox_budget.conf", "run_probe.py", "run_capped.py", "bg_job.py", "deliver.py",
                     "remote_delete.py", "remote_delete_agent.py", "installer_scan.py", "ah.py", "ah_install.py",
                     "guard_files.py", "launch_check.py", "release_receipt.py", "safe_input.py", "redact.py",
                     "shell_words.py", "shellwords.py"):
            with self.subTest(name):
                self.assertTrue(guard_files.is_guard_file(name))
        self.assertFalse(guard_files.is_guard_file("ledger_reminder.py"))  # positive control

    def test_registered_guard_hooks_and_named_files_are_guard_files(self):
        names = ("command_guard_hook.py", "merge_gate.py", "mission_gate.py", "ah.py", "ah_install.py",
                 "guard_files.py", "launch_check.py", "release_receipt.py", "run_probe.py", "run_capped.py",
                 "ahc_release.json", "dropbox_budget.conf", "installer_scan.py", "deliver.py")
        self.assertEqual(guard_files.guard_subset(names, HOOKS), sorted(names))
        for name in ("run_probe.py", "ahc_release.json", "dropbox_budget.conf"):  # found by the closure as well as listed
            with self.subTest(name):
                self.assertIn(name, self.closure)

    def tree(self, d, manifest, files):
        (d / "hooks_manifest.json").write_text(manifest if isinstance(manifest, str) else json.dumps(manifest))
        for name, text in files.items():
            (d / name).write_text(text)

    def test_a_file_no_guard_reaches_is_not_a_guard_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.tree(d, {"hooks": [{"script": "g.py", "event": "PreToolUse"}]},
                      {"g.py": "import h\nX = 'data.conf'\n", "h.py": "", "data.conf": "", "free.py": ""})
            self.assertEqual(guard_files.guard_subset(["g.py", "h.py", "data.conf", "free.py"], d),
                             ["data.conf", "g.py", "h.py"])

    def test_a_listed_guard_file_is_a_starting_point_of_the_closure(self):
        """F2: what a statically listed guard file imports is a guard file even when no registered hook names it."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.tree(d, {"hooks": [{"script": "g.py", "event": "PreToolUse"}]},
                      {"g.py": "", "deliver.py": "import helper_x\n", "helper_x.py": "", "free.py": ""})
            self.assertEqual(guard_files.guard_subset(["helper_x.py", "free.py"], d), ["helper_x.py"])

    def test_every_file_a_guard_names_in_its_source_is_a_guard_file(self):
        """Independent of the closure walk: a plain text scan of every closure module for names of files in the hooks dir."""
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

    def test_unreadable_or_oddly_shaped_manifest_or_module_makes_every_name_a_guard_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "g.py").write_text("pass\n")
            for label, manifest in {"not json": "{not json", "empty object": "{}", "hooks not a list": '{"hooks": {}}',
                                    "no PreToolUse or Stop row": {"hooks": [{"script": "g.py", "event": "PostToolUse"}]},
                                    "a list": "[]"}.items():
                with self.subTest(label):
                    self.tree(d, manifest, {})
                    self.assertEqual(guard_files.guard_subset(["free.py"], d), ["free.py"])
            self.tree(d, {"hooks": [{"script": "g.py", "event": "Stop"}]}, {})
            self.assertEqual(guard_files.guard_subset(["free.py"], d), [])  # positive control
            (d / "g.py").chmod(0)
            try:
                if os.access(d / "g.py", os.R_OK):
                    self.skipTest("running as a user who can read a mode-000 file")
                self.assertEqual(guard_files.guard_subset(["free.py"], d), ["free.py"])
            finally:
                (d / "g.py").chmod(0o600)

    def test_trees_are_combined(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.tree(Path(a), {"hooks": [{"script": "g.py", "event": "Stop"}]}, {"g.py": "", "x.py": ""})
            self.tree(Path(b), {"hooks": [{"script": "g.py", "event": "Stop"}]}, {"g.py": "import x\n", "x.py": ""})
            self.assertEqual(guard_files.guard_subset(["x.py"], a), [])
            self.assertEqual(guard_files.guard_subset_trees(["x.py"], [a, b]), ["x.py"])


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

    def poster(self, ticket, text):
        pass

    def push(self):
        git(self.tmp, "--git-dir", str(self.origin), "fetch", "-q", str(self.work), "+main:main")

    # --- positive controls

    def test_main_installs_a_reviewed_merged_commit(self):
        self.stamp(self.line())
        out = self.install()
        self.assertEqual(out["result"], "installed")
        self.assertEqual(self.receipts, [self.c1])
        gate = self.rows("start")[-1]["guard_gate"]
        self.assertEqual((gate["branch"], gate["guard_files"], gate["waiver"]), ("main-release", ["ah.py"], "mgw-x"))
        self.assertEqual(gate["facts"]["stdin_tty"], False)  # the launch facts are on main's row too

    def test_a_run_with_no_agent_launcher_needs_no_stamp_and_records_why(self):
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()):
            self.assertEqual(self.install()["result"], "installed")
        self.assertEqual(self.receipts, [])
        gate = self.rows("start")[-1]["guard_gate"]
        self.assertEqual(gate["branch"], "not_agent_launched")
        self.assertEqual((gate["facts"]["qualifying_ancestor"], gate["facts"]["tty"]), ([100, "login"], "/dev/ttys009"))

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

    def test_the_refusal_names_main_route_and_never_steers_to_a_terminal(self):
        """F1 (2): the refusal tells an agent what is the user's and what main may do; no runnable line, no terminal."""
        err = self.assert_refused_unchanged(self.before())
        text = str(err)
        self.assertIn("main's own Bash call", text)
        self.assertNotIn("terminal", text.replace("stdin is not a terminal", ""))
        self.assertNotIn("install-files --host", text)
        self.assertEqual(err.data["launch_facts"]["stdin_tty"], False)
        self.stamp(self.line(ref=self.c0, extra=" --allow-older"))
        with self.assertRaises(ai.InstallError) as caught:
            ai.install_files("t2-dev", self.c0, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner, self.poster,
                             allow_older=True)
        self.assertIn("Guard-file downgrade (--allow-older), --resume and --rollback are the user's", str(caught.exception))
        self.assertNotIn("your own terminal", str(caught.exception))

    def test_a_stamp_covers_only_its_exact_command(self):
        self.stamp(self.line(files=("ah.py",)))
        self.assert_refused_unchanged(self.before())  # ah.py + extra.py is another command
        self.stamp(self.line(ref=self.c0))
        self.assert_refused_unchanged(self.before())  # another ref

    def test_a_stamp_from_a_call_that_has_ended_is_refused(self):
        """The stamp is bound to main's call: once the transcript holds that call's result, a later process with the
        same argv (a copied command after main's call) finds it dead."""
        self.stamp(self.line())
        with self.transcript.open("a") as out:
            out.write(json.dumps({"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_%08d" % self.calls_seen, "content": "done"}]}}) + "\n")
        self.assert_refused_unchanged(self.before())
        self.assertEqual(self.receipts, [])

    def test_a_stamp_is_single_use(self):
        """F4: the SAME command again, with main's call still running, is refused at the gate (code guard_file), not
        reported as already current: the first install used the stamp up."""
        self.stamp(self.line())
        self.assertEqual(self.install()["result"], "installed")
        before = self.before()
        err = self.refused()
        self.assertEqual(err.code, "guard_file")
        self.assertIn("No stamp", str(err))
        self.assertEqual(self.before(), before)
        self.assertEqual(self.receipts, [self.c1])

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
        """F4: a live bound stamp for the exact (ref, files) is put in place by hand (mission_gate makes none for
        --allow-older), so the refusal can only come from the downgrade rule; the stamp is left unused."""
        self.calls_seen += 1
        parts = guard_files.install_stamp_parts("t2-dev", self.c0, ["ah.py"], TICKET)
        self.assertTrue(caller_identity.put_stamp(guard_files.INSTALL_STAMP, parts, session=SESSION, home=self.mac,
                                                  tool_use_id="toolu_%08d" % self.calls_seen, transcript=str(self.transcript)))
        before = self.before()
        with self.assertRaises(ai.InstallError) as caught:
            ai.install_files("t2-dev", self.c0, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner, self.poster,
                             allow_older=True)
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertIn("--allow-older", str(caught.exception))
        self.assertEqual(self.before(), before)
        self.assertEqual(self.receipts, [])
        self.assertIsNotNone(caller_identity.take_stamp(guard_files.INSTALL_STAMP, parts, home=self.mac, bound=True))

    def test_a_downgrade_without_allow_older_is_refused_by_the_fetch(self):
        self.stamp(self.line(ref=self.c0, files=("ah.py",)))
        with self.assertRaises(ai.InstallError) as caught:
            ai.install_files("t2-dev", self.c0, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner, self.poster)
        self.assertEqual(caught.exception.code, "older_ref")

    def test_the_source_is_the_commit_never_the_working_tree(self):
        (self.work / "harness" / "hooks" / "ah.py").write_text("# uncommitted edit\n")
        self.stamp(self.line())
        self.install()
        want = subprocess.run(["git", "-C", str(self.work), "show", "%s:harness/hooks/ah.py" % self.c1],
                              capture_output=True).stdout
        self.assertEqual(self.live("ah.py"), sha(want))

    def test_rollback_of_a_guard_file_is_the_users(self):
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()):
            run = self.install()["run"]
        before = self.before()
        self.stamp(self.line())  # even a live stamp and a good receipt do not let an agent roll back
        with self.assertRaises(ai.InstallError) as caught:
            ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, self.poster)
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertEqual(self.before(), before)
        self.assertEqual(self.receipts, [])
        for env in (VIA_SSH, IN_TMUX):  # F1: over ssh or in a multiplexer, only with the user's flag
            with self.subTest(env.env), mock.patch.object(ai, "PROOF_ENV", env):
                with self.assertRaises(ai.InstallError) as caught:
                    ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, self.poster)
                self.assertIn("multiplexer", str(caught.exception))
                self.assertEqual(self.before(), before)
        with mock.patch.object(ai, "PROOF_ENV", VIA_SSH):  # positive control: the user's own run with the flag
            self.assertIn(ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, self.poster, allow_remote=True)["result"],
                          ("rolled_back", "restored"))
        self.assertNotEqual(self.before(), before)
        gate = [r for r in self.rows("start") if r.get("kind") == "rollback"][-1]["guard_gate"]
        self.assertEqual((gate["branch"], gate["facts"]["allow_remote"]), ("not_agent_launched", True))

    def unknown_install(self):
        """An install by the user whose commit ran on the host and whose answer was lost: an unfinished run."""
        self.inject = ("commit", 1, "after")
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()), self.assertRaises(ai.InstallError) as caught:
            self.install()
        self.inject = None
        return caught.exception.data["run"]

    def test_resume_of_a_guard_file_is_the_users_end_to_end(self):
        """F3: an interrupted run, then an agent with a live stamp for the same command tries --resume. Refused at the
        gate before any fetch, the host untouched, no new start row; the user then resumes it."""
        run = self.unknown_install()
        self.stamp(self.line())
        before = self.before()
        with mock.patch.object(ai, "fetch_source", side_effect=AssertionError("fetched before the gate")):
            with self.assertRaises(ai.InstallError) as caught:
                ai.resume(run, TICKET, self.mac, "s", "a", self.runner, self.poster)
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertIn("--resume", str(caught.exception))
        self.assertEqual(self.before(), before)
        self.assertEqual(self.receipts, [])
        with mock.patch.object(ai, "PROOF_ENV", FakeEnv()):  # positive control
            self.assertEqual(ai.resume(run, TICKET, self.mac, "s", "a", self.runner, self.poster)["result"], "installed")

    def test_a_run_recorded_before_the_gate_counts_every_file_as_a_guard_file(self):
        row = {"files": {"extra.py": {}}}
        self.assertEqual(ai.recorded_guard(row), ["extra.py"])
        self.assertEqual(ai.recorded_guard(dict(row, guard_gate=None)), [])
        self.assertEqual(ai.recorded_guard(dict(row, guard_gate={"guard_files": ["ah.py"]})), ["ah.py"])

    def skew_commit(self):
        """c2: the ref's guard hook ah.py now imports newcheck.py. The Mac's hooks directory (this checkout) has no
        newcheck.py, so only the ref's own tree makes it a guard file (F2, version skew)."""
        hooks = self.work / "harness" / "hooks"
        (hooks / "ah.py").write_text("import newcheck\n# c2\n")
        (hooks / "newcheck.py").write_text("# a module the guard imports\n")
        (hooks / "freecheck.py").write_text("# nothing imports this\n")
        (self.work / "install.py").write_text("HOOKS = %r\n" % (NAMES + ("newcheck.py", "freecheck.py"),))
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "-m", "c2")
        self.push()
        return git(self.work, "rev-parse", "HEAD")

    def test_a_file_that_is_a_guard_file_only_at_the_ref_is_gated(self):
        c2 = self.skew_commit()
        self.assertFalse((HOOKS / "newcheck.py").exists())
        self.assertEqual(guard_files.guard_subset(["newcheck.py"], HOOKS), [])  # the local tree alone misses it
        with self.assertRaises(ai.InstallError) as caught:
            self.install(ref=c2, files=("newcheck.py",))
        self.assertEqual(caught.exception.code, "guard_file")
        self.assertIn("newcheck.py", str(caught.exception))
        self.assertFalse((self.hooks / "newcheck.py").exists())
        self.assertEqual(self.rows("start"), [])
        # positive control: a file nothing at the ref reaches installs without a stamp
        self.assertEqual(self.install(ref=c2, files=("freecheck.py",))["result"], "installed")
        self.assertIsNone(self.rows("start")[-1]["guard_gate"])

    def test_main_installs_a_ref_only_guard_file_with_its_stamp(self):
        c2 = self.skew_commit()
        self.stamp(self.line(ref=c2, files=("newcheck.py",)))
        self.assertEqual(self.install(ref=c2, files=("newcheck.py",))["result"], "installed")
        gate = self.rows("start")[-1]["guard_gate"]
        self.assertEqual((gate["branch"], gate["guard_files"]), ("main-release", ["newcheck.py"]))


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
                     base.replace("--file ah.py", "--file $F"),
                     "echo " + base.replace("python3 -I ", "")):
            with self.subTest(line[:60]):
                self.assertEqual(mission_gate.install_files_stamps(line), [])


if __name__ == "__main__":
    unittest.main()
