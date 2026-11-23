"""Who is calling (goodqa#16441, rescue of the round-2 BLOCK at a810e331): caller identity never comes from the command.

The class the two review rounds found: every rule that read the caller from something the agent controls (a flag, an
argparse abbreviation of it, a session variable, a process name such as an `exec -a sshd` shell, a Codex thread id in
the tool environment) invited one more spelling. The model now:

  * the only trusted identity is the PreToolUse payload's session id, which the host writes and the agent cannot;
  * every other route (the verifier CLI, `ah worktree-remove`, `ah takeover`, ssh, cron) has an UNKNOWN caller, and an
    unknown caller is foreign: a path in work/<S>/ needs S retired by evidence, whoever asks;
  * the hook's own-session route hands the verifier a single-use, short-lived, HMAC'd grant bound to the payload
    session, the path and its HEAD, so an agent still removes its own worktrees (private repositories included).

These tests drive the real entry points with a temporary HOME and fake process facts. They vary every identity source an
agent controls (argv, environment, process names, ancestry) and assert the verdict never changes. Nothing outside the
temporary HOME is removed, signalled or written."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT / "scripts"))
import ah  # noqa: E402
import ah_kill  # noqa: E402
import ah_worktree  # noqa: E402
import command_guard as cg  # noqa: E402
import takeover as tk  # noqa: E402

VICTIM = "01a2012f-bca0-78b0-8fc7-162587de5ee7"
CALLER = "6df7b63f-b062-4fa8-834a-f6bd857d0c54"
URL = "https://github.com/acme/widgets.git"
CLAUDE_EXE = "/Users/u/Library/Application Support/Claude/claude-code/2.1.330/x/claude.app/Contents/MacOS/claude"
START = "Sun Nov 22 03:43:10 2026"
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
IDENTITY_ENV = ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "CODEX_THREAD_ID")
EMPTY_REMOTE = {"version": 1, "host": "t2-dev", "flavors": [], "problems": [], "live": [], "worktrees": [],
                "walless": {"exists": False}, "transcript": False}


def git(cwd, *args):
    done = subprocess.run(["git", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError("git %s: %s" % (" ".join(args), done.stderr))
    return done.stdout.strip()


def iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class EmptyHost:
    """takeover's process probe with nothing running (the evidence side; caller identity never reads it)."""
    host = "local"

    def proc_table(self):
        return {}

    def cwd_scan(self):
        return {}

    def env_pairs(self, pids):
        return {p: set() for p in pids}


class Chain:
    """Fake ancestry for the running process: what `ps` would say about this pid and its parents. Every variant here is
    something an agent can produce from a command line (exec -a, a session variable, a forged environment)."""

    def __init__(self, rows, tokens=None, pairs=None):
        me = os.getpid()
        self.rows = {me if pid == "me" else pid: row for pid, row in rows.items()}
        self.tokens, self.pairs = dict(tokens or {}), {me if k == "me" else k: v for k, v in (pairs or {}).items()}

    def info(self, pid):
        r = self.rows.get(pid)
        return None if r is None else {"pid": pid, "ppid": r[0], "comm": r[1], "command": r[2], "uid": os.getuid(),
                                       "stat": "S", "start": START}

    def start_token(self, pid):
        return self.tokens.get(pid)

    def exe_path(self, pid):
        return self.rows.get(pid, (0, ""))[1]

    def session_pairs(self, pid):
        return set(self.pairs.get(pid, ()))


def chains():
    """name -> Chain. `me` is the verifier process itself."""
    return {
        "orphan": Chain({"me": (400, "/usr/bin/python3", "python3 -I command_guard.py"), 400: (1, "/bin/bash", "bash")}),
        # M1: `exec -a sshd bash -c '...'` under a Claude CLI: ps shows comm and argv0 `sshd` for the shell
        "exec -a sshd": Chain({"me": (400, "/usr/bin/python3", "python3 -I command_guard.py"),
                               400: (350, "sshd", "sshd -c 'python3 ...; true'"), 350: (300, "/bin/zsh", "zsh -c x"),
                               300: (1, CLAUDE_EXE, CLAUDE_EXE + " --x")}, tokens={300: START}),
        "real sshd": Chain({"me": (400, "/usr/bin/python3", "python3 -I command_guard.py"), 400: (300, "bash", "bash -c x"),
                            300: (1, "sshd", "sshd: eric@notty")}),
        # a Claude CLI whose own session record names the victim (the victim itself, or a forged record)
        "claude record": Chain({"me": (400, "/usr/bin/python3", "python3 -I command_guard.py"),
                                400: (300, "/bin/zsh", "zsh -c x"), 300: (1, CLAUDE_EXE, CLAUDE_EXE + " --x")},
                               tokens={300: START}),
        # M3: a Codex tool shell on macOS whose /bin/zsh environment ps hides; python carries the forged thread id
        "codex forged env": Chain({"me": (400, "/opt/homebrew/bin/python3.13", "python3 -I ah.py"),
                                   400: (300, "/bin/zsh", "/bin/zsh -lc x"),
                                   300: (1, "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
                                         "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT")},
                                  pairs={"me": {("codex", VICTIM)}}),
    }


class Fixture(unittest.TestCase):
    """A temporary HOME holding the victim session VICTIM (a Claude WAL here, live: active minutes ago, no stop) and one
    clean, published linked worktree in its work directory."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tk-id-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        patches = [mock.patch.dict(os.environ, {"HOME": str(self.home), "AH_HOME": str(self.home)}),
                   mock.patch.object(cg, "REMOTE_LS", lambda url, repo, timeout: dict(self.live)),
                   mock.patch.object(tk, "HostProbe", EmptyHost),
                   mock.patch.object(tk, "fetch_remote_evidence", lambda old, *a, **k: dict(EMPTY_REMOTE)),
                   mock.patch.object(cg, "HOOK_SESSION", None)]
        for name in IDENTITY_ENV:
            patches.append(mock.patch.dict(os.environ, {name: ""}))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        for name in IDENTITY_ENV:
            os.environ.pop(name, None)
        self.policy = cg.load_policy(path=str(self.home / "missing-policy.json"))
        ah_kill._kill_guard().ensure_key(str(self.home))
        self.victim_session(active=True)
        self.make_worktree()

    def victim_session(self, active):
        now = time.time()
        at = now - 600 if active else now - 3 * 3600
        wal = self.home / ".claude" / "wals" / VICTIM
        wal.mkdir(parents=True, exist_ok=True)
        (wal / "main.jsonl").write_text(json.dumps({"at": iso(at), "event": "intent" if active else "handoff"}) + "\n")
        os.utime(wal / "main.jsonl", (at, at))
        transcript = self.home / ".claude" / "projects" / "-p" / (VICTIM + ".jsonl")
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text(json.dumps({"timestamp": iso(at)}) + "\n")
        os.utime(transcript, (at, at))
        records = self.home / ".claude" / "sessions"
        records.mkdir(parents=True, exist_ok=True)
        # the "claude record" chain's CLI (pid 300) records the victim's id with a matching start time
        (records / "300.json").write_text(json.dumps({"pid": 300, "sessionId": VICTIM, "procStart": START}))

    def make_worktree(self):
        base = self.home / ".agent-harness" / "work" / VICTIM / "T"
        self.primary, self.linked = base / "primary", base / "linked"
        self.primary.mkdir(parents=True)
        git(self.primary, "init", "-q", "-b", "main")
        (self.primary / "a.txt").write_text("one\n")
        git(self.primary, "add", "a.txt")
        git(self.primary, "commit", "-q", "-m", "one")
        git(self.primary, "remote", "add", "origin", URL)
        git(self.primary, "worktree", "add", "-q", "-b", "linked", str(self.linked))
        self.head = git(self.linked, "rev-parse", "HEAD")
        git(self.primary, "update-ref", "refs/remotes/origin/main", self.head)
        git(self.primary, "update-ref", "refs/remotes/origin/linked", self.head)
        self.live = {"refs/heads/main": self.head, "refs/heads/linked": self.head}

    @contextlib.contextmanager
    def identity(self, chain=None, env=None):
        """Run with this fake ancestry (ah_kill.Probe is what any ancestry reader would use) and these variables set."""
        with contextlib.ExitStack() as stack:
            if chain is not None:
                stack.enter_context(mock.patch.object(ah_kill, "Probe", lambda *a, **k: chain))
            if env:
                stack.enter_context(mock.patch.dict(os.environ, env))
            yield

    def verifier(self, *extra, chain=None, env=None):
        """`command_guard.py remove-worktree --path <victim worktree> [extra]`: (exit code, JSON or None on a usage error)."""
        out, err = io.StringIO(), io.StringIO()
        with self.identity(chain, env), redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cg.main(["remove-worktree", "--path", str(self.linked), *extra])
            except SystemExit as stop:
                return stop.code, None
        return code, json.loads(out.getvalue())


class VerifierIdentityContract(Fixture):
    """The verifier never learns the caller from argv, environment or ancestry: one verdict for every variant."""

    def outcome(self, code, data):
        """One comparable verdict: a usage error, or (exit code, removed, reason)."""
        return ("usage error", code) if data is None else (code, data["removed"], data["reason"])

    def assert_one_refusal(self, results):
        """Every variant gives the baseline's verdict, the victim's worktree is still there, and that verdict is the
        live session's refusal (not a missing caller)."""
        baseline = results[0][1]
        differing = {label: got for label, got in results if got != baseline}
        self.assertEqual(differing, {}, "the verdict changed with the identity source (baseline %r)" % (baseline,))
        self.assertTrue(self.linked.exists(), "a variant removed the victim's worktree")
        self.assertEqual(baseline[:2], (1, False), baseline)
        self.assertTrue(baseline[2].startswith("foreign session %s is live" % VICTIM), baseline)

    def test_ancestry_never_changes_the_verdict(self):
        results = [("baseline", self.outcome(*self.verifier()))]
        for name, chain in chains().items():
            results.append((name, self.outcome(*self.verifier(chain=chain))))
        self.assert_one_refusal(results)

    def test_identity_variables_never_change_the_verdict(self):
        results = [("baseline", self.outcome(*self.verifier()))]
        for name in IDENTITY_ENV:
            for chain_name in ("orphan", "codex forged env", "claude record", "exec -a sshd"):
                got = self.verifier(chain=chains()[chain_name], env={name: VICTIM})
                results.append(("%s=VICTIM under %s" % (name, chain_name), self.outcome(*got)))
        self.assert_one_refusal(results)

    def test_a_codex_thread_id_in_the_tool_environment_is_not_the_caller(self):
        """M3: a live Codex victim, and a tool started after `printf -v CODEX_THREAD_ID <victim>; export` under a Codex
        host whose shell environment ps hides."""
        import shutil
        shutil.rmtree(self.home / ".claude" / "wals" / VICTIM)
        now = time.time() - 120
        wal = self.home / ".agent-harness" / "codex-wals" / VICTIM
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"at": iso(now), "event": "PreToolUse"}) + "\n")
        (wal / "continuation.json").write_text(json.dumps({"interrupt": None, "state": "active", "used": False}))
        rollout = self.home / ".codex" / "sessions" / "2026" / "11" / "23" / ("rollout-2026-11-23T01-00-00-%s.jsonl" % VICTIM)
        rollout.parent.mkdir(parents=True)
        rollout.write_text(json.dumps({"timestamp": iso(now)}) + "\n")
        results = [("baseline", self.outcome(*self.verifier()))]
        with mock.patch.object(ah_kill, "PLATFORM", "darwin"):
            for env in ({"CODEX_THREAD_ID": VICTIM}, {}):
                got = self.verifier(chain=chains()["codex forged env"], env=env)
                results.append(("codex chain, env %s" % sorted(env), self.outcome(*got)))
        self.assert_one_refusal(results)

    def test_no_caller_flag_or_abbreviation_exists(self):
        """M2 and round 1: --caller-session and every argparse prefix of it are usage errors, under any ancestry."""
        accepted = []
        for flag in ("--caller-session", "--caller-s", "--caller", "--call", "--c"):
            for chain_name in ("real sshd", "exec -a sshd", "orphan"):
                code, data = self.verifier(flag, VICTIM, chain=chains()[chain_name])
                if data is not None or code != 2:
                    accepted.append((flag, chain_name, self.outcome(code, data)))
        self.assertEqual(accepted, [], "these spellings were parsed as an option")
        self.assertTrue(self.linked.exists())

    def test_a_retired_victim_is_removable_by_anyone_and_the_answer_does_not_depend_on_who(self):
        self.victim_session(active=False)  # a handoff three hours ago
        for name, chain in (("orphan", chains()["orphan"]), ("claude record", None)):
            with self.subTest(chain=name):
                code, data = self.verifier(chain=chain)
                self.assertEqual((code, data["removed"]), (0, True), data)
                git(self.primary, "worktree", "add", "-q", "-b", "again-" + name.replace(" ", "-"), str(self.linked))
                head = git(self.linked, "rev-parse", "HEAD")
                self.live["refs/heads/again-" + name.replace(" ", "-")] = head
                git(self.primary, "update-ref", "refs/remotes/origin/again-" + name.replace(" ", "-"), head)


class AhRoutesRelayNoIdentity(Fixture):
    """`ah worktree-remove` and `ah kill --takeover-of` pass no caller to anything, whatever the ancestry or environment."""

    def test_ah_worktree_remove_hands_the_verifier_no_caller(self):
        for name, chain in chains().items():
            for env in ({}, {"CLAUDE_CODE_SESSION_ID": VICTIM}, {"CODEX_THREAD_ID": VICTIM}):
                with self.subTest(chain=name, env=env):
                    seen = []

                    def fake_remove(*args, **kwargs):
                        seen.append((args, kwargs))
                        return {"ok": False, "removed": False}
                    with self.identity(chains()[name], env), mock.patch.object(ah_worktree, "remove", fake_remove):
                        ah.run(ah.build_parser().parse_args(["worktree-remove", "--host", "local", "--path", str(self.linked),
                                                             "--reason", "r"]), self.home)
                    _args, kwargs = seen[0]
                    # the positional session/agent are audit labels only; nothing may hand the verifier a caller
                    self.assertFalse(kwargs.get("caller_session"), "a caller was relayed: %r" % kwargs)

    def test_ah_worktree_remove_builds_no_caller_flag_for_either_host(self):
        argv = []

        def runner(command, **kwargs):
            argv.append(command)
            return subprocess.CompletedProcess(command, 1, json.dumps({"removable": False, "removed": False,
                                                                       "verifier": cg.VERIFIER_VERSION, "reason": "x"}), "")
        for host in ("local", "t2-dev"):
            with self.identity(chains()["claude record"], {"CLAUDE_CODE_SESSION_ID": VICTIM}):
                try:
                    ah_worktree.remove(host, str(self.linked), "r", home=self.home, runner=runner)
                except ah_worktree.WorktreeError:
                    pass
        self.assertEqual(len(argv), 2)
        for command in argv:
            self.assertNotIn("caller", " ".join(command))


class TakeoverVerdictContract(Fixture):
    """`ah takeover status` gives one verdict whatever the caller's ancestry or environment says (including when it names
    the judged session itself)."""

    def status(self, chain=None, env=None):
        out = io.StringIO()
        with self.identity(chain, env), redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            ah.main(["takeover", "status", "--from", VICTIM])
        return json.loads(out.getvalue())

    def test_the_verdict_is_the_same_for_every_identity_source(self):
        self.victim_session(active=False)
        (self.home / ".claude" / "wals" / CALLER).mkdir(parents=True)
        base = self.status()
        self.assertEqual((base["state"], base["reasons"]), ("retired", []), base)
        for name, chain in chains().items():
            for env in ({}, {"CLAUDE_CODE_SESSION_ID": CALLER}, {"CODEX_THREAD_ID": VICTIM},
                        {"CLAUDE_CODE_SESSION_ID": VICTIM}):
                with self.subTest(chain=name, env=env):
                    got = self.status(chains()[name], env)
                    self.assertEqual((got["state"], got["reasons"]), (base["state"], base["reasons"]))

    def test_a_live_session_is_live_for_everyone_including_itself(self):
        base = self.status()
        self.assertEqual(base["state"], "live", base)
        for env in ({"CLAUDE_CODE_SESSION_ID": VICTIM}, {"CODEX_THREAD_ID": VICTIM}):
            with self.subTest(env=env):
                self.assertEqual(self.status(chains()["claude record"], env)["state"], "live")


class OwnRouteGrant(Fixture):
    """The own-session route keeps working: the PreToolUse hook knows the session from its payload and hands the verifier
    a single-use grant for that path. The grant is bound to the payload session, the path and its HEAD."""

    COMMAND = "python3 -I ~/.claude/hooks/ah.py worktree-remove --host local --path %s --reason 'own cleanup'"

    def hook(self, session, command, cwd=None, cli=None):
        """The hook as the Claude CLI runs it: the CLI above it records the payload's session (`cli` overrides that, for
        a payload piped into the hook from some other session's shell)."""
        payload = {"session_id": session, "tool_name": "Bash", "tool_input": {"command": command},
                   "cwd": cwd or str(self.home)}
        above = session if cli is None else cli
        with mock.patch.object(cg, "decide", lambda *a, **k: ("allow", "")), \
                mock.patch.object(tk, "hook_cli_session", lambda home, probe=None, pid=None: above), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cg.hook_main(stdin_bytes=json.dumps(payload).encode(), marker=False)

    def test_a_forged_payload_piped_into_the_hook_gets_no_grant(self):
        # `echo '{"session_id": VICTIM, ...}' | command_guard.py hook` from the agent's own shell: the Claude CLI above
        # that hook records the agent's session, not the victim's
        for cli in (CALLER, None, ""):
            with self.subTest(cli=cli):
                payload = {"session_id": VICTIM, "tool_name": "Bash", "tool_input": {"command": self.COMMAND % self.linked},
                           "cwd": str(self.home)}
                with mock.patch.object(cg, "decide", lambda *a, **k: ("allow", "")), \
                        mock.patch.object(tk, "hook_cli_session", lambda home, probe=None, pid=None: cli), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    cg.hook_main(stdin_bytes=json.dumps(payload).encode(), marker=False)
                code, data = self.verifier()
                self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
                self.assertTrue(self.linked.exists())

    def test_the_cli_above_the_hook_is_found_only_through_a_valid_record(self):
        record = self.home / ".claude" / "sessions" / "300.json"
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(json.dumps({"pid": 300, "sessionId": VICTIM, "procStart": START}))
        found = {name: tk.hook_cli_session(str(self.home), probe=chain) for name, chain in chains().items()}
        self.assertEqual(found["claude record"], VICTIM, "the CLI that really runs the hook")
        for name in ("orphan", "real sshd", "codex forged env"):
            self.assertIsNone(found[name], name)
        record.write_text(json.dumps({"pid": 300, "sessionId": VICTIM, "procStart": "Mon Jan  1 00:00:00 2024"}))
        self.assertIsNone(tk.hook_cli_session(str(self.home), probe=chains()["claude record"]), "a stale record")
        record.unlink()
        self.assertIsNone(tk.hook_cli_session(str(self.home), probe=chains()["claude record"]), "no record")

    def test_the_owner_hook_grant_lets_the_verifier_remove_its_own_worktree_once(self):
        self.assertEqual(self.hook(VICTIM, self.COMMAND % self.linked), 0)
        code, data = self.verifier()
        self.assertEqual((code, data["removed"]), (0, True), data)
        self.assertFalse(self.linked.exists())

    def test_the_grant_is_single_use(self):
        self.hook(VICTIM, self.COMMAND % self.linked)
        # a grant is consumed by the first verifier run on its path, removed or not
        with mock.patch.object(cg, "REMOTE_LS", lambda url, repo, timeout: {}):
            code, data = self.verifier()
        self.assertEqual(data["removed"], False, data)
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())

    def test_another_sessions_payload_or_path_gets_no_grant(self):
        self.hook(CALLER, self.COMMAND % self.linked)  # the payload names another session than the path's owner
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())

    def test_a_grant_for_a_moved_head_is_refused(self):
        self.hook(VICTIM, self.COMMAND % self.linked)
        (self.linked / "b.txt").write_text("two\n")
        git(self.linked, "add", "b.txt")
        git(self.linked, "commit", "-q", "-m", "two")
        head = git(self.linked, "rev-parse", "HEAD")
        self.live["refs/heads/linked"] = head
        git(self.primary, "update-ref", "refs/remotes/origin/linked", head)
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())

    def test_the_check_subcommand_issues_no_grant(self):
        with contextlib.redirect_stdout(io.StringIO()):
            cg.main(["check", "--session", VICTIM, self.COMMAND % self.linked])
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())

    def test_a_forged_grant_file_is_refused(self):
        self.hook(VICTIM, self.COMMAND % self.linked)
        folder = self.home / ".agent-harness" / "takeover" / "grants"
        files = [p for p in folder.iterdir() if p.suffix == ".json"]
        self.assertEqual(len(files), 1)
        data = json.loads(files[0].read_text())
        files[0].write_text(json.dumps(dict(data, exp=data["exp"] + 3600)))
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())

    def test_a_grant_signed_with_another_key_is_refused(self):
        # every field valid and fresh; only the HMAC comes from a key the agent made up
        import hashlib
        import hmac as _hmac
        head = git(self.linked, "rev-parse", "HEAD")
        data = {"v": 1, "session": VICTIM, "path": str(self.linked), "head": head, "exp": int(time.time()) + 60,
                "nonce": "0" * 32}
        data["hmac"] = _hmac.new(b"k" * 32, tk._canonical(data).encode(), hashlib.sha256).hexdigest()
        folder = self.home / ".agent-harness" / "takeover" / "grants"
        folder.mkdir(parents=True, exist_ok=True)
        Path(tk._grant_file(str(self.home), str(self.linked))).write_text(json.dumps(data))
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())

    def test_a_valid_grant_of_another_session_for_the_path_is_refused(self):
        head = git(self.linked, "rev-parse", "HEAD")
        self.assertTrue(tk.issue_grant(str(self.home), CALLER, str(self.linked), head))
        code, data = self.verifier()
        self.assertTrue(data["reason"].startswith("foreign session %s" % VICTIM), data)
        self.assertTrue(self.linked.exists())


class TwoHostVerdict(Fixture):
    """The verifier on the Mac reads t2-dev's evidence before it lets a locally retired session go."""

    @unittest.skipIf(sys.platform.startswith("linux"), "t2-dev judges its own host only")
    def test_a_session_retired_here_but_recorded_on_t2_dev_too_is_refused(self):
        self.victim_session(active=False)
        remote = dict(EMPTY_REMOTE, flavors=["claude"])  # the same id has a WAL on t2-dev: ambiguous_session
        with mock.patch.object(tk, "fetch_remote_evidence", lambda old, *a, **k: dict(remote)):
            code, data = self.verifier()
        self.assertEqual((code, data["removed"]), (1, False), data)
        self.assertIn("foreign session %s" % VICTIM, data["reason"])
        self.assertTrue(self.linked.exists())


class ForgedContinuationIsOnlyAClaim(Fixture):
    """Round 1 `wal.py continuation --wal <other>`: writing another session's checkpoint to `complete` is no identity
    question any more. It counts as a declared stop, exactly like a self-service claim, and it restarts the quiet window
    (the checkpoint's mtime is activity), so the session stays live until R3, R4 and R5 hold anyway."""

    def test_a_forged_complete_restarts_the_quiet_window(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("codex_wal_id", ROOT / "codex" / "hooks" / "wal.py")
        wal = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wal)
        old = time.time() - 3 * 3600
        folder = self.home / ".agent-harness" / "codex-wals" / CALLER
        folder.mkdir(parents=True)
        (folder / "main.jsonl").write_text(json.dumps({"at": iso(old), "event": "PreToolUse"}) + "\n")
        os.utime(folder / "main.jsonl", (old, old))
        rollout = self.home / ".codex" / "sessions" / "2026" / "11" / "21" / ("rollout-2026-11-21T19-57-15-%s.jsonl" % CALLER)
        rollout.parent.mkdir(parents=True)
        rollout.write_text(json.dumps({"timestamp": iso(old)}) + "\n")
        os.utime(rollout, (old, old))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            wal.checkpoint(CALLER, "complete")  # what `wal.py continuation --wal <other> complete` does
        verdict = tk.session_state(CALLER, "worktrees", str(self.home), EmptyHost(), time.time(), tk.LOCAL_ONLY)
        self.assertEqual(verdict["state"], "live", verdict)
        self.assertIn("recent_activity", verdict["reasons"])


class StaleHelpersPinned(Fixture):
    """m2: the stale-helper stop pins every pid to its start time and re-checks it is still a stale helper."""

    def test_stale_helpers_are_stopped_with_expect_and_a_predicate(self):
        helper = "/Applications/ChatGPT.app/Contents/Frameworks/X Framework.framework/Versions/1.2/Helpers/browser_crashpad_handler"

        class Table(EmptyHost):
            def proc_table(self):
                return {300: {"ppid": 1, "start": 1700000000, "command": helper + " --x", "comm": helper}}

            def info(self, pid):
                return {"pid": pid, "ppid": 1, "uid": os.getuid(), "stat": "S", "comm": helper, "command": helper,
                        "start": START}
        calls = []

        def kill_local(pids, reason, **kw):
            calls.append((pids, kw))
            return {"ok": True, "results": [{"pid": p, "status": "would-stop"} for p in pids]}
        ctx = tk.Context(self.home, probe=Table(), kill_local=kill_local, ticket_lookup=lambda t: True, host="mac")
        with mock.patch.object(ah_kill, "PLATFORM", "darwin"), \
                mock.patch.object(ah_kill, "stale_app_helper", lambda info, probe: {"ver": "1.2"}):
            tk.cleanup("none", "stale-helpers", ctx, "old version", "GoodQA goodqa#16441", apply=True)
        pids, kw = calls[0]
        self.assertEqual(pids, [300])
        self.assertEqual(kw.get("expect"), {300: 1700000000})
        self.assertTrue(callable(kw.get("predicate")))
        with mock.patch.object(ah_kill, "stale_app_helper", lambda info, probe: None):
            self.assertFalse(kw["predicate"](Table(), Table().info(300)), "a pid that is no longer a stale helper")


class ClaudeExecutable(unittest.TestCase):
    """m3: a Claude CLI is recognised by its exact executable shape, never by a path component that contains "claude"."""

    def test_exact_shapes(self):
        good = ("/home/eric/.local/share/claude/versions/2.1.330", CLAUDE_EXE, "/Users/u/.local/bin/claude")
        bad = ("/Users/u/.claude/hooks/claude", "/Users/u/.claude/x", "/tmp/claude", "/Users/u/work/claude-tools/python3",
               "/home/eric/.local/share/claude/versions/2.1.330/../../../bin/sh", "sshd", "")
        for path in good:
            self.assertTrue(tk.CLAUDE_EXE.search(path), path)
        for path in bad:
            self.assertFalse(tk.CLAUDE_EXE.search(path), path)


class NoAbbreviations(unittest.TestCase):
    """Every argparse parser of the touched tools refuses prefixes (M2): a recorder sees each parser as it is built."""

    def built(self, build):
        made = []
        real = __import__("argparse").ArgumentParser.__init__

        def record(parser, *a, **k):
            real(parser, *a, **k)
            made.append(parser)
        with mock.patch.object(__import__("argparse").ArgumentParser, "__init__", record), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                build()
            except SystemExit:
                pass
        return made

    def test_every_parser_has_allow_abbrev_off(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("codex_wal_abbrev", ROOT / "codex" / "hooks" / "wal.py")
        cwal = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cwal)
        import enable_takeover_cleanup as enable
        builders = {"ah": ah.build_parser, "command_guard": lambda: cg.main(["--help"]),
                    "codex wal": lambda: (setattr(sys, "argv", ["wal.py", "--help"]), cwal.main()),
                    "enable_takeover_cleanup": enable.build_parser}
        argv = sys.argv[:]
        try:
            for name, build in builders.items():
                with self.subTest(tool=name):
                    made = self.built(build)
                    self.assertGreater(len(made), 0)
                    loose = [p.prog for p in made if p.allow_abbrev]
                    self.assertEqual(loose, [], "%s parsers that accept abbreviations" % name)
        finally:
            sys.argv[:] = argv

    def test_the_review_spellings_are_usage_errors(self):
        import enable_takeover_cleanup as enable
        cases = ((enable.build_parser(), ["--ref", "a" * 40, "--repo", "/r", "--app"]),
                 (enable.build_parser(), ["--ref", "a" * 40, "--repo", "/r", "--und"]),
                 (ah.build_parser(), ["takeover", "cleanup", "--from", VICTIM, "--act", "worktrees", "--reason", "r",
                                      "--ticket", "GoodQA goodqa#1"]),
                 (ah.build_parser(), ["worktree-remove", "--host", "local", "--pa", "/x", "--reason", "r"]))
        for parser, argv in cases:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(argv)


class EnableScriptGuard(unittest.TestCase):
    """The user's enable script: --apply and --undo (and any prefix of them) are refused for agents in both entry
    points and by the guard rule, which covers the .sh and the .py."""

    SH = ROOT / "scripts" / "enable-takeover-cleanup.sh"

    def test_the_guard_rule_covers_both_names_and_every_prefix(self):
        refused = (
            "bash scripts/enable-takeover-cleanup.sh --ref %s --repo /r --apply" % ("a" * 40),
            "python3 scripts/enable_takeover_cleanup.py --ref %s --repo /r --apply" % ("a" * 40),
            "python3 -IB scripts/enable_takeover_cleanup.py --ref x --repo y --undo",
            "scripts/enable-takeover-cleanup.sh --app", "scripts/enable-takeover-cleanup.sh --u",
            "env -u CLAUDECODE -u CLAUDE_CODE_SESSION_ID script -q /dev/null python3 scripts/enable_takeover_cleanup.py --apply",
            "exec -a x bash -c 'scripts/enable-takeover-cleanup.sh --apply; true'",
            "scripts/enable-takeover-cleanup.sh --apply=1",
            "scripts/enable-takeover-cleanup.sh --ref x --repo y --hooks --undo",
        )
        allowed = (
            "bash scripts/enable-takeover-cleanup.sh --ref %s --repo /r --dry-run" % ("a" * 40),
            "python3 scripts/enable_takeover_cleanup.py --ref x --repo /r --verify --host local",
            "grep -n -- --apply scripts/enable-takeover-cleanup.sh",
        )
        for command in refused:
            with self.subTest(command=command):
                self.assertTrue(cg.takeover_rules_refusal(command, None), command)
        for command in allowed:
            with self.subTest(command=command):
                self.assertIsNone(cg.takeover_rules_refusal(command, None), command)

    def test_the_shell_front_refuses_a_prefix_in_an_agent_environment(self):
        for flag in ("--apply", "--app", "--a", "--undo", "--und"):
            with self.subTest(flag=flag):
                done = subprocess.run(["bash", str(self.SH), "--ref", "a" * 40, "--repo", "/nonexistent", flag],
                                      env=dict(os.environ, CLAUDECODE="1"), capture_output=True, text=True,
                                      stdin=subprocess.DEVNULL, timeout=60)
                self.assertEqual(done.returncode, 4, done.stderr + done.stdout)
                self.assertIn("refused", done.stderr + done.stdout)


if __name__ == "__main__":
    unittest.main()
