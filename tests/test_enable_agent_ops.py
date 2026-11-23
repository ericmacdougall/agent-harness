"""GoodQA goodqa#16757 (L5 of the self-serve spec): the user-run enabler scripts/enable-agent-ops.py.

AC-1 apply, AC-2 dry run changes nothing, AC-3 undo restores; NEG-1 an agent cannot run it, NEG-3 the pinned SHA and
installed hooks gate it, NEG-11 it never writes Codex trust. Everything runs in temporary HOME directories with a fake
GitHub, a local stand-in for the worker host and a fake terminal; nothing touches a real host.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# ENABLE_OPS_SCRIPT_VARIANT points at a deliberately broken copy for the failing-first runs recorded in the PR.
SCRIPT = Path(os.environ.get("ENABLE_OPS_SCRIPT_VARIANT") or ROOT / "scripts" / "enable-agent-ops.py")
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("enable_agent_ops", SCRIPT)
E = importlib.util.module_from_spec(spec)
sys.modules["enable_agent_ops"] = E
spec.loader.exec_module(E)

REF = "a" * 40
HOOKS = {"alpha.py": b"print('alpha')\n", "beta.py": b"print('beta')\n", "commit_policy.json": b"{}\n"}
USER_RULE = "Bash(git status)"


def snapshot(root: Path) -> dict:
    out = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if rel.split("/")[0] == "Library" or "/Library" in rel:  # the macOS python shim's own cache, not ours
            continue
        if path.is_symlink():
            out[rel] = ("link", os.readlink(path))
        elif path.is_dir():
            out[rel] = ("dir",)
        else:
            out[rel] = ("file", E.sha256(path.read_bytes()), stat.S_IMODE(path.stat().st_mode))
    return out


class FakeEnv:
    def __init__(self, tty=True, table=None, environ=None, answer=None):
        self.tty, self.table, self.env, self.answer = tty, table or {}, environ or {}, answer
        self.prompts = []

    def is_tty(self):
        return self.tty

    def environ(self):
        return dict(self.env)

    def process_table(self):
        return self.table

    def pid(self):
        return 900

    def read_nonce(self, prompt):
        self.prompts.append(prompt)
        if self.answer is not None:
            return self.answer
        return re.search(r"Type (\S+) to continue", prompt).group(1)


class FakeUpstream:
    def __init__(self, blobs, canonical=(REF,)):
        self.blobs, self.canonical = blobs, set(canonical)

    def is_canonical(self, ref):
        return ref in self.canonical

    def hook_blobs(self, ref):
        return dict(self.blobs)


class LocalRemote:
    """Runs the exact remote command string with /bin/sh under a separate HOME, like ssh would."""

    def __init__(self, home: Path, fail=False, real_python=False):
        self.home, self.fail, self.calls, self.real_python = home, fail, [], real_python

    def run(self, host, command, stdin=None, timeout=90):
        if not E.HOST.match(host):
            raise E.Refused("host")
        self.calls.append(command)
        if self.fail and "mktemp" in command:
            return 1, ""
        if command.startswith("python3 -c ") and not self.real_python:  # same code, run in-process for speed
            import io
            saved = (os.environ.get("HOME"), sys.stdin, sys.stdout)
            os.environ["HOME"], sys.stdin, sys.stdout = str(self.home), io.StringIO(stdin.decode()), io.StringIO()
            try:
                exec(E.REMOTE_HASH_CODE, {})
                return 0, sys.stdout.getvalue()
            finally:
                os.environ["HOME"], sys.stdin, sys.stdout = saved
        done = subprocess.run(["/bin/sh", "-c", command], input=stdin, capture_output=True,
                              env={"HOME": str(self.home), "PATH": os.environ["PATH"]})
        return done.returncode, done.stdout.decode()


def install_hooks(home: Path):
    hooks = home / ".claude" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    for name, data in HOOKS.items():
        (hooks / name).write_bytes(data)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="enable-ops-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home, self.remote_home = self.tmp / "home", self.tmp / "remote"
        for home in (self.home, self.remote_home):
            install_hooks(home)
        self.blobs = {n: E.blob_sha(d) for n, d in HOOKS.items()}
        self.lines = []
        self.remote = LocalRemote(self.remote_home)

    def seed_user_files(self):
        (self.home / ".claude" / "CLAUDE.md").write_text("# mine\n\nuser rule one\n")
        (self.home / ".claude" / "settings.json").write_text(json.dumps(
            {"model": "x", "permissions": {"allow": [USER_RULE], "deny": ["Bash(rm *)"]},
             "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}, indent=2) + "\n")
        codex = self.home / ".codex"
        codex.mkdir(parents=True, exist_ok=True)
        (codex / "AGENTS.md").write_text("# codex notes\n")
        (codex / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [
            {"hooks": [{"type": "command", "command": "python3 guard.py", "timeout": 30}]},
            {"hooks": [{"type": "command", "command": "python3 other.py"}]}]}}, indent=2) + "\n")
        (codex / "hooks.state").write_text('{"trusted": "keep"}\n')
        (codex / "config.toml").write_text("[model]\nname = 'x'\n")

    def run_main(self, *args, env=None, upstream=None, remote=None, on_step=None):
        self.lines.clear()
        argv = list(args) + ["--home", str(self.home)]
        code = E.main(argv, env=env or FakeEnv(), upstream=upstream or FakeUpstream(self.blobs),
                      remote=remote or self.remote, out=self.lines.append, on_step=on_step)
        return code

    def apply(self, **kw):
        return self.run_main("--apply", "--ref", REF, **kw)

    @property
    def output(self):
        return "\n".join(self.lines)

    def all_files(self):
        return snapshot(self.home), snapshot(self.remote_home)


class DryRun(Base):
    def test_dry_run_changes_nothing_and_shows_the_plan(self):  # AC-2
        self.seed_user_files()
        before = self.all_files()
        for args in ([], ["--ref", REF]):
            self.assertEqual(self.run_main(*args), 0)
            self.assertEqual(self.all_files(), before)
        self.assertIn("DRY RUN", self.output)
        for cap in E.CAPABILITIES:
            self.assertIn(cap, self.output)
        self.assertIn("self-serve:begin", self.output)
        self.assertIn("ah.py ops *", self.output)

    def test_dry_run_on_an_empty_home_creates_no_directory(self):
        before = snapshot(self.tmp)
        self.assertEqual(self.run_main("--ref", REF), 0)
        self.assertEqual(snapshot(self.tmp), before)
        self.assertFalse((self.home / ".agent-harness").exists())

    def test_dry_run_reports_a_refusing_preflight_without_failing(self):
        self.assertEqual(self.run_main("--ref", "b" * 40), 0)
        self.assertIn("preflight would refuse", self.output)

    def test_status_is_read_only(self):
        before = self.all_files()
        self.assertEqual(self.run_main("--status"), 0)
        self.assertEqual(self.all_files(), before)
        status = json.loads(self.output)
        self.assertFalse(status["policy_file"])


class Apply(Base):
    def test_apply_writes_everything_and_the_policy_verifies(self):  # AC-1
        self.seed_user_files()
        hooks_state = (self.home / ".codex" / "hooks.state").read_bytes()
        config = (self.home / ".codex" / "config.toml").read_bytes()
        self.assertEqual(self.apply(), 0, self.output)
        layout = E.Layout(self.home)
        # policy: signed, 0600, closed capability list, no expiry by default
        policy = json.loads(layout.policy.read_text())
        self.assertEqual(stat.S_IMODE(layout.policy.stat().st_mode), 0o600)
        self.assertEqual((policy["schema"], policy["purpose"]), ("self-serve/1", "self-serve"))
        self.assertEqual(sorted(policy["capabilities"]), sorted(E.CAPABILITIES))
        self.assertIsNone(policy["expires_at"])
        self.assertIsNone(E.verify_policy(policy, E.load_pinned(layout)))
        # key: 0600, pinned locally and on the worker, through a regular temp file
        self.assertEqual(stat.S_IMODE(layout.keyfile.stat().st_mode), 0o600)
        remote_pin = self.remote_home / ".agent-harness" / "policy" / "self-serve-pubkeys.json"
        self.assertTrue(remote_pin.is_file() and not remote_pin.is_symlink())
        self.assertEqual(remote_pin.read_bytes(), layout.pubkeys.read_bytes())
        self.assertEqual(json.loads(remote_pin.read_text())["keys"][0]["key_id"], policy["key_id"])
        self.assertEqual([p.name for p in remote_pin.parent.iterdir()], ["self-serve-pubkeys.json"])
        self.assertTrue(any("mktemp" in c for c in self.remote.calls))
        self.assertFalse(any("/dev/stdin" in c for c in self.remote.calls))
        # marker blocks keep the user's text and carry the generated-by line, without expiry or gated words
        for path in (layout.claude_md, layout.agents_md):
            text = path.read_text()
            self.assertEqual(text.count(E.MARK_BEGIN), 1)
            self.assertIn("which I ran myself", text)
            self.assertIn(policy["policy_id"], text)
            self.assertNotIn("{{", text)
        self.assertTrue(layout.claude_md.read_text().startswith("# mine\n\nuser rule one\n"))
        self.assertTrue(layout.agents_md.read_text().startswith("# codex notes\n"))
        # settings: user rules and keys kept, the five exact rules added
        settings = json.loads(layout.settings.read_text())
        self.assertEqual(settings["model"], "x")
        self.assertEqual(settings["permissions"]["deny"], ["Bash(rm *)"])
        self.assertEqual(settings["permissions"]["allow"][0], USER_RULE)
        for rule in E.ALLOW_RULES.values():
            self.assertIn(rule, settings["permissions"]["allow"])
        for word in ("waive", "approve-top", "keygen", "publish", "gh pr merge", " pin"):
            self.assertFalse([r for r in settings["permissions"]["allow"] if word in r], word)
        # codex hook: appended last, earlier groups byte-identical
        hooks = json.loads(layout.hooks_json.read_text())["hooks"]["PreToolUse"]
        self.assertEqual(len(hooks), 3)
        self.assertEqual(hooks[0]["hooks"][0]["command"], "python3 guard.py")
        self.assertEqual(hooks[2]["hooks"][0]["command"], E.codex_hook_command(layout))
        self.assertTrue(hooks[2]["hooks"][0]["command"].endswith("|| exit 0"))
        # NEG-11: the trust state and config are untouched
        self.assertEqual((self.home / ".codex" / "hooks.state").read_bytes(), hooks_state)
        self.assertEqual((self.home / ".codex" / "config.toml").read_bytes(), config)
        self.assertIn("/hooks", self.output)
        # audit row, journal, backup, status
        row = json.loads(layout.audit.read_text().splitlines()[-1])
        self.assertEqual((row["event"], row["policy_id"], row["ref"]), ("apply", policy["policy_id"], REF))
        run = json.loads(layout.state.read_text())["run"]
        self.assertTrue((layout.work / run / "journal.json").is_file())
        self.assertTrue((layout.backups / ("self-serve-" + run) / "manifest.json").is_file())
        self.run_main("--status")
        status = json.loads(self.output)
        self.assertEqual(status["signature"], "valid")
        self.assertTrue(status["claude_md_block"] and status["agents_md_block"] and status["codex_hook"])
        self.assertTrue(all(status["allow_rules"].values()))

    def test_apply_never_writes_trusted_hash_anywhere(self):  # NEG-11
        self.seed_user_files()
        self.assertEqual(self.apply(), 0)
        for path in self.home.rglob("*"):
            if path.is_file() and path.stat().st_size < 1_000_000:
                self.assertNotIn(b"trusted_hash", path.read_bytes(), str(path))
        written = [p.name for p in (self.home / ".codex").iterdir()]
        self.assertNotIn("hooks.state.json", written)

    def test_apply_on_empty_home_then_reapply_is_refused_until_undone(self):
        self.assertEqual(self.apply(), 0, self.output)
        self.assertEqual(self.apply(), 3)
        self.assertIn("earlier run", self.output)

    def test_expiry_and_scope_options(self):
        self.assertEqual(self.run_main("--apply", "--ref", REF, "--repo", "o/r", "--expires-days", "30"), 0)
        policy = json.loads(E.Layout(self.home).policy.read_text())
        self.assertIsNotNone(policy["expires_at"])
        self.assertEqual(policy["capabilities"]["merge_reviewed_pr"]["scope"]["repos"], ["o/r"])

    def test_skip_remote_is_recorded_and_pins_nothing(self):
        self.assertEqual(self.run_main("--apply", "--ref", REF, "--skip-remote"), 0)
        self.assertFalse((self.remote_home / ".agent-harness").exists())
        self.assertEqual(self.remote.calls, [])

    def test_wrong_nonce_changes_nothing(self):
        before = self.all_files()
        self.assertEqual(self.apply(env=FakeEnv(answer="enable-000000")), 3)
        self.assertIn("nonce did not match", self.output)
        self.assertEqual(self.all_files(), before)

    def test_signing_key_is_reused_and_policy_signature_is_purpose_bound(self):
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        key_before = layout.keyfile.read_bytes()
        self.assertEqual(self.run_main("--undo"), 0)
        self.assertEqual(self.apply(), 0)
        self.assertEqual(layout.keyfile.read_bytes(), key_before)
        policy = json.loads(layout.policy.read_text())
        pinned = E.load_pinned(layout)
        self.assertIsNone(E.verify_policy(policy, pinned))
        forged = {**policy, "purpose": "central-decisions"}
        self.assertIsNotNone(E.verify_policy(forged, pinned))
        self.assertIsNotNone(E.verify_policy({**policy, "key_id": "0" * 16}, pinned))
        self.assertIsNotNone(E.verify_policy({**policy, "disabled": ["x"]}, pinned))


class AgentCannotEnable(Base):  # NEG-1
    def assert_nothing_written(self, code):
        self.assertEqual(code, 3)
        self.assertIn("refused", self.output)
        self.assertFalse((self.home / ".agent-harness").exists())
        self.assertFalse((self.home / ".claude" / "settings.json").exists())

    def test_real_process_without_a_tty_is_refused(self):
        for stdin in (subprocess.DEVNULL, subprocess.PIPE):
            done = subprocess.run([sys.executable, str(SCRIPT), "--apply", "--ref", REF, "--home", str(self.home)],
                                  input=b"yes\nyes\nenable-000000\n" if stdin == subprocess.PIPE else None,
                                  stdin=None if stdin == subprocess.PIPE else stdin,
                                  capture_output=True, timeout=60)
            self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
            self.assertIn(b"human step", done.stdout)
        self.assertFalse((self.home / ".agent-harness").exists())

    def test_every_mutating_mode_refuses_without_a_tty(self):
        for args in (["--apply", "--ref", REF], ["--undo"], ["--disable", "all"], ["--disable", "pool_cleanup"],
                     ["--resume", "20261123T101500Z-ab12cd"]):
            self.assertEqual(self.run_main(*args, env=FakeEnv(tty=False)), 3, args)
            self.assertIn("human step", self.output)
        self.assertFalse((self.home / ".agent-harness").exists())

    def test_bootstrap_refuses_without_a_tty(self):
        self.assertEqual(self.run_main("--bootstrap", "--ref", REF, env=FakeEnv(tty=False)), 3)
        self.assertFalse((self.home / ".agent-harness").exists())

    def test_agent_ancestor_is_refused_even_on_a_tty(self):
        table = {900: (800, "python3 enable-agent-ops.py --apply"), 800: (700, "-zsh"),
                 700: (600, "/Users/x/.local/bin/claude --resume"), 600: (1, "login")}
        self.assert_nothing_written(self.apply(env=FakeEnv(table=table)))
        self.assertIn("ancestor", self.output)
        table[700] = (600, "node /opt/codex/bin/codex exec")
        self.assert_nothing_written(self.apply(env=FakeEnv(table=table)))

    def test_agent_environment_marker_is_refused(self):
        for name in E.AGENT_ENV:
            self.assert_nothing_written(self.apply(env=FakeEnv(environ={name: "1"})))

    def test_unreadable_process_table_fails_closed(self):
        class Broken(FakeEnv):
            def process_table(self):
                raise OSError("ps")
        self.assert_nothing_written(self.apply(env=Broken()))

    def test_agent_ancestor_detection(self):
        table = {10: (9, "bash"), 9: (8, "/Applications/Claude.app/Contents/MacOS/Claude"), 8: (1, "launchd")}
        self.assertEqual(E.agent_ancestor(table, 10)[0], 9)
        self.assertIsNone(E.agent_ancestor({10: (9, "bash"), 9: (1, "Terminal")}, 10))
        self.assertIsNone(E.agent_ancestor({10: (10, "bash")}, 10))  # a cycle ends the walk


class PinnedShaGate(Base):  # NEG-3
    def test_sha_not_on_canonical_main_is_refused(self):
        before = self.all_files()
        self.assertEqual(self.run_main("--apply", "--ref", "c" * 40), 3)
        self.assertIn("not on canonical main", self.output)
        self.assertEqual(self.all_files(), before)

    def test_ref_must_be_a_full_sha(self):
        for ref in ("main", "abc1234", "A" * 40):
            self.assertEqual(self.run_main("--apply", "--ref", ref), 3, ref)
        self.assertEqual(self.run_main("--apply"), 3)

    def test_a_drifted_hook_on_the_mac_is_refused(self):
        (self.home / ".claude" / "hooks" / "alpha.py").write_text("print('edited')\n")
        before = self.all_files()
        self.assertEqual(self.apply(), 3)
        self.assertIn("differ from the pinned SHA on this Mac", self.output)
        self.assertEqual(self.all_files(), before)

    def test_a_missing_hook_on_the_mac_is_refused(self):
        (self.home / ".claude" / "hooks" / "beta.py").unlink()
        self.assertEqual(self.apply(), 3)

    def test_a_drifted_hook_on_the_worker_is_refused(self):
        (self.remote_home / ".claude" / "hooks" / "beta.py").write_text("x\n")
        before = self.all_files()
        self.assertEqual(self.apply(), 3)
        self.assertIn("on t2-dev", self.output)
        self.assertEqual(self.all_files(), before)

    def test_unreachable_worker_stops_before_any_write(self):
        class Down:
            def run(self, *a, **k):
                return 255, ""
        before = snapshot(self.home)
        self.assertEqual(self.apply(remote=Down()), 3)
        self.assertEqual(snapshot(self.home), before)

    def test_upstream_without_the_listed_hooks_is_refused(self):
        class Missing(FakeUpstream):
            def hook_blobs(self, ref):
                raise E.Refused("canonical main at the pinned SHA lacks hooks the installer lists: x.py")
        self.assertEqual(self.apply(upstream=Missing({})), 3)

    def test_the_real_remote_hash_command_matches_git_blob_shas(self):
        remote = LocalRemote(self.remote_home, real_python=True)
        code, out = remote.run("t2-dev", E.remote_hash_command(), json.dumps(sorted(self.blobs) + ["absent.py"]).encode())
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.splitlines()[-1]), {**self.blobs, "absent.py": None})

    def test_hook_manifest_is_read_from_the_installer_source(self):
        self.assertEqual(E.hook_names_from_installer('A=1\nHOOKS = ("a.py", "b.json",\n "c.md")\n'), ["a.py", "b.json", "c.md"])
        with self.assertRaises(E.Refused):
            E.hook_names_from_installer("X = 1\n")


class UndoDisableResume(Base):
    def test_undo_restores_every_file_byte_for_byte(self):  # AC-3
        self.seed_user_files()
        originals = {p: p.read_bytes() for p in [self.home / ".claude" / "CLAUDE.md", self.home / ".claude" / "settings.json",
                                                 self.home / ".codex" / "AGENTS.md", self.home / ".codex" / "hooks.json",
                                                 self.home / ".codex" / "hooks.state", self.home / ".codex" / "config.toml"]}
        remote_before = snapshot(self.remote_home)
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        self.assertNotEqual((self.home / ".claude" / "settings.json").read_bytes(), originals[self.home / ".claude" / "settings.json"])
        self.assertEqual(self.run_main("--undo"), 0, self.output)
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data, str(path))
        self.assertFalse(layout.policy.exists() or layout.pubkeys.exists() or layout.state.exists())
        self.assertTrue(layout.keyfile.exists())  # kept for reuse
        remote_after = snapshot(self.remote_home)
        self.assertFalse([k for k in remote_after if k.endswith("self-serve-pubkeys.json")])
        self.assertEqual({k: v for k, v in remote_after.items() if ".agent-harness" not in k},
                         {k: v for k, v in remote_before.items() if ".agent-harness" not in k})
        self.assertEqual(json.loads(layout.audit.read_text().splitlines()[-1])["event"], "undo")

    def test_undo_on_a_home_that_had_none_of_the_files_removes_what_it_created(self):
        self.assertEqual(self.apply(), 0)
        self.assertEqual(self.run_main("--undo"), 0)
        for rel in (".claude/CLAUDE.md", ".claude/settings.json", ".codex/AGENTS.md", ".codex/hooks.json"):
            self.assertFalse((self.home / rel).exists(), rel)

    def test_undo_keeps_edits_made_after_apply_and_removes_only_its_own_rules(self):
        self.seed_user_files()
        (self.home / ".claude" / "settings.json").write_text(json.dumps(
            {"permissions": {"allow": [E.ALLOW_RULES["ops"], USER_RULE]}}, indent=2) + "\n")  # ops rule is the user's own
        self.assertEqual(self.apply(), 0)
        settings_path = self.home / ".claude" / "settings.json"
        later = json.loads(settings_path.read_text())
        later["permissions"]["allow"].append("Bash(ls *)")
        settings_path.write_text(json.dumps(later, indent=2) + "\n")
        claude_md = self.home / ".claude" / "CLAUDE.md"
        claude_md.write_text(claude_md.read_text() + "\nadded later\n")
        self.assertEqual(self.run_main("--undo"), 0, self.output)
        allow = json.loads(settings_path.read_text())["permissions"]["allow"]
        self.assertEqual(sorted(allow), sorted([E.ALLOW_RULES["ops"], USER_RULE, "Bash(ls *)"]))
        text = claude_md.read_text()
        self.assertNotIn(E.MARK_BEGIN, text)
        self.assertIn("added later", text)
        self.assertIn("user rule one", text)

    def test_undo_with_nothing_applied_is_refused(self):
        self.assertEqual(self.run_main("--undo"), 3)

    def test_failure_midway_stops_without_a_grant_and_resume_finishes(self):
        def boom(step):
            if step == "settings":
                raise RuntimeError("injected")
        self.assertEqual(self.apply(on_step=boom), 1)
        layout = E.Layout(self.home)
        self.assertIn("--resume", self.output)
        self.assertFalse(layout.policy.exists())  # the signed policy is the last step: no grant after a partial run
        state = json.loads(layout.state.read_text())
        self.assertTrue(state["steps"]["settings"].startswith("failed"))
        self.assertEqual(state["steps"]["pin_remote"], "done")
        self.assertEqual(self.apply(), 3)  # a fresh apply does not paper over the partial run
        self.assertEqual(self.run_main("--resume", state["run"]), 0, self.output)
        self.assertTrue(layout.policy.exists())
        self.assertEqual(self.run_main("--status"), 0)
        self.assertEqual(json.loads(self.output)["signature"], "valid")

    def test_remote_failure_is_reported_and_never_falls_back(self):  # NEG-12 for this lane
        remote = LocalRemote(self.remote_home, fail=True)
        self.assertEqual(self.apply(remote=remote), 1)
        self.assertIn("pin_remote", self.output)
        layout = E.Layout(self.home)
        self.assertFalse(layout.policy.exists())
        self.assertFalse((self.remote_home / ".agent-harness").exists())
        self.assertEqual(self.run_main("--undo"), 0)  # rollback of the partial run works
        self.assertFalse(layout.pubkeys.exists())

    def test_undo_after_a_failed_remote_unpin_reports_it(self):
        self.assertEqual(self.apply(), 0)
        class Down:
            def run(self, *a, **k):
                return 255, ""
        self.assertEqual(self.run_main("--undo", remote=Down()), 1)
        self.assertIn("remove it by hand", self.output)

    def test_resume_rejects_a_bad_or_unknown_run(self):
        self.assertEqual(self.run_main("--resume", "../../etc"), 3)
        self.assertEqual(self.run_main("--resume", "20261123T101500Z-ab12cd"), 3)

    def test_disable_one_capability_resigns_and_all_writes_the_kill_switch(self):
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        self.assertEqual(self.run_main("--disable", "pool_cleanup"), 0, self.output)
        policy = json.loads(layout.policy.read_text())
        self.assertEqual(policy["disabled"], ["pool_cleanup"])
        self.assertIsNone(E.verify_policy(policy, E.load_pinned(layout)))
        self.assertEqual(self.run_main("--disable", "nonsense"), 3)
        self.assertEqual(self.run_main("--disable", "all"), 0)
        self.assertTrue(layout.kill.is_file())


class Pieces(unittest.TestCase):
    def test_gated_tier_words_appear_in_no_file_this_lane_writes(self):
        import escalation
        for path in (SCRIPT, ROOT / "templates" / "self-serve-block.md", Path(__file__)):
            self.assertIsNone(escalation.TOP_TERMS.search(path.read_text()), str(path))

    def test_allow_rules_are_exact_and_exclude_forbidden_commands(self):
        self.assertEqual(len(E.ALLOW_RULES), 5)
        for rule in E.ALLOW_RULES.values():
            self.assertTrue(rule.startswith("Bash(") and rule.endswith(")"))
            for word in ("waive", "approve", "keygen", "publish", "pin", "gh pr", "sh -c", "secret"):
                self.assertNotIn(word, rule)

    def test_markers_round_trip_and_malformed_markers_refuse(self):
        block = E.render_block((ROOT / "templates" / "self-serve-block.md").read_text(), E.CAPABILITIES, "p" * 32, "k" * 16)
        for text in ("", "a\n", "a\n\n", "a\n\nb\n"):
            self.assertEqual(E.remove_block(E.add_block(text, block)), text)
        self.assertNotIn(E.MARK_BEGIN, E.remove_block(E.add_block("a", block)))
        self.assertEqual(E.add_block(E.add_block("x\n", block), block).count(E.MARK_BEGIN), 1)
        for bad in (E.MARK_BEGIN + "\n", E.MARK_END + "\n" + E.MARK_BEGIN + "\n", (E.MARK_BEGIN + E.MARK_END) * 2):
            with self.assertRaises(E.Refused):
                E.add_block(bad, block)

    def test_codex_hook_append_is_last_and_idempotent(self):
        existing = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "a"}]}], "Stop": []}}
        once, added = E.append_codex_hook(existing, "cmd")
        twice, again = E.append_codex_hook(once, "cmd")
        self.assertTrue(added and not again)
        self.assertEqual(once, twice)
        self.assertEqual(once["hooks"]["PreToolUse"][0], existing["hooks"]["PreToolUse"][0])
        self.assertEqual(E.remove_codex_hook(once, "cmd"), existing)

    def test_remote_commands_use_regular_files_and_validated_ids(self):
        self.assertNotIn("/dev/stdin", E.remote_pin_command())
        self.assertIn("mktemp", E.remote_pin_command())
        with self.assertRaises(E.Refused):
            E.remote_unpin_command("x; rm -rf ~")
        with self.assertRaises(E.Refused):
            E.Remote().run("bad host;rm", "true")


class InstallWiring(unittest.TestCase):
    def test_installer_places_the_enabler_and_template_in_bin(self):
        import install
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw).resolve()
            preview = install.install_enabler_bin(home, False)
            self.assertIn("would place", preview)
            self.assertFalse((home / ".agent-harness").exists())
            self.assertIn("placed", install.install_enabler_bin(home, True))
            target = home / ".agent-harness" / "bin" / "ah_enable_self_serve.py"
            self.assertEqual(target.read_bytes(), SCRIPT.read_bytes())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual((home / ".agent-harness" / "bin" / "self-serve-block.md").read_bytes(),
                             (ROOT / "templates" / "self-serve-block.md").read_bytes())
            self.assertIn("up to date", install.install_enabler_bin(home, True))
            target.write_text("tampered\n")
            self.assertIn("placed", install.install_enabler_bin(home, True))
            self.assertEqual(target.read_bytes(), SCRIPT.read_bytes())

    def test_the_installed_copy_finds_its_template_and_runs_a_dry_run(self):
        import install
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw).resolve()
            install.install_enabler_bin(home, True)
            done = subprocess.run([sys.executable, str(home / ".agent-harness" / "bin" / "ah_enable_self_serve.py"),
                                   "--home", str(home)], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn("DRY RUN", done.stdout)

    def test_both_installers_call_the_wiring(self):
        for name in ("install.py", "install_codex.py"):
            self.assertIn("install_enabler_bin(args.home, args.apply)", (ROOT / name).read_text())

    def test_installer_refuses_a_symlinked_bin_directory(self):
        import install
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw).resolve()
            (home / ".agent-harness").mkdir()
            (home / "elsewhere").mkdir()
            (home / ".agent-harness" / "bin").symlink_to(home / "elsewhere")
            self.assertIn("skipped", install.install_enabler_bin(home, True))
            self.assertEqual(list((home / "elsewhere").iterdir()), [])


class Bootstrap(Base):
    class RecordingRunner(E.Runner):
        def __init__(self):
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append([str(a) for a in argv])
            return 0

    def fetch_from_worktree(self, ref, dest, runner):
        src = dest / "src"
        for name in (*E.BOOTSTRAP_SURFACE, "harness/hooks/installer_scan.py", "harness/hooks/safe_input.py"):
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, src / name)
        return src

    def boot(self, runner, fetch=None, env=None, upstream=None):
        self.lines.clear()
        params = {"ref": REF, "host": "t2-dev", "skip_remote": False, "repos": [E.REPO], "expires_days": None}
        return E.bootstrap(E.Layout(self.home), params, env=env or FakeEnv(), upstream=upstream or FakeUpstream(self.blobs),
                           runner=runner, out=self.lines.append, fetch=fetch or self.fetch_from_worktree)

    def test_scan_then_repair_on_the_pinned_sha_then_enable(self):
        runner = self.RecordingRunner()
        self.assertEqual(self.boot(runner), 0, self.output)
        shown = [" ".join(c) for c in runner.calls]
        self.assertEqual(len(shown), 3, shown)
        self.assertTrue(shown[0].endswith("repair-harness.sh --ref %s --host t2-dev --check" % REF))
        self.assertTrue(shown[1].endswith("--host t2-dev --apply"))
        self.assertIn("enable-agent-ops.py --apply --ref %s --host t2-dev" % REF, shown[2])
        self.assertIn("installer_scan", self.output)
        report = list((E.Layout(self.home).work).glob("bootstrap-*/installer-scan.json"))
        self.assertEqual(len(report), 1)

    def test_an_unexpected_scan_category_stops_before_repair(self):
        def bad_fetch(ref, dest, runner):
            src = self.fetch_from_worktree(ref, dest, runner)
            with (src / "install_codex.py").open("a") as handle:
                handle.write("\nimport os\nos.system('launchctl load -w /Library/LaunchDaemons/x.plist')\n")
            return src
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused) as caught:
            self.boot(runner, fetch=bad_fetch)
        self.assertIn("unexpected side effects", str(caught.exception))
        self.assertEqual(runner.calls, [])

    def test_a_missing_surface_file_stops_before_repair(self):
        def short_fetch(ref, dest, runner):
            src = self.fetch_from_worktree(ref, dest, runner)
            (src / "install.py").unlink()
            return src
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused):
            self.boot(runner, fetch=short_fetch)
        self.assertEqual(runner.calls, [])

    def test_a_non_canonical_sha_is_refused_before_any_fetch(self):
        runner = self.RecordingRunner()
        fetched = []
        with self.assertRaises(E.Refused):
            self.boot(runner, fetch=lambda *a: fetched.append(a), upstream=FakeUpstream(self.blobs, canonical=()))
        self.assertEqual((runner.calls, fetched), ([], []))

    def test_a_failed_repair_stops_before_the_enabler(self):
        class Fails(self.RecordingRunner):
            def run(self, argv, **kwargs):
                super().run(argv, **kwargs)
                return 2 if "--apply" in argv and "repair-harness.sh" in " ".join(map(str, argv)) else 0
        runner = Fails()
        with self.assertRaises(E.Refused):
            self.boot(runner)
        self.assertFalse(any("enable-agent-ops" in " ".join(c) for c in runner.calls))

    def test_wrong_nonce_stops_before_repair(self):
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused):
            self.boot(runner, env=FakeEnv(answer="bootstrap-000000"))
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
