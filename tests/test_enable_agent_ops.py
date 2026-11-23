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


class FakeHandle:
    def __init__(self, env):
        self.env = env

    def close(self):
        return not self.env.dialog_dismissed


class FakeEnv:
    """oob=True models the native dialog: the code goes to `shown`, never into the prompt."""

    def __init__(self, tty=True, table=None, environ=None, answer=None, oob=False, dialog_dismissed=False,
                 on_nonce=None, session_proof=False):
        self.tty, self.table, self.env, self.answer = tty, table or {}, environ or {}, answer
        self.oob, self.dialog_dismissed, self.on_nonce, self.proof = oob, dialog_dismissed, on_nonce, session_proof
        self.prompts, self.shown = [], []

    def is_tty(self):
        return self.tty

    def environ(self):
        return dict(self.env)

    def process_table(self):
        return self.table

    def pid(self):
        return 900

    def session_proof_required(self):
        return self.proof

    def present_code(self, code, label):
        if not self.oob:
            return None
        self.shown.append(code)
        return FakeHandle(self)

    def read_nonce(self, prompt):
        self.prompts.append(prompt)
        if self.on_nonce:
            self.on_nonce()
        if self.answer is not None:
            return self.answer
        if self.shown:
            return self.shown[-1]
        return re.search(r"Type (\S+) to continue", prompt).group(1)


class FakeUpstream:
    def __init__(self, blobs, canonical=(REF,)):
        self.blobs, self.canonical = blobs, set(canonical)

    def is_canonical(self, ref):
        return ref in self.canonical

    def hook_blobs(self, ref):
        return dict(self.blobs)


class FakeParity:
    """The seam for ah_parity.verify_gate: records exactly what the enabler asked and answers with a report."""

    def __init__(self, ok=True, gate=(), error=None, warnings=()):
        self.ok, self.gate, self.error, self.calls, self.warnings = ok, list(gate), error, [], list(warnings)

    def __call__(self, layout, ref):
        self.calls.append(ref)
        report = {"ok": self.ok, "gate": list(self.gate), "error": self.error, "hosts": {}}
        if self.warnings:
            report["hosts"] = {"mac": {"status": "CLEAN", "warnings": list(self.warnings)}}
            report["warnings"] = list(self.warnings)
        return report


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

    def run_main(self, *args, env=None, upstream=None, remote=None, on_step=None, parity=None):
        self.lines.clear()
        argv = list(args) + ["--home", str(self.home)]
        self.parity = parity or FakeParity()
        code = E.main(argv, env=env or FakeEnv(), upstream=upstream or FakeUpstream(self.blobs),
                      remote=remote or self.remote, out=self.lines.append, on_step=on_step, parity=self.parity)
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

    def test_an_unlisted_importable_file_warns_by_name_and_does_not_refuse(self):  # goodqa#16810
        warning = "claude: unexpected importable file or package codex_pool.py"
        self.assertEqual(self.apply(parity=FakeParity(ok=True, warnings=[warning])), 0, self.output)
        self.assertIn("WARN (not a failure): " + warning, self.output)

    def test_a_refusing_gate_report_still_refuses_whatever_it_warns(self):
        before = self.all_files()
        self.assertEqual(self.apply(parity=FakeParity(ok=False, gate=["drift"], warnings=["w"])), 3)
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
        self.assertIn("run --undo again", self.output)
        self.assertTrue(E.Layout(self.home).state.exists())

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

    CLOSURE = ("netwatch_install.py", "log_backup_install.py", "mission_control_install.py", "harness/hooks/installer_scan.py", "harness/hooks/safe_input.py")

    def setUp(self):
        super().setUp()
        hooks = self.home / ".claude" / "hooks"  # the independently installed scanner (not the checkout's)
        for name in ("installer_scan.py", "safe_input.py"):
            shutil.copy(ROOT / "harness" / "hooks" / name, hooks / name)

    def fetch_from_worktree(self, ref, dest, runner):
        src = dest / "src"
        for name in (*E.BOOTSTRAP_SURFACE, *self.CLOSURE):
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, src / name)
        return src

    def boot(self, runner, fetch=None, env=None, upstream=None):
        self.lines.clear()
        params = {"ref": REF, "host": "t2-dev", "skip_remote": False, "repos": [E.REPO], "expires_days": None}
        return E.bootstrap(E.Layout(self.home), params, env=env or FakeEnv(), upstream=upstream or FakeUpstream(self.blobs),
                           runner=runner, out=self.lines.append, fetch=fetch or self.fetch_from_worktree)

    def src_dir(self):
        return next((E.Layout(self.home).work).glob("bootstrap-*")) / "src"

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


    def test_the_scan_surface_follows_what_the_installers_import(self):  # repair round, finding 4
        names = E.surface_names(self.fetch_from_worktree(REF, self.tmp / "s", None))
        for needed in ("scripts/repair_harness.py", "netwatch_install.py", "log_backup_install.py", "mission_control_install.py"):
            self.assertIn(needed, names)

    def test_a_new_import_added_to_an_installer_joins_the_scanned_surface(self):
        def fetch(ref, dest, runner):
            src = self.fetch_from_worktree(ref, dest, runner)
            (src / "harness" / "hooks" / "sidecar.py").write_text("import os\nos.system('launchctl load -w /Library/LaunchDaemons/x.plist')\n")
            with (src / "install.py").open("a") as handle:
                handle.write("\nimport sidecar\n")
            return src
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused) as caught:
            self.boot(runner, fetch=fetch)
        self.assertIn("unexpected side effects", str(caught.exception))
        self.assertEqual(runner.calls, [])

    def test_launchd_is_expected_only_in_the_opt_in_log_backup_installer(self):
        def fetch(ref, dest, runner):
            src = self.fetch_from_worktree(ref, dest, runner)
            with (src / "netwatch_install.py").open("a") as handle:
                handle.write("\nimport os\nos.system('launchctl load -w /Library/LaunchDaemons/x.plist')\n")
            return src
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused):
            self.boot(runner, fetch=fetch)
        self.assertEqual(runner.calls, [])

    def swap(self, relative, text="print('swapped')\n"):
        (self.src_dir() / relative).write_text(text)

    def test_a_file_swapped_while_the_user_reads_the_report_is_refused(self):
        for relative in ("scripts/repair_harness.py", "scripts/enable-agent-ops.py", "harness/hooks/safe_input.py"):
            self.setUp()
            runner = self.RecordingRunner()
            with self.assertRaises(E.Refused, msg=relative) as caught:
                self.boot(runner, env=FakeEnv(on_nonce=lambda r=relative: self.swap(r)))
            self.assertIn("changed after it was scanned", str(caught.exception))
            self.assertEqual(runner.calls, [], relative)

    def test_a_file_added_after_the_scan_is_refused(self):
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused):
            self.boot(runner, env=FakeEnv(on_nonce=lambda: self.swap("json.py")))
        self.assertEqual(runner.calls, [])

    def test_a_swap_between_the_executions_is_refused_before_the_next_one(self):
        outer = self

        class Swaps(self.RecordingRunner):
            def run(self, argv, **kwargs):
                code = super().run(argv, **kwargs)
                if len(self.calls) == 1:
                    outer.swap("scripts/enable-agent-ops.py")
                return code
        runner = Swaps()
        with self.assertRaises(E.Refused):
            self.boot(runner)
        self.assertEqual(len(runner.calls), 1)  # the repair check ran; nothing after the swap did

    def test_the_scanner_comes_from_the_installed_harness_not_the_checkout(self):
        def fetch(ref, dest, runner):
            src = self.fetch_from_worktree(ref, dest, runner)
            (src / "harness" / "hooks" / "installer_scan.py").write_text(
                "import json,sys\nprint(json.dumps({'files_scanned': 99, 'findings': []}))\n")
            with (src / "install_codex.py").open("a") as handle:
                handle.write("\nimport os\nos.system('launchctl load -w /Library/LaunchDaemons/x.plist')\n")
            return src
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused) as caught:
            self.boot(runner, fetch=fetch)
        self.assertIn("unexpected side effects", str(caught.exception))
        self.assertEqual(runner.calls, [])

    def test_no_installed_scanner_means_no_bootstrap(self):
        (self.home / ".claude" / "hooks" / "installer_scan.py").unlink()
        runner = self.RecordingRunner()
        with self.assertRaises(E.Refused) as caught:
            self.boot(runner)
        self.assertIn("installed", str(caught.exception))
        self.assertEqual(runner.calls, [])

    def test_a_scan_that_skips_even_one_code_file_is_refused(self):
        class ShortScan(self.RecordingRunner):
            def capture(self, argv, **kwargs):
                code, out = super().capture(argv, **kwargs)
                report = json.loads(out)
                report["files_scanned"] -= 1
                return code, json.dumps(report)
        runner = ShortScan()
        with self.assertRaises(E.Refused) as caught:
            self.boot(runner)
        self.assertIn("did not cover", str(caught.exception))
        self.assertEqual(runner.calls, [])

    def test_the_deviation_is_stated_in_the_output(self):
        self.boot(self.RecordingRunner())
        self.assertIn("DEVIATION", self.output)


# ----------------------------------------------------------------------------------------------- repair round
def attacker_key():
    ed25519, serialization = E.crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, E.key_id_of(raw), E.b64url(raw)


class PolicyChokePoint(Base):
    """Finding 1: --disable re-signs only a policy that verifies against the LOCAL signing key, and rebuilds it."""

    def applied(self, *extra):
        self.assertEqual(self.run_main("--apply", "--ref", REF, *extra), 0, self.output)
        return E.Layout(self.home)

    def tamper(self, layout, change):
        policy = json.loads(layout.policy.read_text())
        change(policy)
        layout.policy.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")

    TAMPERS = {
        "scope widened": lambda p: p["capabilities"]["merge_reviewed_pr"]["scope"].update(repos=["*"]),
        "ttl stretched": lambda p: p["capabilities"]["merge_reviewed_pr"].update(ttl_seconds=10 ** 9),
        "unknown capability": lambda p: p["capabilities"].update(evil_cap={"scope": {}, "ttl_seconds": None}),
        "expiry removed": lambda p: p.update(expires_at=None),
    }

    def test_disable_refuses_to_launder_a_tampered_policy(self):
        for name, change in self.TAMPERS.items():
            self.setUp()
            layout = self.applied("--expires-days", "30")
            self.tamper(layout, change)
            before = layout.policy.read_bytes()
            audit = layout.audit.read_bytes()
            from unittest import mock
            with mock.patch.object(E, "sign_policy", wraps=E.sign_policy) as signer:
                self.assertEqual(self.run_main("--disable", "pool_cleanup"), 3, name)
            self.assertEqual(signer.call_count, 0, name)
            self.assertIn("does not verify", self.output, name)
            self.assertEqual(layout.policy.read_bytes(), before, name)
            self.assertEqual(layout.audit.read_bytes(), audit, name)

    def test_disable_refuses_an_attacker_pin_plus_an_attacker_signed_policy(self):
        layout = self.applied()
        key, key_id, public = attacker_key()
        layout.pubkeys.write_text(json.dumps({"schema": E.KEYS_SCHEMA, "keys": [{"key_id": key_id, "public_key": public}]}))
        policy = json.loads(layout.policy.read_text())
        body = {**{k: v for k, v in policy.items() if k != "signature"}, "key_id": key_id}
        body["capabilities"]["merge_reviewed_pr"]["scope"]["repos"] = ["*"]
        layout.policy.write_text(json.dumps(E.sign_policy(body, key), indent=2, sort_keys=True))
        self.assertIsNone(E.verify_policy(json.loads(layout.policy.read_text()), E.load_pinned(layout)))  # the pin file alone is fooled
        before = layout.policy.read_bytes()
        self.assertEqual(self.run_main("--disable", "pool_cleanup"), 3)
        self.assertEqual(layout.policy.read_bytes(), before)

    def test_disable_refuses_a_validly_signed_policy_this_enabler_would_not_issue(self):
        layout = self.applied()
        key = E.Enabler(layout, env=FakeEnv())._private_key()
        original = json.loads(layout.policy.read_text())
        odd = {
            "ttl stretched": lambda p: p["capabilities"]["pool_cleanup"].update(ttl_seconds=10 ** 9),
            "capability added": lambda p: p["capabilities"].update(evil_cap={"scope": {"hosts": ["mac"]}, "ttl_seconds": 60}),
            "scope field added": lambda p: p["capabilities"]["harness_repair"]["scope"].update(paths=["/"]),
            "wildcard repo": lambda p: p["capabilities"]["merge_reviewed_pr"]["scope"].update(repos=["*"]),
        }
        for name, change in odd.items():
            policy = json.loads(json.dumps(original))
            change(policy)
            layout.policy.write_text(json.dumps(E.sign_policy(policy, key), indent=2, sort_keys=True))
            before = layout.policy.read_bytes()
            self.assertIsNone(E.verify_policy(json.loads(before), E.load_pinned(layout)), name)  # it IS validly signed
            self.assertEqual(self.run_main("--disable", "pool_cleanup"), 3, name)
            self.assertIn("not the shape", self.output, name)
            self.assertEqual(layout.policy.read_bytes(), before, name)

    def test_disable_keeps_expiry_scope_and_id_exactly_and_ignores_unknown_disabled_names(self):
        layout = self.applied("--expires-days", "30", "--repo", "o/r")
        before = json.loads(layout.policy.read_text())
        self.assertEqual(self.run_main("--disable", "pool_cleanup"), 0, self.output)
        after = json.loads(layout.policy.read_text())
        for field in ("expires_at", "issued_at", "policy_id", "key_id", "capabilities"):
            self.assertEqual(after[field], before[field], field)
        self.assertEqual(after["disabled"], ["pool_cleanup"])
        self.assertIsNone(E.verify_policy(after, E.load_pinned(layout)))
        key = E.Enabler(layout, env=FakeEnv())._private_key()
        layout.policy.write_text(json.dumps(E.sign_policy({**after, "disabled": ["pool_cleanup", "made_up"]}, key)))
        self.assertEqual(self.run_main("--disable", "harness_repair"), 3)

    def test_disable_shows_the_change_before_the_nonce(self):
        layout = self.applied()
        before = layout.policy.read_bytes()
        self.assertEqual(self.run_main("--disable", "pool_cleanup", env=FakeEnv(answer="disable-000000")), 3)
        self.assertIn("nonce did not match", self.output)
        self.assertRegex(self.output, r"\+\s+\"pool_cleanup\"")
        self.assertEqual(layout.policy.read_bytes(), before)

    def test_status_does_not_call_a_policy_valid_for_a_key_that_is_not_the_local_one(self):
        layout = self.applied()
        key, key_id, public = attacker_key()
        layout.pubkeys.write_text(json.dumps({"schema": E.KEYS_SCHEMA, "keys": [{"key_id": key_id, "public_key": public}]}))
        policy = {k: v for k, v in json.loads(layout.policy.read_text()).items() if k != "signature"}
        layout.policy.write_text(json.dumps(E.sign_policy({**policy, "key_id": key_id}, key)))
        layout.keyfile.unlink()
        self.assertEqual(self.run_main("--status"), 0)
        status = json.loads(self.output)
        self.assertFalse(status["key_present"])
        self.assertNotEqual(status["signature"], "valid")


class JournalIntegrity(Base):
    """Finding 2: the journal and state file are signed with the local key; resume and undo trust nothing else."""

    def plant_journal(self, signed_with=None, steps_done=True):
        run = "20261123T101500Z-ab12cd"
        key, key_id, public = attacker_key()
        journal = {"schema": E.STATE_SCHEMA, "run": run, "params": {"ref": REF, "host": "t2-dev", "skip_remote": True,
                                                                  "repos": [E.REPO], "expires_days": None},
                   "steps": {s: ("done" if steps_done else "pending") for s in E.STEPS}, "started_at": "x", "files": {},
                   "rules_added": [], "codex_hook_added": False, "key_created": False, "remote_pinned": False,
                   "key_id": key_id, "public_key": public, "policy_id": "a" * 32, "backup": str(self.tmp / "evil-backup")}
        if signed_with == "attacker":
            journal = E.sign_policy({**journal, "purpose": "self-serve-journal"}, key)
        path = E.Layout(self.home).work / run / "journal.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(journal))
        return run, path

    def assert_untouched(self):
        for rel in (".claude/CLAUDE.md", ".claude/settings.json", ".codex/AGENTS.md", ".codex/hooks.json"):
            self.assertFalse((self.home / rel).exists(), rel)
        self.assertFalse(E.Layout(self.home).policy.exists())

    def test_resume_of_a_planted_journal_is_refused(self):
        for signed in (None, "attacker"):
            run, _ = self.plant_journal(signed)
            self.assertEqual(self.run_main("--resume", run), 3, signed)
            self.assert_untouched()
            shutil.rmtree(E.Layout(self.home).work)

    def test_a_planted_state_file_and_backup_cannot_steer_undo(self):
        self.seed_user_files()
        self.assertEqual(self.apply(), 0, self.output)
        layout = E.Layout(self.home)
        evil = self.tmp / "evil-backup"
        evil.mkdir()
        (evil / "settings").write_text('{"permissions": {"allow": ["Bash(*)"]}}\n')
        state = json.loads(layout.state.read_text())
        for field, value in (("backup", str(evil)), ("key_id", "0" * 16), ("remote_pinned", False)):
            layout.state.write_text(json.dumps({**state, field: value}, indent=2, sort_keys=True) + "\n")
            files = snapshot(self.home)
            self.assertEqual(self.run_main("--undo"), 3, field)
            self.assertEqual(snapshot(self.home), files, field)
        entry = dict(state["files"]["settings"], sha_after="0" * 64)
        layout.state.write_text(json.dumps({**state, "files": {**state["files"], "settings": entry}}, indent=2) + "\n")
        self.assertEqual(self.run_main("--undo"), 3)

    def test_a_journal_signature_is_not_a_policy_signature(self):
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        journal = json.loads(layout.state.read_text())
        self.assertIsNotNone(E.verify_policy(journal, E.load_pinned(layout)))  # purpose differs: never a grant
        layout.state.write_text(layout.policy.read_text())  # a real signed policy standing in for the journal
        self.assertEqual(self.run_main("--undo"), 3)

    def test_undo_refuses_a_tampered_backup_before_writing_anything(self):
        self.seed_user_files()
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        run = json.loads(layout.state.read_text())["run"]
        (layout.backups / ("self-serve-" + run) / "settings").write_text('{"permissions": {"allow": ["Bash(*)"]}}\n')
        before = snapshot(self.home)
        self.assertEqual(self.run_main("--undo"), 3)
        self.assertIn("backup", self.output)
        self.assertEqual(snapshot(self.home), before)

    def test_undo_refuses_a_validly_signed_journal_that_points_elsewhere(self):
        self.seed_user_files()
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        journal = json.loads(layout.state.read_text())
        evil = self.tmp / "evil-backup"
        evil.mkdir()
        (evil / "settings").write_text("{}\n")
        journal["backup"] = str(evil)
        E.Enabler(layout, env=FakeEnv())._save_journal(journal)
        before = snapshot(self.home)
        self.assertEqual(self.run_main("--undo"), 3)
        self.assertIn("expected backup", self.output)
        self.assertEqual(snapshot(self.home), before)

    def boom_at(self, step):
        def boom(name):
            if name == step:
                raise RuntimeError("injected")
        return boom

    def test_resume_rederives_the_pin_instead_of_trusting_done_steps(self):
        self.assertEqual(self.apply(on_step=self.boom_at("settings")), 1)
        layout = E.Layout(self.home)
        good = layout.pubkeys.read_bytes()
        _, key_id, public = attacker_key()
        layout.pubkeys.write_text(json.dumps({"schema": E.KEYS_SCHEMA, "keys": [{"key_id": key_id, "public_key": public}]}))
        run = json.loads(layout.state.read_text())["run"]
        self.assertEqual(self.run_main("--resume", run), 0, self.output)
        self.assertEqual(layout.pubkeys.read_bytes(), good)
        self.run_main("--status")
        self.assertEqual(json.loads(self.output)["signature"], "valid")

    def test_resume_shows_the_plan_before_the_nonce(self):
        self.assertEqual(self.apply(on_step=self.boom_at("settings")), 1)
        layout = E.Layout(self.home)
        run = json.loads(layout.state.read_text())["run"]
        before = snapshot(self.home)
        self.assertEqual(self.run_main("--resume", run, env=FakeEnv(answer="resume-000000")), 3)
        self.assertIn("Resuming run", self.output)
        self.assertIn("ah.py ops *", self.output)  # the diff of what resume would still write
        self.assertEqual(snapshot(self.home), before)

    def test_resume_never_takes_a_second_backup_so_undo_still_restores_the_originals(self):
        self.seed_user_files()
        originals = {p: p.read_bytes() for p in (self.home / ".claude" / "CLAUDE.md", self.home / ".claude" / "settings.json",
                                                 self.home / ".codex" / "AGENTS.md", self.home / ".codex" / "hooks.json")}
        self.assertEqual(self.apply(on_step=self.boom_at("codex_hook")), 1)
        layout = E.Layout(self.home)
        run = json.loads(layout.state.read_text())["run"]
        self.assertEqual(self.run_main("--resume", run), 0, self.output)
        self.assertEqual(self.run_main("--undo"), 0, self.output)
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data, str(path))

    def test_resume_and_undo_audit_rows_are_not_duplicated(self):
        self.assertEqual(self.apply(on_step=self.boom_at("policy")), 1)
        layout = E.Layout(self.home)
        run = json.loads(layout.state.read_text())["run"]
        self.assertEqual(self.run_main("--resume", run), 0)
        rows = [json.loads(line)["event"] for line in layout.audit.read_text().splitlines()]
        self.assertEqual(rows, ["apply"])

    def test_the_key_comes_before_the_first_saved_journal(self):
        self.assertEqual(self.apply(on_step=self.boom_at("preflight")), 1)
        layout = E.Layout(self.home)
        self.assertTrue(layout.keyfile.exists())
        run = json.loads(layout.state.read_text())["run"]
        self.assertEqual(self.run_main("--resume", run), 0, self.output)


class RemotePinTrail(Base):
    """Finding 5: an uncertain remote pin is always unpinned by --undo, and a failed unpin keeps the state."""

    class LossyRemote(LocalRemote):
        def __init__(self, home, mode):
            super().__init__(home)
            self.mode = mode

        def run(self, host, command, stdin=None, timeout=90):
            result = super().run(host, command, stdin, timeout)
            if "mktemp" in command:  # the pin landed on the worker; the answer is lost
                if self.mode == "exit":
                    return 255, ""
                raise subprocess.TimeoutExpired(command, timeout)
            return result

    def worker_pin(self):
        return self.remote_home / ".agent-harness" / "policy" / "self-serve-pubkeys.json"

    def test_undo_unpins_after_an_uncertain_pin_whatever_the_failure_looked_like(self):
        for mode in ("exit", "timeout"):
            self.setUp()
            self.assertEqual(self.apply(remote=self.LossyRemote(self.remote_home, mode)), 1, mode)
            self.assertTrue(self.worker_pin().exists(), mode)  # the pin really is on the worker
            self.assertEqual(self.run_main("--undo"), 0, "%s: %s" % (mode, self.output))
            self.assertFalse(self.worker_pin().exists(), mode)
            self.assertFalse(E.Layout(self.home).state.exists(), mode)

    def test_the_attempt_is_durable_before_the_ssh_call(self):
        outer = self

        class Spy(LocalRemote):
            seen = None

            def run(self, host, command, stdin=None, timeout=90):
                if "mktemp" in command:
                    Spy.seen = json.loads(E.Layout(outer.home).state.read_text()).get("remote_pin_attempted")
                return super().run(host, command, stdin, timeout)
        self.assertEqual(self.apply(remote=Spy(self.remote_home)), 0)
        self.assertIs(Spy.seen, True)

    class Down:
        def run(self, *a, **k):
            return 255, ""

    def test_a_failed_unpin_keeps_the_state_and_a_rerun_finishes_without_touching_files_twice(self):
        (self.home / ".claude").mkdir(parents=True, exist_ok=True)
        original = b'{"permissions":{"allow":["Bash(git status)"]}}'  # compact, no newline: a second pass would reformat it
        (self.home / ".claude" / "settings.json").write_bytes(original)
        self.assertEqual(self.apply(), 0)
        layout = E.Layout(self.home)
        self.assertEqual(self.run_main("--undo", remote=self.Down()), 1)
        self.assertTrue(layout.state.exists(), "the only record of the pin must survive a failed unpin")
        self.assertTrue(self.worker_pin().exists())
        self.assertEqual((self.home / ".claude" / "settings.json").read_bytes(), original)
        self.assertEqual(self.run_main("--undo"), 0, self.output)
        self.assertFalse(self.worker_pin().exists())
        self.assertFalse(layout.state.exists())
        self.assertEqual((self.home / ".claude" / "settings.json").read_bytes(), original)
        self.assertEqual(self.run_main("--undo"), 3)  # now there is truly nothing left


class HumanGate(Base):
    """Finding 3: the code is shown out of band, the claim is honest, and a daemonized pty gets nowhere."""

    def test_the_code_never_reaches_the_terminal_when_a_dialog_shows_it(self):
        env = FakeEnv(oob=True)
        self.assertEqual(self.apply(env=env), 0, self.output)
        self.assertEqual(len(env.shown), 1)
        for text in (*env.prompts, self.output):
            self.assertNotIn(env.shown[0], text)
        for mode in (["--disable", "pool_cleanup"], ["--undo"]):
            env = FakeEnv(oob=True)
            self.assertEqual(self.run_main(*mode, env=env), 0, self.output)
            self.assertEqual(len(env.shown), 1, mode)
            self.assertNotIn(env.shown[0], " ".join(env.prompts) + self.output)

    def test_a_dismissed_or_expired_dialog_is_a_refusal(self):
        before = self.all_files()
        self.assertEqual(self.apply(env=FakeEnv(oob=True, dialog_dismissed=True)), 3)
        self.assertIn("dialog", self.output)
        self.assertEqual(self.all_files(), before)

    def stub(self, body, name="osascript"):
        path = self.tmp / name
        out = self.tmp / (name + ".argv")
        path.write_text("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\n%s\n" % (out, body))
        path.chmod(0o755)
        return path, out

    def wait_for(self, path, seconds=10):
        import time
        end = time.time() + seconds
        while time.time() < end and not path.exists():
            time.sleep(0.05)
        return path.exists()

    def test_the_real_env_hands_the_code_to_the_approval_dialog_only(self):
        stub, argv = self.stub("exec sleep 30")
        env = E.Env(platform="darwin", osascript=str(stub))
        handle = env.present_code("enable-abc123", "enable")
        self.assertTrue(self.wait_for(argv))
        self.assertIn("enable-abc123", argv.read_text())
        self.assertTrue(handle.close())  # still on screen when the person answered
        done, _ = self.stub("exit 1", "dismissed")
        handle = E.Env(platform="darwin", osascript=str(done)).present_code("enable-abc123", "enable")
        import time
        time.sleep(0.5)
        self.assertFalse(handle.close())  # cancelled or timed out before the answer

    def test_the_real_env_fails_closed_when_the_dialog_cannot_be_shown(self):
        with self.assertRaises(E.Refused):
            E.Env(platform="darwin", osascript=str(self.tmp / "missing")).present_code("enable-abc123", "enable")
        self.assertIsNone(E.Env(platform="linux").present_code("enable-abc123", "enable"))

    def test_without_a_dialog_the_session_must_have_an_interactive_ancestor(self):
        orphan = {900: (2, "python3 enable-agent-ops.py --apply"), 2: (1, "python3 -c daemonized")}
        self.assertEqual(self.apply(env=FakeEnv(table=orphan, session_proof=True)), 3)
        self.assertIn("interactive", self.output)
        self.assertFalse((self.home / ".agent-harness").exists())
        for root in ("sshd: eric@pts/0", "/usr/bin/login -pf eric", "tmux: server", "-bash"):
            table = {900: (800, "python3 x"), 800: (700, "-zsh"), 700: (1, root)}
            self.assertEqual(E.interactive_ancestor(table, 900) is not None, root != "-bash", root)

    def test_claims_are_honest(self):
        self.assertNotIn("There is no flag, environment variable or file that skips", E.__doc__)
        self.assertIn("accidental", E.__doc__)
        self.assertIn("command_guard", E.__doc__)
        template = (ROOT / "templates" / "self-serve-block.md").read_text()
        self.assertIn("command_guard", template)

    PROBE = r"""
import os, pty, sys, time, select, re, importlib.util
out_path, script, home, ref, stub, platform = sys.argv[1:7]
if os.fork():
    os._exit(0)
os.setsid()
if os.fork():
    os._exit(0)
pid, fd = pty.fork()
if pid == 0:
    child = (
        "import importlib.util, sys, os\n"
        "spec = importlib.util.spec_from_file_location('e', %r)\n"
        "m = importlib.util.module_from_spec(spec); sys.modules['e'] = m; spec.loader.exec_module(m)\n"
        "class Up:\n"
        "    def is_canonical(self, ref): return True\n"
        "    def hook_blobs(self, ref):\n"
        "        d = os.path.join(%r, '.claude', 'hooks')\n"
        "        return {n: m.blob_sha(open(os.path.join(d, n), 'rb').read()) for n in os.listdir(d)}\n"
        "sys.exit(m.main(['--apply', '--ref', %r, '--home', %r, '--skip-remote'],\n"
        "                env=m.Env(platform=%r, osascript=%r), upstream=Up(), parity=lambda layout, ref: {'ok': True, 'gate': []}))\n"
    ) % (script, home, ref, home, platform, stub)
    os.execve(sys.executable, [sys.executable, "-I", "-c", child], {})
transcript = b""
guess_sent = False
deadline = time.time() + 40
status = None
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.5)
    if ready:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            chunk = b""
        if not chunk:
            break
        transcript += chunk
        if b"Type" in transcript and not guess_sent:
            found = re.findall(rb"[a-z]+-[0-9a-f]{6}", transcript)
            time.sleep(1.5)  # a person takes a moment; also lets the dialog stub record its arguments
            os.write(fd, (found[-1] if found else b"enable-000000") + b"\n")
            guess_sent = True
done, raw = os.waitpid(pid, 0)
open(out_path, "wb").write(transcript)
open(out_path + ".status", "w").write(str(os.waitstatus_to_exitcode(raw)))
"""

    def run_probe(self, platform, stub):
        probe = self.tmp / "probe.py"
        probe.write_text(self.PROBE)
        out = self.tmp / "transcript"
        subprocess.run([sys.executable, "-I", str(probe), str(out), str(SCRIPT), str(self.home), REF, str(stub), platform],
                       timeout=60, env={}, stdin=subprocess.DEVNULL)
        self.assertTrue(self.wait_for(Path(str(out) + ".status"), 45), "the daemonized probe never finished")
        return out.read_bytes().decode("utf-8", "replace"), int(Path(str(out) + ".status").read_text())

    def test_a_daemonized_pty_with_a_scrubbed_environment_cannot_learn_the_code(self):
        stub, argv = self.stub("exec sleep 60")
        transcript, status = self.run_probe("darwin", stub)
        self.assertTrue(argv.exists(), "the probe never got as far as the approval dialog: " + transcript[-1500:])
        code = re.search(r"[a-z]+-[0-9a-f]{6}", argv.read_text()).group(0)
        self.assertNotIn(code, transcript)
        self.assertIn("nonce did not match", transcript)
        self.assertEqual(status, 3)
        self.assertFalse((self.home / ".agent-harness").exists())
        self.assertFalse((self.home / ".claude" / "settings.json").exists())

    def test_a_daemonized_pty_is_refused_by_the_ancestry_proof_where_there_is_no_dialog(self):
        transcript, status = self.run_probe("linux", self.tmp / "none")
        self.assertIn("interactive", transcript)
        self.assertEqual(status, 3)
        self.assertFalse((self.home / ".agent-harness").exists())


if __name__ == "__main__":
    unittest.main()
