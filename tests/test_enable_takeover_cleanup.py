"""scripts/enable_takeover_cleanup.py (run through enable-takeover-cleanup.sh): temp homes for "this Mac" and "t2-dev", a temp
repository for the ref, a fake repair-harness. Nothing here touches the real home, the real hooks or ssh."""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import enable_takeover_cleanup as et  # noqa: E402

GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.invalid")
NOW = 1_800_000_000.0
MANAGED_CLAUDE = "<!-- agent-harness:start -->\nmanaged text\n<!-- agent-harness:end -->\n\n## my own section\nkeep me\n"
MANAGED_CODEX = "<!-- agent-harness-codex:start -->\ncodex managed\n<!-- agent-harness-codex:end -->\n"


def git(cwd, *args):
    done = subprocess.run(["git", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError(done.stderr)
    return done.stdout.strip()


def tree(home):
    out = {}
    for path in sorted(Path(home).rglob("*")):
        if path.is_file():
            out[str(path.relative_to(home))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(os.path.realpath(self.tmp.name))
        self.repo, self.kit = base / "repo", base / "kit"
        self.mac, self.t2 = base / "mac", base / "t2"
        for path in (self.repo, self.mac, self.t2):
            path.mkdir()
        self.make_repo()
        self.ref = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.ref)
        for home in (self.mac, self.t2):
            self.make_home(home)
        self.repairs, self.repair_code, self.nonce = [], {"check": 0, "apply": 0}, "ignored"
        self.out = io.StringIO()
        self.kit_dir = ROOT

    def make_repo(self):
        files = list(et.KIT) + ["harness/hooks/" + n for n in et.HOOKS_COMMON] + [
            "harness/hooks/wal.py", "codex/hooks/wal.py", "harness/hooks/ahc_release.json", "harness/hooks/model_tiers.json",
            "harness/hooks/resource_limits.json"]
        for rel in files:
            target = self.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            source = ROOT / rel
            target.write_bytes(source.read_bytes())
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "kit")

    def make_home(self, home):
        (home / ".claude" / "hooks").mkdir(parents=True)
        (home / ".codex" / "agent-harness").mkdir(parents=True)
        (home / ".claude" / "CLAUDE.md").write_text(MANAGED_CLAUDE)
        (home / ".codex" / "AGENTS.md").write_text(MANAGED_CODEX)
        for flavor, directory in et.DIRS.items():
            for name in ("model_tiers.json", "resource_limits.json"):
                (home / directory / name).write_text('{"tuned": "%s-%s"}' % (flavor, name))
            for name in et.HOOKS_COMMON:
                (home / directory / name).write_text("old %s\n" % name)
            (home / directory / "wal.py").write_text("old wal\n")
        (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"command": "/h/.codex/agent-harness/command_guard_hook.py"}]}}).replace(
            "command_guard_hook", "command_guard"))
        wal = home / ".agent-harness" / "codex-wals" / "s1"
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"event": "PreToolUse"}) + "\n")
        os.utime(wal / "main.jsonl", (NOW - 3600, NOW - 3600))

    def fake_repair(self, phase):
        self.repairs.append(phase)
        if phase == "apply" and not self.repair_code["apply"]:
            for home in (self.mac, self.t2):
                for flavor, directory in et.DIRS.items():
                    for name in et.HOOKS_COMMON:
                        (home / directory / name).write_bytes(self.repo_blob("harness/hooks/" + name))
                    (home / directory / "model_tiers.json").write_bytes(self.repo_blob("harness/hooks/model_tiers.json"))
                    (home / directory / "resource_limits.json").write_bytes(self.repo_blob("harness/hooks/resource_limits.json"))
                (home / ".claude/hooks/wal.py").write_bytes(self.repo_blob("harness/hooks/wal.py"))
                (home / ".codex/agent-harness/wal.py").write_bytes(self.repo_blob("codex/hooks/wal.py"))
        return self.repair_code[phase]

    def repo_blob(self, rel):
        return (self.repo / rel).read_bytes()

    def run_script(self, *argv, tty=True, environ=None, remote=None, deps=None):
        base = {"home": self.mac, "remote": remote or et.LocalHost(self.t2, "t2-dev"), "repair": self.fake_repair,
                "environ": environ or {"PATH": "/usr/bin"}, "stdin_tty": tty, "stdout_tty": tty,
                "nonce_in": lambda: self.nonce_value(), "out": self.out, "now": lambda: NOW, "kit_dir": self.kit_dir}
        base.update(deps or {})
        self.out.seek(0)
        self.out.truncate()
        code = et.main(["--ref", self.ref, "--repo", str(self.repo), *argv], base)
        return code, self.out.getvalue()

    def nonce_value(self):
        text = self.out.getvalue()
        return text.split("Type this code to confirm: ")[1].split()[0] if "Type this code" in text else ""


class DryRun(Fixture):
    def test_the_default_run_reports_and_writes_nothing(self):
        before = (tree(self.mac), tree(self.t2))
        code, text = self.run_script()
        self.assertEqual(code, 0, text)
        self.assertIn("WOULD WRITE .claude/CLAUDE.md on local", text)
        self.assertIn("Dry run: nothing was written.", text)
        self.assertEqual((tree(self.mac), tree(self.t2)), before)
        self.assertEqual(self.repairs, ["check"])


class Apply(Fixture):
    def test_apply_writes_backups_blocks_once_and_keeps_the_tuned_json_and_managed_text(self):
        before_tuned = {h.name: {r: (h / r).read_bytes() for r in et.TUNED} for h in (self.mac, self.t2)}
        code, text = self.run_script("--apply")
        self.assertEqual(code, 0, text)
        for home in (self.mac, self.t2):
            claude = (home / ".claude/CLAUDE.md").read_text()
            self.assertEqual(claude.count(et.BEGIN), 1)
            self.assertTrue(claude.startswith("<!-- agent-harness:start -->\nmanaged text\n<!-- agent-harness:end -->\n\n## my own section\nkeep me\n"))
            codex = (home / ".codex/AGENTS.md").read_text()
            self.assertEqual(codex.count(et.BEGIN), 1)
            self.assertTrue(codex.startswith(MANAGED_CODEX))
            for rel in et.TUNED:
                self.assertEqual((home / rel).read_bytes(), before_tuned[home.name][rel], rel)
            self.assertEqual((home / "ah.py").exists(), False)
            self.assertEqual((home / ".claude/hooks/ah.py").read_bytes(), self.repo_blob("harness/hooks/ah.py"))
        backups = sorted((self.mac / et.BACKUP_REL).iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(oct(backups[0].stat().st_mode & 0o777), "0o700")
        self.assertTrue((self.mac / et.STATE_REL).exists())
        self.assertEqual(self.repairs, ["check", "apply"])

    def test_a_second_apply_changes_no_rule_file(self):
        self.run_script("--apply")
        before = {h.name: [(h / r).read_bytes() for r in et.RULE_FILES] for h in (self.mac, self.t2)}
        code, text = self.run_script("--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("block already present", text)
        self.assertEqual({h.name: [(h / r).read_bytes() for r in et.RULE_FILES] for h in (self.mac, self.t2)}, before)

    def test_the_codex_rule_file_is_skipped_where_guard_hooks_are_not_shown_active(self):
        (self.t2 / ".codex/hooks.json").write_text("{}")
        code, text = self.run_script("--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("TARGET_MISMATCH .codex/AGENTS.md on t2-dev not written", text)
        self.assertEqual((self.t2 / ".codex/AGENTS.md").read_text(), MANAGED_CODEX)
        self.assertEqual((self.mac / ".codex/AGENTS.md").read_text().count(et.BEGIN), 1)
        os.utime(self.mac / ".agent-harness/codex-wals/s1/main.jsonl", (NOW - 30 * 86400, NOW - 30 * 86400))

    def test_a_tuned_file_the_installer_changed_to_anything_but_the_ref_default_is_kept_and_exits_three(self):
        original = self.fake_repair

        def merging(phase):
            code = original(phase)
            if phase == "apply":
                (self.mac / ".claude/hooks/model_tiers.json").write_text('{"merged": true}')
            return code
        self.fake_repair = merging
        code, text = self.run_script("--apply", deps={"repair": merging})
        self.assertEqual(code, et.EXIT_TUNED, text)
        self.assertIn("enable-parallel-build.sh --apply --permanent", text)
        self.assertEqual((self.mac / ".claude/hooks/model_tiers.json").read_text(), '{"merged": true}')

    def test_a_failing_install_restores_what_was_done_and_exits_nonzero(self):
        self.repair_code["apply"] = 1
        before = tree(self.mac)
        code, text = self.run_script("--apply")
        self.assertNotEqual(code, 0)
        rules = {r: (self.mac / r).read_bytes() for r in et.RULE_FILES}
        self.assertEqual(rules[".claude/CLAUDE.md"].decode(), MANAGED_CLAUDE)
        # the backups and the state file (kept so --undo can read it) are the only additions
        keep = lambda files: {k: v for k, v in files.items() if not k.startswith((et.BACKUP_REL, et.STATE_REL))}
        self.assertEqual(keep(tree(self.mac)), keep(before))


class UserOnly(Fixture):
    def test_apply_and_undo_refuse_agent_environments_without_writing(self):
        before = (tree(self.mac), tree(self.t2))
        for name in ("CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CLAUDECODE", "CODEX_SANDBOX"):
            for mode in ("--apply", "--undo"):
                code, text = self.run_script(mode, environ={"PATH": "/usr/bin", name: "1"})
                self.assertEqual(code, et.EXIT_AGENT, (name, mode, text))
        self.assertEqual((tree(self.mac), tree(self.t2)), before)

    def test_no_terminal_is_refused_and_so_is_a_wrong_nonce(self):
        before = tree(self.mac)
        self.assertEqual(self.run_script("--apply", tty=False)[0], et.EXIT_AGENT)
        code, text = self.run_script("--apply", deps={"nonce_in": lambda: "000000"})
        self.assertEqual(code, et.EXIT_AGENT, text)
        self.assertIn("did not match", text)
        self.assertEqual(tree(self.mac), before)

    def test_dry_run_and_verify_are_not_user_only(self):
        for mode in ("--dry-run", "--verify"):
            code, text = self.run_script(mode, tty=False, environ={"PATH": "/usr/bin", "CLAUDE_CODE_SESSION_ID": "x"})
            self.assertNotEqual(code, et.EXIT_AGENT, (mode, text))

    def test_the_shell_front_refuses_before_any_write_too(self):
        script = ROOT / "scripts" / "enable-takeover-cleanup.sh"
        env = {"PATH": "/usr/bin:/bin", "CODEX_THREAD_ID": "x", "HOME": str(self.mac)}
        done = subprocess.run(["bash", str(script), "--apply", "--ref", self.ref, "--repo", str(self.repo)], env=env,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 4, done.stderr)
        done = subprocess.run(["bash", str(script), "--undo", "--ref", self.ref, "--repo", str(self.repo)],
                              env={"PATH": "/usr/bin:/bin", "HOME": str(self.mac)}, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIn("terminal", done.stderr)


class Preflight(Fixture):
    def refuses(self, *argv, deps=None, part=None):
        before = (tree(self.mac), tree(self.t2))
        code, text = self.run_script(*argv, deps=deps)
        self.assertNotEqual(code, 0, text)
        if part:
            self.assertIn(part, text)
        self.assertEqual((tree(self.mac), tree(self.t2)), before, "nothing may change on a refusal")
        self.assertNotIn("apply", self.repairs)

    def test_a_ref_that_is_not_on_main_changes_nothing(self):
        git(self.repo, "update-ref", "refs/remotes/origin/main", git(self.repo, "commit-tree", "-m", "other", self.ref + "^{tree}"))
        self.refuses("--apply", part="ancestor")

    def test_kit_bytes_that_differ_from_the_ref_blobs_change_nothing(self):
        kit = Path(self.tmp.name) / "kit"
        (kit / "scripts").mkdir(parents=True)
        for rel in et.KIT:
            (kit / rel).write_bytes((ROOT / rel).read_bytes())
        (kit / "scripts/enable_takeover_cleanup.py").write_text("# tampered\n")
        self.refuses("--apply", deps={"kit_dir": kit}, part="differs from the blob")

    def test_too_little_room_ssh_down_unfinished_run_malformed_markers_and_a_failing_check(self):
        class Tight(et.LocalHost):
            def free_bytes(self):
                return 1000
        self.refuses("--apply", deps={"remote": Tight(self.t2, "t2-dev")}, part="bytes free")

        class Down(et.LocalHost):
            def alive(self):
                return False
        self.refuses("--apply", deps={"remote": Down(self.t2, "t2-dev")}, part="ssh")
        audit = self.mac / ".agent-harness/install-audit.jsonl"
        audit.write_text(json.dumps({"event": "start", "run": "r1", "host": "t2-dev", "kind": "install"}) + "\n")
        self.refuses("--apply", part="unfinished")
        audit.write_text(audit.read_text() + json.dumps({"event": "result", "run": "r1", "host": "t2-dev", "result": "installed"}) + "\n")
        (self.t2 / ".claude/CLAUDE.md").write_text(MANAGED_CLAUDE + et.BEGIN + "\n")
        self.refuses("--apply", part="malformed")
        (self.t2 / ".claude/CLAUDE.md").write_text(MANAGED_CLAUDE)
        self.repair_code["check"] = 3
        self.refuses("--apply", part="--check failed")

    def test_duplicated_or_nested_blocks_are_refused_and_managed_text_is_never_edited(self):
        block = et.Run.policy_block
        text = MANAGED_CLAUDE + et.BEGIN + "\nx\n" + et.END + "\n" + et.BEGIN + "\ny\n" + et.END + "\n"
        with self.assertRaises(et.ScriptError):
            et.with_block(text, "<!-- takeover-cleanup:begin v1 -->\nnew\n<!-- takeover-cleanup:end -->")
        nested = "<!-- agent-harness:start -->\n" + et.BEGIN + "\nx\n" + et.END + "\n<!-- agent-harness:end -->\n"
        with self.assertRaises(et.ScriptError):
            et.with_block(nested, et.BEGIN + "\nnew\n" + et.END)
        replaced = et.with_block(MANAGED_CLAUDE + "\n" + et.BEGIN + "\nold\n" + et.END + "\n\n## after\nz\n", et.BEGIN + "\nnew\n" + et.END)
        self.assertTrue(replaced.startswith(MANAGED_CLAUDE), "managed text and the user's own sections stay as they were")
        self.assertIn("## after\nz\n", replaced)
        self.assertIn("\nnew\n", replaced)
        self.assertIsNone(et.with_block(replaced, et.BEGIN + "\nnew\n" + et.END))
        self.assertIsNotNone(block)


class Undo(Fixture):
    def test_undo_without_a_recorded_apply_refuses(self):
        code, text = self.run_script("--undo")
        self.assertNotEqual(code, 0)
        self.assertIn("no recorded apply", text)

    def test_undo_restores_rule_files_and_tuned_json_byte_for_byte(self):
        keep = {h.name: {r: (h / r).read_bytes() for r in et.RULE_FILES + et.TUNED} for h in (self.mac, self.t2)}
        self.run_script("--apply")
        code, text = self.run_script("--undo")
        self.assertEqual(code, 0, text)
        for home in (self.mac, self.t2):
            for rel, data in keep[home.name].items():
                self.assertEqual((home / rel).read_bytes(), data, rel)
        self.assertIn("repair-harness.sh --ref <previous ref>", text)
        self.assertEqual((self.mac / ".claude/hooks/ah.py").read_bytes(), self.repo_blob("harness/hooks/ah.py"), "hooks stay without --hooks")

    def test_a_rule_file_changed_after_the_apply_needs_force_file(self):
        self.run_script("--apply")
        edited = (self.mac / ".claude/CLAUDE.md").read_text() + "\nmy later edit\n"
        (self.mac / ".claude/CLAUDE.md").write_text(edited)
        code, text = self.run_script("--undo")
        self.assertNotEqual(code, 0)
        self.assertIn("--force-file", text)
        self.assertEqual((self.mac / ".claude/CLAUDE.md").read_text(), edited)
        code, text = self.run_script("--undo", "--force-file", ".claude/CLAUDE.md")
        self.assertEqual(code, 0, text)
        self.assertEqual((self.mac / ".claude/CLAUDE.md").read_text(), MANAGED_CLAUDE)

    def test_undo_hooks_restores_only_files_still_at_the_post_apply_bytes(self):
        self.run_script("--apply")
        (self.mac / ".claude/hooks/ah.py").write_text("changed after apply\n")
        code, text = self.run_script("--undo", "--hooks")
        self.assertEqual(code, 0, text)
        self.assertIn("SKIP .claude/hooks/ah.py on local: changed since the apply", text)
        self.assertEqual((self.mac / ".claude/hooks/ah.py").read_text(), "changed after apply\n")
        self.assertEqual((self.mac / ".claude/hooks/ah_kill.py").read_text(), "old ah_kill.py\n")
        self.assertEqual((self.t2 / ".claude/hooks/ah.py").read_text(), "old ah.py\n")


class Verify(Fixture):
    def install_all_hooks(self):
        """A healthy install: every hook file in both directories of both homes, so the probes can run for real."""
        for home in (self.mac, self.t2):
            for directory in et.DIRS.values():
                for source in (ROOT / "harness" / "hooks").iterdir():
                    if source.is_file():
                        (home / directory / source.name).write_bytes(source.read_bytes())
            (home / ".codex/agent-harness/wal.py").write_bytes((ROOT / "codex/hooks/wal.py").read_bytes())

    def test_a_healthy_install_verifies_with_exit_zero_and_every_probe_passes(self):
        self.install_all_hooks()
        self.run_script("--apply")
        code, text = self.run_script("--verify", tty=False)
        self.assertEqual(code, 0, text)
        self.assertNotIn("FAIL", text)
        self.assertIn("PASS parity .claude/hooks/ah.py on local", text)
        self.assertIn("PASS parity .codex/agent-harness/takeover.py on t2-dev", text)
        self.assertIn("PASS block in .claude/CLAUDE.md on local: 1", text)
        self.assertIn("PASS guard check on local: own session, forced remove blocks with the ah route", text)
        self.assertIn("PASS guard check on t2-dev: foreign session, lone form blocks with the takeover route", text)
        self.assertIn("PASS guard check on local: an assigned session id blocks", text)
        self.assertIn("PASS takeover evidence (codex) on t2-dev: no session", text)
        self.assertIn("PASS dry-run probe (claude) on local: would-stop, nothing signalled", text)

    def test_a_drifted_hook_fails_parity(self):
        self.install_all_hooks()
        self.run_script("--apply")
        (self.t2 / ".claude/hooks/command_guard.py").write_text("drift\n")
        code, text = self.run_script("--verify", tty=False)
        self.assertEqual(code, 1)
        self.assertIn("FAIL parity .claude/hooks/command_guard.py on t2-dev", text)


class SshHostAndModes(Fixture):
    def shim(self, home):
        def run(argv, input=None, capture_output=True, timeout=60):
            self.assertEqual(argv[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--"])
            return subprocess.run(["bash", "-c", argv[-1]], input=input, capture_output=True, timeout=timeout,
                                  env={"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        return run

    def test_a_full_apply_and_undo_over_the_ssh_host_class(self):
        remote = et.SshHost("t2-dev", self.shim(self.t2))
        keep = {r: (self.t2 / r).read_bytes() for r in et.RULE_FILES + et.TUNED}
        code, text = self.run_script("--apply", remote=remote)
        self.assertEqual(code, 0, text)
        self.assertEqual((self.t2 / ".claude/CLAUDE.md").read_text().count(et.BEGIN), 1)
        self.assertTrue((self.t2 / et.BACKUP_REL).is_dir())
        code, text = self.run_script("--undo", remote=remote)
        self.assertEqual(code, 0, text)
        for rel, data in keep.items():
            self.assertEqual((self.t2 / rel).read_bytes(), data, rel)

    def test_the_ssh_host_refuses_a_path_it_cannot_quote_and_reports_a_missing_file_as_none(self):
        remote = et.SshHost("t2-dev", self.shim(self.t2))
        self.assertIsNone(remote.read(".claude/not-there.md"))
        with self.assertRaises(et.ScriptError):
            remote.read("a b; rm -rf x")
        with self.assertRaises(et.ScriptError):
            remote.write("../escape", b"x")

    def test_file_modes_are_kept_across_apply_and_undo(self):
        for home in (self.mac, self.t2):
            os.chmod(home / ".claude/CLAUDE.md", 0o640)
        self.run_script("--apply")
        for home in (self.mac, self.t2):
            self.assertEqual(oct((home / ".claude/CLAUDE.md").stat().st_mode & 0o777), "0o640")
        self.run_script("--undo")
        for home in (self.mac, self.t2):
            self.assertEqual(oct((home / ".claude/CLAUDE.md").stat().st_mode & 0o777), "0o640")

    def test_an_interrupted_apply_leaves_a_state_file_for_undo(self):
        def interrupted(phase):
            if phase == "apply":
                raise KeyboardInterrupt
            return 0
        with self.assertRaises(KeyboardInterrupt):
            self.run_script("--apply", deps={"repair": interrupted})
        self.assertTrue((self.mac / et.STATE_REL).exists())


if __name__ == "__main__":
    unittest.main()
