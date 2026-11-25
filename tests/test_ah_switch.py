"""The off switch (ah_hook.py, ah_switch.py), launcher wiring in install.py, and the release floor.

Everything runs against a temporary HOME; nothing here touches the real ~/.claude, ~/.codex or ~/.agent-harness, and
no test calls launchctl or systemctl (service tests use a recording runner)."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
os.environ["AH_LOCAL_CONFIG"] = str(ROOT / "tests" / "data" / "local_fixture.json")  # hermetic labels
import ah_switch  # noqa: E402
import install  # noqa: E402

START, END = install.START, install.END
USER_BEFORE = "# My own rules\n\nKeep tabs\there, a trailing space \nand CRLF\r\n"
USER_AFTER = "\n## After the block\nmine too\n"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class TempHome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ah-switch-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(os.path.realpath(self.tmp.name))
        self.claude = self.home / ".claude"
        (self.claude / "hooks").mkdir(parents=True)
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)

    def block(self, body="# Agent Harness engineering workflow\nrules\n"):
        return f"{START}\n{body.rstrip()}\n{END}\n"


class Launcher(TempHome):
    """ah_hook.py: OFF exits 0 without starting the script; ON is the script itself (stdin, args, exit code)."""

    def setUp(self):
        super().setUp()
        shutil.copy(HOOKS / "ah_hook.py", self.claude / "hooks" / "ah_hook.py")
        (self.claude / "hooks" / "probe.py").write_text(
            "import sys, pathlib\n"
            "data = sys.stdin.read()\n"
            "pathlib.Path(sys.argv[0]).with_name('ran.txt').write_text(repr((sys.argv[1:], data)))\n"
            "print('out:' + data.upper())\n"
            "sys.exit(int(sys.argv[1]))\n")

    def launch(self, *args, stdin="payload"):
        return subprocess.run([sys.executable, str(self.claude / "hooks" / "ah_hook.py"), "probe.py", *args],
                              input=stdin, capture_output=True, text=True, timeout=30,
                              env={**os.environ, "HOME": str(self.home)})

    def test_on_passes_stdin_args_stdout_and_exit_code_through(self):
        done = self.launch("2", "--flag", "x y")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "out:PAYLOAD\n")
        self.assertEqual((self.claude / "hooks" / "ran.txt").read_text(), repr((["2", "--flag", "x y"], "payload")))
        self.assertEqual(self.launch("0").returncode, 0)

    def test_off_exits_zero_silently_without_starting_the_script(self):
        ah_switch.switch_off(self.home, "test")
        done = self.launch("2")
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertFalse((self.claude / "hooks" / "ran.txt").exists())
        ah_switch.switch_on(self.home)
        self.assertEqual(self.launch("2").returncode, 2)


class LauncherWiring(TempHome):
    """install.merged_settings: direct (old) and launcher (new) wiring are both recognised and replaced."""

    @staticmethod
    def direct_form(hooks, claude):
        """What an installer that predates the launcher wrote: python3 <hooks>/<script> [args]."""
        launcher = str(claude / "hooks" / install.LAUNCHER)
        out = json.loads(json.dumps(hooks))
        for groups in out.values():
            for group in groups:
                for handler in group["hooks"]:
                    if handler.get("args", [None])[0] == launcher:
                        handler["args"] = [str(claude / "hooks" / handler["args"][1]), *handler["args"][2:]]
        return out

    def user_settings(self):
        foreign = {"type": "command", "command": "python3", "args": ["/opt/mine/hook.py", "x"]}
        mine_in_hooks_dir = {"type": "command", "command": "python3", "args": [str(self.claude / "hooks" / "my_own.py")]}
        return {"env": {"KEEP": "1"}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [foreign, mine_in_hooks_dir]}],
                                                "Notification": [{"hooks": [foreign]}]}}

    def handlers(self, settings):
        return [h for groups in settings["hooks"].values() for g in groups for h in g["hooks"]]

    def test_every_managed_handler_runs_through_the_launcher(self):
        hooks = install.managed_hooks(self.claude)
        launcher = str(self.claude / "hooks" / "ah_hook.py")
        python = [h for groups in hooks.values() for g in groups for h in g["hooks"] if h["command"] == "python3"]
        self.assertGreater(len(python), 40)
        for handler in python:
            self.assertEqual(handler["args"][0], launcher, handler)
            self.assertNotIn("/", handler["args"][1])
            self.assertTrue((HOOKS / handler["args"][1]).is_file(), handler["args"][1])
        self.assertIn("ah_hook.py", install.HOOKS)
        self.assertIn("ah_roles.py", install.HOOKS)

    def test_old_direct_wiring_is_replaced_once_and_user_hooks_survive(self):
        new = install.managed_hooks(self.claude)
        old_settings = self.user_settings()
        for event, groups in self.direct_form(new, self.claude).items():
            old_settings["hooks"].setdefault(event, []).extend(groups)
        merged = install.merged_settings(old_settings, self.claude)
        handlers = self.handlers(merged)
        self.assertFalse([h for h in handlers if h.get("args", [""])[0].startswith(str(self.claude / "hooks"))
                          and os.path.basename(h["args"][0]) in {Path(p).name for p in install.managed_scripts(self.claude)}],
                         "old direct wiring survived")
        for event, groups in new.items():
            for group in groups:
                self.assertEqual(merged["hooks"][event].count(group), 1, (event, group))
        self.assertIn(self.user_settings()["hooks"]["PreToolUse"][0], merged["hooks"]["PreToolUse"])
        self.assertEqual(merged["hooks"]["Notification"], self.user_settings()["hooks"]["Notification"])
        self.assertEqual(merged["env"]["KEEP"], "1")
        again = install.merged_settings(merged, self.claude)
        self.assertEqual(again["hooks"], merged["hooks"])

    def test_an_old_installer_run_on_new_wiring_is_undone_by_the_next_new_install(self):
        fresh = install.merged_settings(self.user_settings(), self.claude)
        # an old installer does not know the launcher form: it keeps it and appends its direct groups
        doubled = json.loads(json.dumps(fresh))
        for event, groups in self.direct_form(install.managed_hooks(self.claude), self.claude).items():
            doubled["hooks"].setdefault(event, []).extend(groups)
        self.assertEqual(install.merged_settings(doubled, self.claude)["hooks"], fresh["hooks"])

    def test_git_backstop_runs_through_the_launcher(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            out = "git version 2.60.0\n" if argv[1] == "--version" else ""
            return subprocess.CompletedProcess(argv, 1 if "--get-all" in argv else 0, out, "")
        with mock.patch("subprocess.run", fake_run):
            install.git_hook_status(self.home, install.GIT_HOOK_KEY, self.claude / "hooks" / "commit_policy.py", apply=True)
        command = next(c[-1] for c in calls if "--replace-all" in c and f"hook.{install.GIT_HOOK_KEY}.command" in c)
        self.assertIn(str(self.claude / "hooks" / "ah_hook.py"), command)
        self.assertIn('"$f" commit_policy.py git-hook', command)


class SwitchRoundTrip(TempHome):
    def write(self, text, name=".claude/CLAUDE.md"):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
        return path

    def test_off_on_round_trip_keeps_user_text_byte_identical(self):
        original = USER_BEFORE + "\n" + self.block() + USER_AFTER
        path = self.write(original)
        codex = self.write("codex user text\n\n<!-- agent-harness-codex:start -->\n# Agent Harness for Codex\n"
                           "<!-- agent-harness-codex:end -->\n", ".codex/AGENTS.md")
        codex_original = codex.read_bytes()
        result = ah_switch.switch_off(self.home, "trying without it")
        self.assertEqual(result["blocks"], {"claude": "stashed", "codex": "stashed"})
        self.assertTrue((self.home / ".agent-harness" / "OFF").exists())
        off_text = path.read_bytes().decode()
        self.assertNotIn(START, off_text)
        self.assertEqual(off_text, USER_BEFORE + USER_AFTER)
        self.assertEqual(codex.read_bytes(), b"codex user text\n")
        flag = json.loads((self.home / ".agent-harness" / "OFF").read_text())
        self.assertEqual(flag["reason"], "trying without it")
        self.assertEqual(ah_switch.switch_off(self.home)["blocks"]["claude"], "stashed earlier")  # idempotent
        self.assertEqual(path.read_bytes().decode(), off_text)
        line = ah_switch.status_line(ah_switch.status(self.home))
        self.assertTrue(line.startswith("harness: OFF since "), line)
        on = ah_switch.switch_on(self.home)
        self.assertFalse(on["off"])
        self.assertEqual(path.read_bytes(), original.encode())
        self.assertEqual(codex.read_bytes(), codex_original)
        self.assertFalse((self.home / ".agent-harness" / "OFF").exists())
        self.assertEqual(ah_switch.switch_on(self.home)["blocks"]["claude"], "nothing stashed")  # idempotent
        self.assertEqual(path.read_bytes(), original.encode())
        log = (self.home / ".agent-harness" / "logs" / "switch.log").read_text().splitlines()
        self.assertEqual(len(log), 4)
        self.assertIn("off by", log[0])

    def test_block_absent_and_file_missing_still_switch(self):
        path = self.write("only mine\n")
        ah_switch.switch_off(self.home)
        self.assertEqual(path.read_text(), "only mine\n")
        self.assertTrue(ah_switch.is_off(self.home))
        ah_switch.switch_on(self.home)
        self.assertEqual(path.read_text(), "only mine\n")
        self.assertFalse(ah_switch.is_off(self.home))

    def test_user_edit_while_off_is_kept_and_block_comes_back_at_the_end(self):
        path = self.write(USER_BEFORE + "\n" + self.block() + USER_AFTER)
        ah_switch.switch_off(self.home)
        path.write_text("rewritten while off\n")
        ah_switch.switch_on(self.home)
        self.assertEqual(path.read_text(), "rewritten while off\n\n" + self.block())

    def test_malformed_markers_are_left_alone_and_the_flag_still_goes_on(self):
        text = USER_BEFORE + START + "\nno end marker\n"
        path = self.write(text)
        result = ah_switch.switch_off(self.home)
        self.assertIn("left in place", result["blocks"]["claude"])
        self.assertEqual(path.read_bytes().decode(), text)
        self.assertTrue(ah_switch.is_off(self.home))

    def test_cli_and_shim(self):
        self.write(self.block())
        shutil.copy(HOOKS / "ah_switch.py", self.claude / "hooks" / "ah_switch.py")
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin"}
        shim = ROOT / "harness" / "bin" / "harness"
        off = subprocess.run(["/bin/sh", str(shim), "off", "--reason", "cli"], capture_output=True, text=True, env=env,
                             timeout=30)
        self.assertEqual(off.returncode, 0, off.stderr)
        self.assertIn("harness: OFF", off.stdout)
        st = subprocess.run([sys.executable, str(HOOKS / "ah.py"), "switch-status", "--json"], capture_output=True,
                            text=True, env={**os.environ, **env}, timeout=30)
        self.assertTrue(json.loads(st.stdout)["off"])
        on = subprocess.run(["/bin/sh", str(shim), "on"], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(on.returncode, 0, on.stderr)
        self.assertTrue(on.stdout.startswith("harness: ON"), on.stdout)


class Services(TempHome):
    def test_off_stops_loaded_agents_and_on_restarts_only_those(self):
        agents = self.home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        for label in ("com.agent-harness.ahd", ah_switch.FLOOR_LABEL, "com.agent-harness.ops-watch"):
            (agents / f"{label}.plist").write_text("<plist/>")
        calls = []

        def run(argv):
            calls.append(argv)
            if argv[1] == "print":
                return 0 if not argv[2].endswith("ops-watch") else 113  # ops-watch present but not loaded
            return 0
        result = ah_switch.switch_off(self.home, services=True, run=run, system="darwin")
        self.assertEqual(sorted(result["services_stopped"]), sorted(["com.agent-harness.ahd", ah_switch.FLOOR_LABEL]))
        self.assertFalse([c for c in calls if c[1] == "bootout" and c[2].endswith("ops-watch")])
        calls.clear()
        on = ah_switch.switch_on(self.home, run=run, system="darwin")
        self.assertEqual(sorted(on["services_started"]), sorted(["com.agent-harness.ahd", ah_switch.FLOOR_LABEL]))
        self.assertEqual(len([c for c in calls if c[1] == "bootstrap"]), 2)
        self.assertFalse((self.home / ".agent-harness" / "off-stash" / "services.json").exists())

    def test_floor_watcher_units(self):
        plist_path, data = ah_switch.floor_watch_units(self.home, "darwin")[0]
        import plistlib
        plist = plistlib.loads(data)
        self.assertEqual(plist["Label"], "com.agent-harness.floor")
        self.assertEqual(plist["ThrottleInterval"], 30)
        self.assertEqual(plist["ProgramArguments"][-3:], ["floor-check", "--repair", "--quiet"])
        self.assertIn(str(self.claude / "settings.json"), plist["WatchPaths"])
        self.assertIn(str(self.home / ".agent-harness" / "install-state.json"), plist["WatchPaths"])
        calls = []
        line = install.floor_watch_status(self.home, True, None, run=lambda a: calls.append(a) or 0, system="darwin")
        self.assertIn("loaded", line)
        self.assertTrue(plist_path.exists())
        self.assertIn(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)], calls)
        line = install.floor_watch_status(self.home, True, False, run=lambda a: 0, system="darwin")
        self.assertIn("removed", line)
        self.assertFalse(plist_path.exists())
        self.assertIs(ah_switch.read_state(self.home)["floor_watch"], False)
        units = dict(ah_switch.floor_watch_units(self.home, "linux"))
        path_unit = units[self.home / ".config/systemd/user/agent-harness-floor.path"].decode()
        self.assertIn(f"PathChanged={self.claude / 'hooks'}", path_unit)


class Downgrade(TempHome):
    def set_floor(self, release, flavor="claude"):
        floor = self.home / ".agent-harness" / "floor.json"
        floor.parent.mkdir(parents=True, exist_ok=True)
        floor.write_text(json.dumps({"flavors": {flavor: {"release": release, "commit": "a" * 40}}}))

    def test_install_refuses_a_lower_release_unless_allowed(self):
        self.set_floor(1000)
        with self.assertRaises(install.DowngradeRefused) as caught:
            install.install(self.home, False, release=999)
        self.assertIn("release 999", str(caught.exception))
        self.assertIn("--allow-downgrade", str(caught.exception))
        self.assertTrue(install.install(self.home, False, release=999, allow_downgrade=True))
        self.assertTrue(install.install(self.home, False, release=1000))

    def test_cli_refuses_in_one_line_before_writing_anything(self):
        self.set_floor(install.switch_module().read_release(ROOT) + 1)
        done = subprocess.run([sys.executable, str(ROOT / "install.py"), "--apply", "--home", str(self.home),
                               "--no-netwatch"], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(len(done.stderr.strip().splitlines()), 1, done.stderr)
        self.assertIn("refusing to install release", done.stderr)
        self.assertFalse((self.claude / "settings.json").exists())
        self.assertFalse(list((self.claude / "hooks").iterdir()))

    def test_codex_refuses_a_lower_release(self):
        try:
            import install_codex
        except (ImportError, SyntaxError, TypeError) as error:
            self.skipTest(f"install_codex needs Python 3.11: {error}")
        if install_codex.tomllib is None:
            self.skipTest("install_codex needs Python 3.11 (tomllib)")
        self.set_floor(1000, "codex")
        with self.assertRaises(install.DowngradeRefused):
            install_codex.install(self.home, False, release=999)
        self.assertTrue(install_codex.install(self.home, False, release=999, allow_downgrade=True))


class Floor(TempHome):
    """A small installed tree recorded as release 1000, then an old installer's footprints."""

    def setUp(self):
        super().setUp()
        self.hooks = self.claude / "hooks"
        for name in ("wal.py", "commit_policy.py", "ah_hook.py"):
            (self.hooks / name).write_text(f"# {name} release 1000\n")
        self.groups = {"SessionStart": [{"hooks": [{"type": "command", "command": "python3",
                                                    "args": [str(self.hooks / "ah_hook.py"), "wal.py", "session"]}]}],
                       "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3",
                                       "args": [str(self.hooks / "ah_hook.py"), "commit_policy.py", "hook"]}]}]}
        self.user_group = {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3", "args": ["/opt/mine.py"]}]}
        hooks = {"PreToolUse": [self.user_group, *self.groups["PreToolUse"]], "SessionStart": self.groups["SessionStart"]}
        (self.claude / "settings.json").write_text(json.dumps({"hooks": hooks, "env": {"A": "1"}}, indent=2))
        (self.claude / "CLAUDE.md").write_text("mine\n\n" + self.block() + "\nmine after\n")
        self.backups = self.claude / "agent-harness-backups"
        (self.backups / "20261124T100000000000Z-aaaa").mkdir(parents=True)
        spec = {"path": ".claude/settings.json", "hooks_dir": str(self.hooks), "names": ["commit_policy.py", "wal.py"],
                "groups": self.groups}
        ah_switch.record_install(self.home, "claude", 1000, "c" * 40, sorted(self.hooks.iterdir()), spec,
                                 {"block": self.block()}, "20261124T100000000000Z-aaaa")
        self.settings_after_install = (self.claude / "settings.json").read_text()

    def old_installer(self, state_overwrite=False, block=True):
        """What an install.py from a stale checkout does: older file bytes, direct wiring appended next to the
        launcher wiring it does not recognise, a backup directory, an older instruction block, maybe a state rewrite."""
        (self.hooks / "wal.py").write_text("# wal.py OLD\n")
        settings = json.loads((self.claude / "settings.json").read_text())
        settings["hooks"]["SessionStart"].append({"hooks": [{"type": "command", "command": "python3",
                                                             "args": [str(self.hooks / "wal.py"), "session"]}]})
        (self.claude / "settings.json").write_text(json.dumps(settings))
        (self.backups / "20261125T100000000000Z-bbbb").mkdir()
        if block:
            text = (self.claude / "CLAUDE.md").read_text()
            if START in text:
                text = text.replace("rules", "OLD rules")
            else:
                text += "\n" + self.block("# Agent Harness engineering workflow\nOLD rules\n")
            (self.claude / "CLAUDE.md").write_text(text)
        if state_overwrite:
            (self.home / ".agent-harness" / "install-state.json").write_text('{"schema": 1, "durable_tmp": true}')

    def test_fresh_install_is_ok(self):
        result = ah_switch.floor_check(self.home)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["flavors"]["claude"]["state"], "ok")

    def check_repair(self, state_overwrite):
        self.old_installer(state_overwrite)
        found = ah_switch.floor_check(self.home)
        self.assertFalse(found["ok"])
        problems = " ".join(found["flavors"]["claude"]["problems"])
        self.assertIn("wired directly", problems)
        self.assertIn("1 managed file(s) differ", problems)
        self.assertEqual((self.hooks / "wal.py").read_text(), "# wal.py OLD\n")  # detection writes nothing
        fixed = ah_switch.floor_check(self.home, repair=True)
        self.assertEqual(fixed["flavors"]["claude"]["state"], "repaired", fixed)
        self.assertEqual((self.hooks / "wal.py").read_text(), "# wal.py release 1000\n")
        self.assertEqual(json.loads((self.claude / "settings.json").read_text()), json.loads(self.settings_after_install))
        self.assertEqual((self.claude / "CLAUDE.md").read_text(), "mine\n\n" + self.block() + "\nmine after\n")
        self.assertTrue(ah_switch.floor_check(self.home)["ok"])  # converged: a second run changes nothing
        self.assertEqual(ah_switch.read_state(self.home)["flavors"]["claude"]["release"], 1000)
        log = (self.home / ".agent-harness" / "logs" / "floor.log").read_text().splitlines()
        self.assertEqual(len(log), 1)
        self.assertIn("repaired claude to release 1000", log[0])

    def test_old_installer_overwrite_is_detected_and_repaired(self):
        self.check_repair(state_overwrite=False)

    def test_old_installer_that_also_rewrote_install_state_is_repaired(self):
        self.check_repair(state_overwrite=True)

    def test_repair_respects_off(self):
        ah_switch.switch_off(self.home, "testing")
        self.old_installer(block=True)  # the old installer puts its block back while OFF
        fixed = ah_switch.floor_check(self.home, repair=True)
        self.assertEqual(fixed["flavors"]["claude"]["state"], "repaired")
        self.assertTrue(ah_switch.is_off(self.home))
        self.assertNotIn(START, (self.claude / "CLAUDE.md").read_text())
        self.assertEqual((self.hooks / "wal.py").read_text(), "# wal.py release 1000\n")
        ah_switch.switch_on(self.home)
        self.assertEqual((self.claude / "CLAUDE.md").read_text(), "mine\n\n" + self.block() + "\nmine after\n")

    def test_a_newer_install_in_progress_or_done_is_left_alone(self):
        ah_switch.mark_pending(self.home, "claude", 1001)
        self.old_installer()
        self.assertEqual(ah_switch.floor_check(self.home, repair=True)["flavors"]["claude"]["state"],
                         "install_in_progress")
        ah_switch.update_state(self.home, lambda s: (s.pop("pending"), s["flavors"]["claude"].__setitem__("release", 1001)))
        self.assertEqual(ah_switch.floor_check(self.home, repair=True)["flavors"]["claude"]["state"], "newer_install")
        self.assertEqual((self.hooks / "wal.py").read_text(), "# wal.py OLD\n")

    def test_hand_edit_without_an_old_installer_sign_is_not_reverted(self):
        (self.hooks / "wal.py").write_text("# my local experiment\n")
        result = ah_switch.floor_check(self.home, repair=True)
        self.assertEqual(result["flavors"]["claude"]["state"], "ok")
        self.assertIn("hand edits", result["flavors"]["claude"]["note"])
        self.assertEqual((self.hooks / "wal.py").read_text(), "# my local experiment\n")

    def test_newest_two_releases_are_kept(self):
        for release in (1001, 1002):
            ah_switch.record_install(self.home, "claude", release, "d" * 40, [self.hooks / "wal.py"])
        self.assertEqual(sorted(os.listdir(self.home / ".agent-harness" / "releases")), ["1001", "1002"])
        self.assertEqual(json.loads((self.home / ".agent-harness" / "floor.json").read_text())["release"], 1002)


class InstallIntegration(TempHome):
    """A real install.py --apply into the temp HOME: release recorded, snapshot written, OFF honoured."""

    def run_install(self, *extra):
        done = subprocess.run([sys.executable, str(ROOT / "install.py"), "--apply", "--home", str(self.home),
                               "--no-netwatch", "--no-mission-control", "--no-log-backup", "--no-durable-tmp", *extra],
                              capture_output=True, text=True, timeout=300,
                              env={**os.environ, "HOME": str(self.home), "CLAUDE_CODE_TMPDIR": ""})
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        return done.stdout

    def test_install_records_release_and_honours_off(self):
        user = "my rules\n"
        (self.claude / "CLAUDE.md").write_text(user)
        out = self.run_install()
        self.assertIn("release 1000", out)
        self.assertIn("switch shim", out)
        state = ah_switch.read_state(self.home)
        self.assertEqual(state["flavors"]["claude"]["release"], 1000)
        self.assertTrue(ah_switch.floor_check(self.home)["ok"])
        self.assertTrue(os.access(self.home / ".agent-harness" / "bin" / "harness", os.X_OK))
        installed = (self.claude / "CLAUDE.md").read_bytes()
        ah_switch.switch_off(self.home)
        self.assertEqual((self.claude / "CLAUDE.md").read_text(), user)
        self.run_install()  # while OFF: files and wiring, no instruction block
        self.assertEqual((self.claude / "CLAUDE.md").read_text(), user)
        self.assertTrue(ah_switch.is_off(self.home))
        self.assertTrue(ah_switch.floor_check(self.home)["ok"])
        ah_switch.switch_on(self.home)
        self.assertEqual((self.claude / "CLAUDE.md").read_bytes(), installed)


if __name__ == "__main__":
    unittest.main()
