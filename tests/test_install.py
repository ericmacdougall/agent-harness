import json
import re
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from install import (END, START, ROOT, durable_tmp_choice, hook_argv, install, merged_instructions,
                     save_durable_tmp_choice, scratch_status)


class InstallerTests(unittest.TestCase):
    def test_task_recovery_survives_reinstall(self):
        for _ in range(2):
            install(self.home, apply=True)
            helper = self.claude / "hooks/task_recovery.py"
            self.assertEqual(helper.read_bytes(), (ROOT / "harness/hooks/task_recovery.py").read_bytes())
            result = subprocess.run([sys.executable, str(helper), "--help"], cwd=self.home,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("enroll", result.stdout)

    def setUp(self):
        # Sessions started after install export CLAUDE_CODE_TMPDIR; tests must not depend on the host.
        isolate = patch.dict(os.environ)
        isolate.start()
        self.addCleanup(isolate.stop)
        os.environ.pop("CLAUDE_CODE_TMPDIR", None)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.claude = self.home / ".claude"
        self.claude.mkdir()

    def test_subagent_hooks_fire_for_every_agent_type(self):
        # goodqa#14613: the matcher covered four agent types, so a general-purpose owner never got a
        # SubagentStart/Stop WAL record and no liveness check could see it stop.
        install(self.home, apply=True)
        hooks = json.loads((self.claude / "settings.json").read_text())["hooks"]
        for event, action in (("SubagentStart", "subagent"), ("SubagentStop", "subagent_stop")):
            groups = [g for g in hooks[event]
                      if any(os.path.basename(str((hook_argv(h) or [""])[0])) == "wal.py" for h in g.get("hooks", []))]
            self.assertEqual(len(groups), 1, event)
            matcher = groups[0].get("matcher")
            self.assertIn(matcher, (None, ".*", "*"), (event, matcher))  # every type, not a list of named types
            matcher = matcher or ".*"
            for agent_type in ("general-purpose", "claude", "Explore", "Plan", "task-owner", "red-team", "fixer",
                               "click-tester", "statusline-setup", "any-new-type-123"):
                self.assertTrue(re.fullmatch(matcher if matcher != "*" else ".*", agent_type), (event, matcher, agent_type))
            hook = [h for h in groups[0]["hooks"] if os.path.basename(str(hook_argv(h)[0])) == "wal.py"][0]
            self.assertEqual(hook_argv(hook)[1], action)
            result = subprocess.run([sys.executable, *[str(a) for a in hook["args"]]],
                                    input=json.dumps({"session_id": "s-gp", "agent_id": "owner-gp", "agent_type": "general-purpose"}),
                                    text=True, capture_output=True, timeout=30, env={**os.environ, "HOME": str(self.home)})
            self.assertEqual(result.returncode, 0, result.stderr)
        wal = self.claude / "wals" / "s-gp" / "main.jsonl"
        self.assertTrue(wal.exists(), list((self.claude / "wals").rglob("*")))
        events = [json.loads(line).get("event") for line in wal.read_text().splitlines() if line.strip()]
        self.assertIn("subagent", events); self.assertIn("subagent_stop", events)

    def test_preview_does_not_write(self):
        paths = install(self.home, apply=False)
        self.assertGreater(len(paths), 10)
        self.assertEqual(list(self.claude.iterdir()), [])

    def test_inline_marker_text_is_preserved(self):
        original = f'Keep this example: {START} user text {END} forever.\n'
        merged = merged_instructions(original, 'Managed instructions.')
        self.assertIn(original.rstrip(), merged)
        self.assertIn('Managed instructions.', merged)

    def test_fenced_marker_example_is_preserved(self):
        example = f'```md\n{START}\n# Agent Harness engineering workflow\nExample.\n{END}\n```\n'
        merged = merged_instructions(example, 'Managed instructions.')
        self.assertIn(example, merged)
        self.assertIn('Managed instructions.', merged)

    def test_replacement_preserves_end_marker_newline_and_suffix(self):
        existing = (f'{START}\n# Agent Harness engineering workflow\nOld.\n{END}\n'
                    'User instructions after block.\n')
        merged = merged_instructions(existing, '# Agent Harness engineering workflow\nNew.')
        self.assertIn(f'{END}\nUser instructions after block.\n', merged)
        self.assertEqual(merged_instructions(merged, '# Agent Harness engineering workflow\nNew.'), merged)

    def test_same_inode_edit_during_backup_is_preserved(self):
        target = self.claude / 'CLAUDE.md'
        target.write_text('original\n')
        from install import atomic_write
        changed = False

        def edit_during_backup(path, data, mode=0o600, **kwargs):
            nonlocal changed
            if not changed and 'agent-harness-backups' in path.parts:
                changed = True
                target.write_text('concurrent user edit\n')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=edit_during_backup):
            with self.assertRaises(OSError):
                install(self.home, apply=True)
        self.assertTrue(changed)
        self.assertEqual(target.read_text(), 'concurrent user edit\n')

    def test_rollback_preserves_same_inode_edit_to_published_file(self):
        from install import atomic_write
        for existed in (False, True):
            with self.subTest(existed=existed), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                agents = home / '.claude' / 'agents'
                agents.mkdir(parents=True)
                owner = agents / 'task-owner.md'
                if existed:
                    owner.write_text('original owner\n')
                changed = False

                def edit_then_fail(path, data, mode=0o600, **kwargs):
                    nonlocal changed
                    if path == agents / 'click-tester.md' and not changed:
                        changed = True
                        owner.write_text('concurrent published edit\n')
                        raise OSError('fixture: stop after edit')
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=edit_then_fail):
                    with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                        install(home, apply=True)
                self.assertTrue(changed)
                self.assertEqual(owner.read_text(), 'concurrent published edit\n')

    def test_preserves_settings_and_is_idempotent(self):
        original = {
            "model": "sonnet",
            "permissions": {"deny": ["Read(**/.env)"]},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}]},
        }
        (self.claude / "settings.json").write_text(json.dumps(original))
        (self.claude / "CLAUDE.md").write_text("My existing instructions.\n")
        install(self.home, apply=True)
        for name in ('git_safety.py', 'integrate_local.py', 'report_file.py', 'peer_review.py', 'rescue.py'):
            self.assertEqual((self.claude / 'hooks' / name).read_bytes(),
                             (ROOT / 'harness/hooks' / name).read_bytes())
        kimi = self.claude / 'hooks' / 'kimi_review.py'  # goodqa#15201 N2: installed, identical, private mode
        self.assertEqual(kimi.read_bytes(), (ROOT / 'harness/hooks/kimi_review.py').read_bytes())
        self.assertEqual(stat.S_IMODE(kimi.stat().st_mode), 0o600)
        first = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(first["model"], "sonnet")
        self.assertEqual(first["permissions"]["deny"], ["Read(**/.env)"])
        self.assertEqual(len(first["hooks"]["PreToolUse"]), 2)  # the user's own + the prod-delete guard (database tools)
        self.assertNotIn("skipDangerousModePermissionPrompt", first)
        self.assertIn("My existing instructions.", (self.claude / "CLAUDE.md").read_text())
        self.assertEqual((self.claude / "CLAUDE.md").read_text().count(START), 1)
        install(self.home, apply=True)
        second = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(first, second)
        self.assertEqual((self.claude / "CLAUDE.md").read_text().count(START), 1)
        self.assertTrue(list((self.claude / "agent-harness-backups").rglob("settings.json")))

    def test_reinstall_keeps_exactly_one_of_each_handler(self):
        for _ in range(3):
            install(self.home, apply=True)
        hooks = json.loads((self.claude / "settings.json").read_text())["hooks"]
        counts = {}
        for event, groups in hooks.items():
            for group in groups:
                for hook in group.get("hooks", []):
                    args = hook_argv(hook)
                    if args and str(args[0]).startswith(str(self.claude / "hooks")):
                        key = (event, group.get("matcher"), os.path.basename(args[0]), tuple(args[1:]))
                        counts[key] = counts.get(key, 0) + 1
        self.assertTrue(counts and all(v == 1 for v in counts.values()), counts)
        self.assertEqual(len(counts), 10)
        names = {k[2] for k in counts}
        self.assertEqual(names, {"session_env.py", "wal.py", "autosave.py", "owner_inbox.py", "dropped_gate.py",
                                 "prod_delete_guard.py"})


    def test_foreign_session_start_hook_survives_and_a_reinstall_changes_nothing(self):
        foreign = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "other-start"}]}]}}
        (self.claude / "settings.json").write_text(json.dumps(foreign))
        install(self.home, apply=True)
        start = json.loads((self.claude / "settings.json").read_text())["hooks"]["SessionStart"]
        self.assertTrue(any(h.get("command") == "other-start" for g in start for h in g["hooks"]))
        before = (self.claude / "settings.json").read_bytes()
        install(self.home, apply=True)
        self.assertEqual((self.claude / "settings.json").read_bytes(), before)

    def test_hand_wired_retired_entries_are_removed(self):
        hooks_dir = self.claude / "hooks"
        manual = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3",
                                                  "args": [str(hooks_dir / "provenance_hooks.py"), "stop-lint"],
                                                  "timeout": 99}]}],
                            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3",
                                                                          "args": [str(hooks_dir / "command_guard_hook.py"), "hook"]}]}]}}
        (self.claude / "settings.json").write_text(json.dumps(manual))
        install(self.home, apply=True)
        hooks = json.loads((self.claude / "settings.json").read_text())["hooks"]
        stop = [os.path.basename(hook_argv(h)[0]) for g in hooks["Stop"] for h in g["hooks"]]
        self.assertEqual(stop, ["autosave.py", "dropped_gate.py"])
        self.assertEqual([os.path.basename(hook_argv(h)[0]) for g in hooks["PreToolUse"] for h in g["hooks"]],
                         ["prod_delete_guard.py"])

    def test_foreign_hook_sharing_a_group_and_users_empty_event_list_survive(self):
        script = str(self.claude / "hooks" / "provenance_hooks.py")
        mixed = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "other-stop"},
                                               {"type": "command", "command": "python3", "args": [script, "stop-lint"]}]}],
                           "Notification": []}}
        (self.claude / "settings.json").write_text(json.dumps(mixed))
        install(self.home, apply=True)
        hooks = json.loads((self.claude / "settings.json").read_text())["hooks"]
        self.assertEqual([h["command"] for g in hooks["Stop"] for h in g["hooks"]], ["other-stop", "python3", "python3"])  # foreign kept; the save and the dropped-owner gate
        self.assertTrue(any("dropped_gate.py" in str(h.get("args")) for g in hooks["Stop"] for h in g["hooks"]))
        self.assertEqual(hooks["Notification"], [])  # untouched, not ours

    def test_an_upgrade_removes_the_retired_registrations(self):
        hooks_dir = self.claude / "hooks"
        old = {"Stop": [{"hooks": [{"type": "command", "command": "python3", "args": [str(hooks_dir / name), *rest]}]}
                        for name, rest in (("status_truth.py", ["stop"]), ("mc_inbox.py", ["hook"]),
                                           ("idle_guard.py", ["stop"]), ("wal_cadence.py", []))],
               "PostToolUseFailure": [{"hooks": [{"type": "command", "command": "python3",
                                                  "args": [str(hooks_dir / "idle_guard.py"), "reject"]}]}],
               "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "python3",
                                                "args": [str(hooks_dir / "ledger_reminder.py")]}]},
                                    {"hooks": [{"type": "command", "command": "other-prompt"}]}]}
        (self.claude / "settings.json").write_text(json.dumps({"hooks": old}))
        install(self.home, apply=True)
        hooks = json.loads((self.claude / "settings.json").read_text())["hooks"]

        def scripts(event):
            return [os.path.basename(hook_argv(h)[0]) for g in hooks.get(event, []) for h in g["hooks"] if hook_argv(h)]
        self.assertEqual(scripts("Stop"), ["autosave.py", "dropped_gate.py"])
        self.assertEqual(scripts("UserPromptSubmit"), ["owner_inbox.py"])
        self.assertNotIn("PostToolUseFailure", hooks)  # an event left empty by the upgrade goes
        self.assertTrue(any(h.get("command") == "other-prompt" for g in hooks["UserPromptSubmit"] for h in g["hooks"]))

    def test_an_upgrade_moves_the_retired_guard_files_into_the_backup(self):
        """The release 1001 red team: an upgrade from 1000 left command_guard.py, merge_gate.py and the rest on disk."""
        hooks_dir = self.claude / "hooks"
        hooks_dir.mkdir(parents=True)
        for name in ("command_guard.py", "merge_gate.py", "kill_guard_policy.json", "commit_policy.json"):
            (hooks_dir / name).write_text("# release 1000\n")
        (hooks_dir / "my_own_hook.py").write_text("# the user's\n")
        os.symlink(hooks_dir / "my_own_hook.py", hooks_dir / "tier_gate.py")   # not a regular file: left alone
        changes = install(self.home, apply=True)
        for name in ("command_guard.py", "merge_gate.py", "kill_guard_policy.json", "commit_policy.json"):
            self.assertFalse((hooks_dir / name).exists(), name)
            kept = list((self.claude / "agent-harness-backups").glob("*/retired/" + name))
            self.assertEqual(len(kept), 1, name)
            self.assertEqual(kept[0].read_text(), "# release 1000\n")
        self.assertTrue((hooks_dir / "my_own_hook.py").exists())
        self.assertTrue((hooks_dir / "tier_gate.py").is_symlink())
        self.assertTrue(any("retired file" in c for c in changes), changes)

    def test_removed_flags_fail_loudly_before_anything_is_written(self):
        for flag in ("--services", "--no-provenance-hooks", "--no-command-guard", "--floor-watch", "--no-floor-watch"):
            with self.subTest(flag=flag):
                done = subprocess.run([sys.executable, str(ROOT / "install.py"), "--apply", "--home", str(self.home),
                                       flag], capture_output=True, text=True, timeout=120,
                                      env={**os.environ, "HOME": str(self.home)})
                self.assertEqual(done.returncode, 2)
                self.assertIn(f"install.py: {flag} was removed in release 1001:", done.stderr)
                self.assertEqual(list(self.claude.iterdir()), [])

    def test_while_off_the_sandbox_files_go_to_the_off_stash(self):
        import install as installer  # noqa: PLC0415
        switch = installer.switch_module()
        (self.home / ".agent-harness").mkdir(exist_ok=True)
        (self.home / ".agent-harness" / "OFF").write_text("{}")
        line = installer.sandbox_status(self.home, apply=True)
        self.assertIn("OFF", line)
        self.assertFalse((self.home / ".agent-harness" / "sandbox" / "reviewer.claude.json").exists())
        self.assertTrue((switch.sandbox_stash_dir(self.home) / "reviewer.claude.json").is_file())

    def test_sandbox_files_are_written_private_and_equal_to_ah_sandbox(self):
        import install as installer  # noqa: PLC0415
        sandbox = installer.sandbox_module()
        self.assertIn("would write", installer.sandbox_status(self.home, apply=False))
        self.assertFalse((self.home / ".agent-harness" / "sandbox").exists())
        line = installer.sandbox_status(self.home, apply=True)
        self.assertIn("wrote", line)
        for role in sandbox.ROLES:
            path = Path(sandbox.installed_path(self.home, role))
            self.assertEqual(path.parent, self.home / ".agent-harness" / "sandbox")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            expected = json.dumps(sandbox.claude_settings(role, home=self.home), indent=2, sort_keys=True) + "\n"
            self.assertEqual(path.read_text(), expected)
            self.assertEqual(json.loads(path.read_text())["env"]["AH_ROLE"], role)
        self.assertEqual(stat.S_IMODE((self.home / ".agent-harness" / "sandbox").stat().st_mode), 0o700)
        settings = self.claude / "settings.json"
        self.assertFalse(settings.exists())  # inert: no role selected, no managed settings, settings.json untouched
        for managed in (Path("/Library/Application Support/ClaudeCode/managed-settings.d/50-agent-harness.json"),
                        self.home / ".claude" / "managed-settings.json"):
            self.assertFalse(managed.exists() and managed.stat().st_mtime > path.stat().st_mtime - 5, managed)

    def test_a_symlinked_sandbox_file_is_refused(self):
        import install as installer  # noqa: PLC0415
        sandbox = installer.sandbox_module()
        target = Path(sandbox.installed_path(self.home, sandbox.ROLES[0]))
        target.parent.mkdir(parents=True)
        outside = self.home / "outside.json"
        outside.write_text("mine\n")
        target.symlink_to(outside)
        self.assertIn("refused", installer.sandbox_status(self.home, apply=True))
        self.assertEqual(outside.read_text(), "mine\n")

    def test_no_launchctl_or_systemctl_for_a_non_default_home(self):
        import install as installer  # noqa: PLC0415
        calls = []
        real = subprocess.run

        def spy(argv, *a, **kw):
            if argv and str(argv[0]) in ("launchctl", "systemctl"):
                calls.append(argv)
            return real(argv, *a, **kw)
        with patch("subprocess.run", spy):
            line = installer.floor_watch_status(self.home, apply=True)
        self.assertIn("skipped (non-default --home)", line)
        self.assertEqual(calls, [])
        self.assertFalse(hasattr(installer, "install_services"))
        self.assertFalse(hasattr(installer, "service_commands"))

    def test_the_shim_moves_a_foreign_harness_aside_and_writes_itself(self):
        import install as installer  # noqa: PLC0415
        bindir = self.home / ".agent-harness" / "bin"
        bindir.mkdir(parents=True)
        other = bindir / "harness"
        other.write_bytes(b"\x7fELF a go binary")
        line = installer.shim_status(self.home, apply=True, now=1764000000)
        retired = bindir / "harness.retired-20251124T160000Z"
        self.assertIn(str(retired), line)
        self.assertEqual(retired.read_bytes(), b"\x7fELF a go binary")  # kept, never deleted
        self.assertIn(installer.SHIM_MARK, other.read_bytes())
        self.assertTrue(os.access(other, os.X_OK))
        self.assertIn("switch shim:", installer.shim_status(self.home, apply=True))  # now ours: rewritten in place
        self.assertEqual(sorted(p.name for p in bindir.iterdir()), ["harness", retired.name])

    def test_tolerates_user_hook_with_empty_args(self):
        (self.claude / "settings.json").write_text(json.dumps(
            {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3", "args": []}]}]}}
        ))
        install(self.home, apply=True)
        settings = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(len(settings["hooks"]["PreToolUse"]), 2)  # the user's own + the prod-delete guard
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["hooks"][0]["args"], [])

    def test_backups_are_private(self):
        (self.claude / "settings.json").write_text(json.dumps({"env": {"EXAMPLE": "value"}}))
        install(self.home, apply=True)
        root = self.claude / "agent-harness-backups"
        for folder in (root, *root.iterdir()):
            self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700, folder)
        self.assertEqual(stat.S_IMODE((next(root.rglob("settings.json"))).stat().st_mode), 0o600)

    def test_harness_state_directories_are_private(self):
        # record_gate_epoch creates ~/.agent-harness before any other component:
        # the parents must not keep the umask-default 0755 that mkdir(parents=True) gives them.
        install(self.home, apply=True)
        for rel in (".agent-harness", ".agent-harness/state"):
            self.assertEqual(stat.S_IMODE((self.home / rel).stat().st_mode), 0o700, rel)
        self.assertEqual(stat.S_IMODE((self.home / ".agent-harness/state/dropped-gate").stat().st_mode), 0o700)

    def test_malformed_hook_and_permission_shapes_raise_valueerror(self):
        # A damaged settings.json must be refused with a clear message, like the
        # existing env shape check, not crash with an AttributeError.
        cases = (
            ({"hooks": []}, "hooks must be an object"),
            ({"hooks": {"PreToolUse": {}}}, "hooks.PreToolUse must be a list"),
            ({"hooks": {"PreToolUse": ["not-a-group"]}}, "invalid hook group"),
            ({"hooks": {"PreToolUse": [42]}}, "invalid hook group"),
            ({"hooks": {"PreToolUse": [{"hooks": {}}]}}, "invalid hook group"),
            ({"hooks": {"PreToolUse": [{"hooks": ["not-a-hook"]}]}}, "invalid hook group"),
            ({"permissions": []}, "permissions must be an object"),
            ({"permissions": {"allow": "Bash(foo)"}}, "permissions.allow must be a list"),
        )
        for settings, message in cases:
            with self.subTest(settings=settings):
                (self.claude / "settings.json").write_text(json.dumps(settings))
                with self.assertRaisesRegex(ValueError, message):
                    install(self.home, apply=True)
                self.assertFalse((self.claude / "hooks").exists())

    def test_refuses_symlinked_destination(self):
        outside = self.home / "outside"
        outside.write_text("preserve")
        (self.claude / "settings.json").symlink_to(outside)
        with self.assertRaises(ValueError):
            install(self.home, apply=True)
        self.assertEqual(outside.read_text(), "preserve")

    def test_preserves_foreign_hook_in_a_managed_group(self):
        foreign = {"type": "command", "command": "keep-my-hook"}
        managed = {"type": "command", "command": "python3",
                   "args": [str(self.claude / "hooks/wal.py"), "pretool"]}
        group = {"matcher": "Write", "hooks": [managed, foreign], "timeout": 42}
        (self.claude / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [group]}}))
        install(self.home, apply=True)
        install(self.home, apply=True)
        groups = json.loads((self.claude / "settings.json").read_text())["hooks"]["PreToolUse"]
        self.assertEqual(groups[0], {**group, "hooks": [foreign]})
        self.assertEqual(len(groups), 2)  # foreign + prod-delete guard

    def test_refuses_symlinked_parent_directories_before_writing(self):
        for name in ("agents", "hooks", "tools", "agent-harness-backups", ".claude"):
            for apply in (False, True):
                with self.subTest(name=name, apply=apply), tempfile.TemporaryDirectory() as temp:
                    home = Path(temp)
                    claude = home / ".claude"
                    claude.mkdir()
                    outside = home / "outside"
                    outside.mkdir(mode=0o755)
                    sentinel = outside / "sentinel"
                    sentinel.write_text("unchanged")
                    destination = claude if name == ".claude" else claude / name
                    if name == ".claude":
                        claude.rmdir()
                    destination.symlink_to(outside, target_is_directory=True)
                    with self.assertRaises(ValueError):
                        install(home, apply=apply)
                    self.assertEqual(list(outside.iterdir()), [sentinel])
                    self.assertEqual(sentinel.read_text(), "unchanged")
                    self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)

    def test_directory_swap_after_preflight_never_writes_or_removes_outside_files(self):
        outside = self.home / 'outside'
        outside.mkdir()
        (self.claude / 'agents').mkdir()
        sentinel = outside / 'task-owner.md'
        sentinel.write_text('outside fixture')
        from install import atomic_write
        swapped = False

        def swap_before_first_write(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped:
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                (self.claude / 'agents').symlink_to(outside, target_is_directory=True)
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_before_first_write):
            with self.assertRaises((OSError, ValueError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual(sentinel.read_text(), 'outside fixture')
        self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_backup_uses_original_snapshot_when_parent_is_swapped(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        sentinel = outside / 'task-owner.md'
        sentinel.write_text('outside private fixture')
        from install import atomic_write
        swapped = False

        def swap_before_backup(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and 'agent-harness-backups' in path.parts:
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                outside.rename(self.claude / 'agents')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_before_backup):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped, 'backup mutation must actually run')
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'outside private fixture')
        saved, = (self.claude / 'agent-harness-backups').rglob('task-owner.md')
        self.assertEqual(saved.read_text(), 'old owner\n')

    def test_real_directory_replacement_after_backups_never_overwrites_unrelated_files(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        sentinel = outside / 'task-owner.md'
        sentinel.write_text('unrelated outside file')
        from install import atomic_write
        swapped = False

        def swap_after_backups(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/task-owner.md':
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                outside.rename(self.claude / 'agents')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_after_backups):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated outside file')

    def test_rollback_refuses_a_real_directory_replacement_after_one_write(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        (outside / 'task-owner.md').write_text('unrelated owner')
        from install import atomic_write
        swapped = False

        def swap_on_second_managed_write(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/click-tester.md':
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                outside.rename(self.claude / 'agents')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_on_second_managed_write):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated owner')
        self.assertFalse((self.claude / 'agents/click-tester.md').exists())

    def test_real_file_replacement_after_snapshot_is_not_overwritten(self):
        self.seed_existing_installation()
        outsider = self.home / 'unrelated-owner.md'
        outsider.write_text('unrelated leaf')
        from install import atomic_write
        swapped = False

        def swap_leaf_before_write(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/task-owner.md':
                swapped = True
                path.rename(path.with_name('old-owner.md'))
                outsider.rename(path)
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_leaf_before_write):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated leaf')

    def test_rollback_refuses_a_new_leaf_replacing_an_installed_file(self):
        self.seed_existing_installation()
        outsider = self.home / 'unrelated-owner.md'
        outsider.write_text('unrelated rollback leaf')
        from install import atomic_write
        swapped = False

        def swap_leaf_before_failure(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/click-tester.md':
                swapped = True
                owner = self.claude / 'agents/task-owner.md'
                owner.rename(owner.with_name('installed-owner.md'))
                outsider.rename(owner)
                raise OSError('fixture: interrupt after leaf swap')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_leaf_before_failure):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated rollback leaf')

    def test_rollback_pins_published_inode_after_unlink_and_recreation(self):
        from install import atomic_write
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                agents = claude / 'agents'
                agents.mkdir(parents=True)
                owner = agents / 'task-owner.md'
                if existing:
                    owner.write_text('original owner\n')
                original = owner.read_bytes() if existing else None
                retained = False
                injected = False

                def replace_then_fail(path, data, mode=0o600, **kwargs):
                    nonlocal retained, injected
                    if path == agents / 'click-tester.md' and not injected:
                        injected = True
                        published = owner.stat()
                        for name in os.listdir('/dev/fd'):
                            if not name.isdigit():
                                continue
                            try:
                                opened = os.fstat(int(name))
                            except OSError:
                                continue
                            if (opened.st_dev, opened.st_ino) == (published.st_dev, published.st_ino):
                                retained = True
                                break
                        owner.unlink()
                        owner.write_text('unrelated recreated owner\n')
                        raise OSError('fixture: interrupt after unlink and recreation')
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=replace_then_fail):
                    with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                        install(home, apply=True)
                self.assertTrue(injected)
                self.assertTrue(retained, 'the published inode must remain open through rollback')
                self.assertEqual(owner.read_text(), 'unrelated recreated owner\n')
                self.assertEqual(original, b'original owner\n' if existing else None)

    def test_file_replacement_during_final_publish_cannot_report_success(self):
        outsider = self.home / 'unrelated-owner.md'
        outsider.write_text('unrelated final leaf')
        replace = os.replace
        swapped = False

        def swap_after_replace(source, destination, **kwargs):
            nonlocal swapped
            result = replace(source, destination, **kwargs)
            if destination == 'task-owner.md' and not swapped:
                swapped = True
                owner = self.claude / 'agents/task-owner.md'
                owner.rename(owner.with_name('installed-owner.md'))
                outsider.rename(owner)
            return result

        with patch('install.os.replace', side_effect=swap_after_replace):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated final leaf')

    def test_new_directory_swap_between_creation_and_open_is_refused(self):
        from install import DirectoryPins
        for name in ('agents', 'agent-harness-backups'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                (claude / 'settings.json').write_text('{"model":"keep"}\n')
                outside = home / 'outside'
                outside.mkdir(mode=0o755)
                (outside / 'marker').write_text('unrelated')
                if name == 'agents':
                    (outside / 'task-owner.md').write_text('unrelated owner')
                outside_mode = stat.S_IMODE(outside.stat().st_mode)
                original_create = DirectoryPins.create
                original_mkdir = os.mkdir
                active = None
                swapped = False
                injected_path = None

                def track_create(pins, path, **kwargs):
                    nonlocal active
                    active = path
                    try:
                        return original_create(pins, path, **kwargs)
                    finally:
                        active = None

                def swap_created(name_to_make, *args, **kwargs):
                    nonlocal swapped, injected_path
                    result = original_mkdir(name_to_make, *args, **kwargs)
                    if active == claude / name and not swapped:
                        created = active.parent / name_to_make
                        created.rename(created.with_name(created.name + '-moved'))
                        outside.rename(created)
                        swapped = True
                        injected_path = created
                    return result

                with patch('install.DirectoryPins.create', track_create), \
                     patch('install.os.mkdir', side_effect=swap_created):
                    with self.assertRaises((OSError, RuntimeError)):
                        install(home, apply=True)
                self.assertTrue(swapped)
                replacement = injected_path
                self.assertEqual((replacement / 'marker').read_text(), 'unrelated')
                self.assertEqual(stat.S_IMODE(replacement.stat().st_mode), outside_mode)
                if name == 'agents':
                    self.assertEqual((replacement / 'task-owner.md').read_text(), 'unrelated owner')
                else:
                    self.assertEqual([path.name for path in replacement.iterdir()], ['marker'])

    def test_post_replace_fsync_error_rolls_back_the_published_file(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                if existing:
                    agents = claude / 'agents'
                    agents.mkdir()
                    (agents / 'task-owner.md').write_text('original owner\n')
                    (agents / 'task-owner.md').chmod(0o640)
                before = {str(path.relative_to(claude)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                          for path in claude.rglob('*') if path.is_file()}
                replace = os.replace
                fsync = os.fsync
                published = False
                failed = False

                def record_replace(source, destination, **kwargs):
                    nonlocal published
                    result = replace(source, destination, **kwargs)
                    if destination == 'task-owner.md' and not published:
                        published = True
                    return result

                def fail_directory_fsync(fd):
                    nonlocal failed
                    if published and not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
                        failed = True
                        raise OSError('fixture: directory fsync failed after replace')
                    return fsync(fd)

                with patch('install.os.replace', side_effect=record_replace), \
                     patch('install.os.fsync', side_effect=fail_directory_fsync):
                    with self.assertRaisesRegex(OSError, 'fixture: directory fsync failed'):
                        install(home, apply=True)
                self.assertTrue(published)
                self.assertTrue(failed)
                after = {str(path.relative_to(claude)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                         for path in claude.rglob('*') if path.is_file() and 'agent-harness-backups' not in path.parts}
                self.assertEqual(after, before)

    def test_installed_delivery_helpers_can_start(self):
        import subprocess
        import sys
        install(self.home, apply=True)
        for name in ("publish_feature.py", "integrate_local.py", "peer_review.py", "rescue.py"):
            result = subprocess.run([sys.executable, str(self.claude / "hooks" / name), "--help"],
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        watched = subprocess.run([sys.executable, str(self.claude / 'tools/watch-tests.py'),
                                  '--root', str(self.home), '--once', '--', sys.executable, '-c', 'pass'],
                                 text=True, capture_output=True, timeout=10)
        self.assertEqual(watched.returncode, 0, watched.stdout + watched.stderr)

    def test_rejects_bad_markers_before_writing(self):
        (self.claude / "CLAUDE.md").write_text(END)
        with self.assertRaises(ValueError):
            install(self.home, apply=True)
        self.assertFalse((self.claude / "settings.json").exists())

    def test_delivery_workflow_dependency_closure_starts_without_source_imports(self):
        install(self.home, apply=True)
        required = ('deliver.py', 'github_identity.py', 'process.py', 'git_safety.py',
                    'report_file.py', 'publish_feature.py', 'integrate_local.py')
        for name in required:
            target = self.claude / 'hooks' / name
            self.assertTrue(target.is_file(), f'{name} was not installed')
            self.assertEqual(target.read_bytes(), (ROOT / 'harness' / 'hooks' / name).read_bytes())
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        environment.update(HOME=str(self.home), PYTHONNOUSERSITE='1')
        result = subprocess.run([sys.executable, str(self.claude / 'hooks' / 'deliver.py'), '--help'],
                                cwd=self.home, env=environment, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('prepare', result.stdout)
        self.assertIn('finish', result.stdout)

    def test_installed_usage_guard_starts_without_source_imports(self):
        install(self.home, apply=True)
        helper = self.claude / 'hooks' / 'usage_guard.py'
        self.assertTrue(helper.is_file(), 'Usage guard was not installed')
        self.assertEqual(helper.read_bytes(), (ROOT / 'harness/hooks/usage_guard.py').read_bytes())
        state = self.home / 'owned-usage-state'
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        environment.update(HOME=str(self.home), PYTHONNOUSERSITE='1', AGENT_HARNESS_USAGE_DIR=str(state))
        result = subprocess.run([sys.executable, str(helper), '--help'], cwd=self.home,
                                env=environment, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('reconcile', result.stdout)
        self.assertFalse(state.exists(), 'Help must not create usage state')

    def managed_snapshot(self):
        return {str(path.relative_to(self.claude)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                for path in self.claude.rglob('*')
                if path.is_file() and 'agent-harness-backups' not in path.parts}

    def seed_existing_installation(self):
        (self.claude / 'agents').mkdir()
        (self.claude / 'agents/task-owner.md').write_text('old owner\n')
        (self.claude / 'agents/task-owner.md').chmod(0o640)
        (self.claude / 'CLAUDE.md').write_text('user instructions\n')
        (self.claude / 'settings.json').write_text('{"model": "keep-me"}\n')

    def test_missing_payload_is_detected_before_any_installation_write(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        read_bytes = Path.read_bytes
        def missing_payload(path):
            if path == ROOT / 'harness/tools/watch-tests.py':
                raise FileNotFoundError('fixture: final payload missing')
            return read_bytes(path)
        with patch.object(Path, 'read_bytes', missing_payload), self.assertRaises(FileNotFoundError):
            install(self.home, apply=True)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse((self.claude / 'agent-harness-backups').exists())

    def test_fifo_destinations_are_rejected_without_opening_them(self):
        for name in ('settings.json', 'agents/task-owner.md'):
            for apply in (False, True):
                with self.subTest(name=name, apply=apply):
                    path = self.claude / name
                    path.parent.mkdir(exist_ok=True)
                    os.mkfifo(path)
                    try:
                        try:
                            result = subprocess.run([sys.executable, str(ROOT / 'install.py'),
                                                     '--home', str(self.home), *(['--apply'] if apply else [])],
                                                    text=True, capture_output=True, timeout=15)
                        except subprocess.TimeoutExpired:
                            self.fail('installer blocked opening a FIFO')
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('regular file', result.stderr)
                        self.assertFalse((self.claude / 'agent-harness-backups').exists())
                    finally:
                        path.unlink()

    def test_file_in_place_of_managed_directory_is_rejected_before_writing(self):
        (self.claude / 'hooks').write_text('preserve this file')
        before = self.managed_snapshot()
        with self.assertRaisesRegex(ValueError, 'directory'):
            install(self.home, apply=True)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse((self.claude / 'agent-harness-backups').exists())

    def test_failed_replacement_restores_existing_files_and_removes_new_files(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        replace = os.replace
        failed = False
        def fail_once(source, destination, **kwargs):
            nonlocal failed
            in_claude = os.fstat(kwargs['dst_dir_fd']).st_ino == self.claude.stat().st_ino
            if destination == 'settings.json' and in_claude and not failed:
                failed = True
                raise OSError('fixture: settings replacement failed')
            return replace(source, destination, **kwargs)
        with patch('install.os.replace', side_effect=fail_once), self.assertRaisesRegex(OSError, 'fixture'):
            install(self.home, apply=True)
        self.assertTrue(failed)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse(list(self.claude.rglob('.agent-harness-*')))
        saved, = (self.claude / 'agent-harness-backups').rglob('settings.json')
        self.assertEqual(saved.read_bytes(), before['settings.json'][0])
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)

    def test_every_managed_write_boundary_rolls_back_to_exact_originals(self):
        from install import atomic_write

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            claude = home / '.claude'
            claude.mkdir()
            planned = [Path(path) for path in install(home, apply=False)]
            observed = []

            def record_write(path, data, mode=0o600, **kwargs):
                if 'agent-harness-backups' not in path.relative_to(claude).parts:
                    observed.append(path)
                return atomic_write(path, data, mode, **kwargs)

            with patch('install.atomic_write', side_effect=record_write):
                install(home, apply=True)
            self.assertEqual(observed, planned)
            self.assertEqual(len(observed), len(set(observed)))
            relative_plan = [path.relative_to(claude) for path in observed]
        fired_boundaries = set()
        for existing in (False, True):
            for boundary, destination in enumerate(relative_plan):
                with self.subTest(existing=existing, boundary=boundary, destination=str(destination)), \
                        tempfile.TemporaryDirectory() as temporary:
                    home = Path(temporary).resolve()
                    claude = home / '.claude'
                    claude.mkdir()
                    if existing:
                        for index, relative in enumerate(relative_plan):
                            path = claude / relative
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_text('Original managed file: ' + str(relative) + '\n')
                            path.chmod(0o600 if index % 2 else 0o640)
                    (claude / 'CLAUDE.md').write_text('existing instructions\n')
                    (claude / 'settings.json').write_text('{"model":"keep"}\n')
                    foreign = claude / 'foreign.txt'
                    foreign.write_text('unrelated user data\n')
                    foreign.chmod(0o640)

                    def snapshot():
                        return {str(path.relative_to(claude)):
                                (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                                for path in claude.rglob('*')
                                if path.is_file() and 'agent-harness-backups' not in path.parts}

                    before = snapshot()
                    writes = []
                    fired = False

                    def fail_at_boundary(path, data, mode=0o600, **kwargs):
                        nonlocal fired
                        if 'agent-harness-backups' not in path.parts and not fired:
                            relative = path.relative_to(claude)
                            self.assertEqual(relative, relative_plan[len(writes)])
                            if len(writes) == boundary:
                                fired = True
                                fired_boundaries.add((existing, relative))
                                raise OSError('fixture: interrupted managed write')
                            writes.append(relative)
                        return atomic_write(path, data, mode, **kwargs)

                    with patch('install.atomic_write', side_effect=fail_at_boundary):
                        with self.assertRaisesRegex(OSError, 'interrupted managed write'):
                            install(home, apply=True)
                    self.assertTrue(fired, 'planned failure boundary never executed')
                    self.assertEqual(len(writes), boundary)
                    self.assertEqual(snapshot(), before)
                    self.assertFalse(list(claude.rglob('.agent-harness-*')))
        self.assertEqual(fired_boundaries,
                         {(existing, relative) for existing in (False, True) for relative in relative_plan})

    def test_swapped_ancestor_at_each_write_stage_cannot_redirect_install(self):
        from install import atomic_write
        for name in ('agents', 'hooks', 'tools', '.claude'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                for folder in ('agents', 'hooks', 'tools'):
                    (claude / folder).mkdir()
                outside = home / 'outside'
                outside.mkdir()
                marker = outside / 'marker'
                marker.write_text('unchanged')
                swapped = False

                def swap_before_target(path, data, mode=0o600, **kwargs):
                    nonlocal swapped
                    target = claude if name == '.claude' else claude / name
                    if not swapped and (name == '.claude' or path.parent == target):
                        swapped = True
                        target.rename(target.with_name(target.name + '-moved'))
                        target.symlink_to(outside, target_is_directory=True)
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=swap_before_target):
                    with self.assertRaises((OSError, RuntimeError)):
                        install(home, apply=True)
                self.assertTrue(swapped)
                self.assertEqual(list(outside.iterdir()), [marker])
                self.assertEqual(marker.read_text(), 'unchanged')

    def test_final_parent_swap_during_replace_cannot_report_installed(self):
        outside = self.home / 'outside'
        outside.mkdir()
        marker = outside / 'marker'
        marker.write_text('unchanged')
        replace = os.replace
        swapped = False

        def swap_during_last_replace(source, destination, **kwargs):
            nonlocal swapped
            if Path(destination).name == 'settings.json' and not swapped:
                swapped = True
                self.claude.rename(self.home / 'claude-moved')
                self.claude.symlink_to(outside, target_is_directory=True)
            return replace(source, destination, **kwargs)

        with patch('install.os.replace', side_effect=swap_during_last_replace):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [marker])

    def test_backup_directory_swap_cannot_redirect_private_snapshot(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        marker = outside / 'marker'
        marker.write_text('unchanged')
        from install import atomic_write
        swapped = False

        def swap_before_backup(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            backup_root = self.claude / 'agent-harness-backups'
            if not swapped and backup_root in path.parents:
                swapped = True
                backup_root.rename(self.claude / 'backups-moved')
                backup_root.symlink_to(outside, target_is_directory=True)
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_before_backup):
            with self.assertRaises(OSError):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [marker])
        self.assertEqual(marker.read_text(), 'unchanged')

    def test_rollback_failure_is_reported_and_other_files_are_still_restored(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        replace = os.replace
        failed = False
        def fail_install_and_one_restore(source, destination, **kwargs):
            nonlocal failed
            in_claude = os.fstat(kwargs['dst_dir_fd']).st_ino == self.claude.stat().st_ino
            in_agents = os.fstat(kwargs['dst_dir_fd']).st_ino == (self.claude / 'agents').stat().st_ino
            if destination == 'settings.json' and in_claude:
                failed = True
                raise OSError('fixture: write failure')
            if failed and destination == 'task-owner.md' and in_agents:
                raise OSError('fixture: restore failure')
            return replace(source, destination, **kwargs)
        with patch('install.os.replace', side_effect=fail_install_and_one_restore):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete') as raised:
                install(self.home, apply=True)
        self.assertIn('agents/task-owner.md', str(raised.exception))
        self.assertIn('agent-harness-backups', str(raised.exception))
        after = self.managed_snapshot()
        self.assertEqual(after.pop('CLAUDE.md'), before['CLAUDE.md'])
        self.assertEqual(after.pop('settings.json'), before['settings.json'])
        self.assertEqual(set(after), {'agents/task-owner.md'})


class DurableScratchInstallTests(unittest.TestCase):
    def setUp(self):
        # Sessions started after install export CLAUDE_CODE_TMPDIR; tests must not depend on the host.
        isolate = patch.dict(os.environ)
        isolate.start()
        self.addCleanup(isolate.stop)
        os.environ.pop("CLAUDE_CODE_TMPDIR", None)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.claude = self.home / ".claude"
        self.claude.mkdir()
        self.scratch = self.home / ".agent-harness" / "scratch"

    def settings(self):
        return json.loads((self.claude / "settings.json").read_text())

    def test_sets_managed_tmpdir_and_prepares_private_root(self):
        (self.claude / "settings.json").write_text(json.dumps({"env": {"EXAMPLE": "1"}}))
        install(self.home, apply=True)
        env = self.settings()["env"]
        self.assertEqual(env, {"EXAMPLE": "1", "CLAUDE_CODE_TMPDIR": str(self.scratch)})
        self.assertIn("Bash(python3 ~/.claude/hooks/workdir.py prune)", self.settings()["permissions"]["allow"])
        self.assertEqual((self.claude / "hooks/workdir.py").read_bytes(),
                         (ROOT / "harness/hooks/workdir.py").read_bytes())
        calls = []
        status = scratch_status(self.home, True, run=lambda *a, **k: calls.append(a[0]) or
                                subprocess.CompletedProcess(a[0], 0))
        self.assertEqual(stat.S_IMODE(self.scratch.stat().st_mode), 0o700)
        self.assertTrue((self.scratch / ".metadata_never_index").exists())
        self.assertIn("restart running sessions", status)
        if sys.platform == "darwin":
            self.assertEqual(calls, [["tmutil", "addexclusion", str(self.scratch)]])

    def test_user_value_is_never_overwritten(self):
        (self.claude / "settings.json").write_text(json.dumps({"env": {"CLAUDE_CODE_TMPDIR": "/tmp"}}))
        install(self.home, apply=True)
        self.assertEqual(self.settings()["env"]["CLAUDE_CODE_TMPDIR"], "/tmp")
        self.assertIn("not managed", scratch_status(self.home, True))
        self.assertFalse(self.scratch.exists())

    def test_opt_out_removes_only_managed_value_and_is_remembered(self):
        install(self.home, apply=True)
        self.assertIn("CLAUDE_CODE_TMPDIR", self.settings()["env"])
        install(self.home, apply=True, durable_tmp=False)
        self.assertNotIn("CLAUDE_CODE_TMPDIR", self.settings().get("env", {}))
        save_durable_tmp_choice(self.home, False)
        self.assertFalse(durable_tmp_choice(self.home, None))
        install(self.home, apply=True, durable_tmp=durable_tmp_choice(self.home, None))
        self.assertNotIn("CLAUDE_CODE_TMPDIR", self.settings().get("env", {}))
        state = self.home / ".agent-harness" / "install-state.json"
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
        self.assertTrue(durable_tmp_choice(self.home, True))
        foreign = {"env": {"CLAUDE_CODE_TMPDIR": "/Volumes/fast/tmp"}}
        (self.claude / "settings.json").write_text(json.dumps(foreign))
        install(self.home, apply=True, durable_tmp=False)
        self.assertEqual(self.settings()["env"], foreign["env"])

    def test_shell_exported_value_is_respected(self):
        with patch.dict(os.environ, {"CLAUDE_CODE_TMPDIR": "/Volumes/fast"}):
            install(self.home, apply=True)
            self.assertIn("exported in the shell", scratch_status(self.home, True))
        self.assertNotIn("CLAUDE_CODE_TMPDIR", self.settings().get("env", {}))

    def test_saved_choice_is_parsed_strictly(self):
        state = self.home / ".agent-harness" / "install-state.json"
        state.parent.mkdir()
        for raw, expected in (('{"durable_tmp": "false"}', True), ('{"durable_tmp": false}', False),
                              ("not json", True), ("[]", True)):
            state.write_text(raw)
            self.assertEqual(durable_tmp_choice(self.home, None), expected, raw)

    def test_symlinked_harness_root_fails_before_settings_change(self):
        outside = self.home / "outside"
        outside.mkdir()
        (self.home / ".agent-harness").symlink_to(outside)
        (self.claude / "settings.json").write_text("{}")
        result = subprocess.run([sys.executable, str(ROOT / "install.py"), "--apply", "--no-durable-tmp",
                                 "--home", str(self.home)], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("could not save the durable-tmp choice", result.stderr)
        self.assertEqual((self.claude / "settings.json").read_text(), "{}")
        self.assertEqual(list(outside.iterdir()), [])

    def test_rejects_non_object_env(self):
        (self.claude / "settings.json").write_text(json.dumps({"env": ["bad"]}))
        with self.assertRaises(ValueError):
            install(self.home, apply=True)


if __name__ == "__main__":
    unittest.main()
