"""Release 1001 registrations (docs/direction.md, plan section 4.2): the exact hook tables both installers write.

Ten Claude Code handlers and seven Codex handlers, every one through the off-switch launcher, none with
onFailure "block", and none on a tool event whose matcher matches Bash: a Bash call starts no harness process.
An upgrade of a home that holds release 1000's settings (tests/data/settings_release_1000.json, 52 handlers, as the
base commit's install.py wrote them) leaves exactly the new table plus the user's own hooks and rules.

Everything runs in a temporary HOME; AH_LOCAL_CONFIG points at an empty file so the real local.json never leaks in.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))

import install  # noqa: E402

try:
    import install_codex  # noqa: E402
except (ImportError, SyntaxError):  # Python < 3.11 has no tomllib
    install_codex = None

TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied")
DB_MATCHER = r".*d1_database_query|mcp__.*__(execute_sql|run_sql|query|sql)|mcp__.*__hyperdrive_.*"
# (event, matcher, script, args, timeout, async) in file order
CLAUDE_TABLE = [
    ("PreToolUse", DB_MATCHER, "prod_delete_guard.py", (), 30, False),
    ("SessionEnd", None, "autosave.py", (), 30, False),
    ("SessionStart", None, "session_env.py", (), 10, False),
    ("SessionStart", None, "wal.py", ("session",), 10, False),
    ("Stop", None, "autosave.py", (), 30, True),
    ("Stop", None, "dropped_gate.py", (), 15, False),
    ("SubagentStart", ".*", "wal.py", ("subagent",), 10, False),
    ("SubagentStop", ".*", "wal.py", ("subagent_stop",), 10, False),
    ("SubagentStop", ".*", "autosave.py", (), 30, True),
    ("UserPromptSubmit", None, "owner_inbox.py", ("hook",), 5, False),
]
CODEX_TABLE = [  # (event, script, args, timeout)
    ("SessionStart", "wal.py", ("hook",), 10),
    ("SessionStart", "owner_inbox.py", ("hook",), 5),
    ("SessionStart", "session_env.py", (), 10),
    ("Stop", "wal.py", ("hook",), 10),
    ("Stop", "autosave.py", (), 30),
    ("SubagentStart", "wal.py", ("hook",), 10),
    ("UserPromptSubmit", "owner_inbox.py", ("hook",), 5),
]


def matches_bash(matcher) -> bool:
    """As Claude Code applies a matcher (p1 2.3): none, empty or "*" matches every tool; otherwise a regex that
    must match the whole tool name."""
    if matcher in (None, "", "*"):
        return True
    try:
        return re.fullmatch(matcher, "Bash") is not None
    except re.error:
        return True  # an unreadable matcher is not proven to miss Bash


def claude_rows(hooks: dict, claude: Path) -> list:
    rows = []
    for event in sorted(hooks):
        for group in hooks[event]:
            for handler in group["hooks"]:
                args = install.hook_argv(handler)
                if not args or os.path.dirname(args[0]) != str(claude / "hooks"):
                    continue
                rows.append((event, group.get("matcher"), os.path.basename(args[0]), tuple(args[1:]),
                             handler.get("timeout"), bool(handler.get("async"))))
    return rows


class Isolated(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ah-reg-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(os.path.realpath(self.tmp.name))
        self.claude = self.home / ".claude"
        empty = self.home / "local.json"
        empty.write_text("{}\n")
        env = mock.patch.dict(os.environ, {"HOME": str(self.home), "AH_LOCAL_CONFIG": str(empty)})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDE_CODE_TMPDIR", None)
        import ah_local  # noqa: PLC0415 - read once per process: drop what an earlier test cached
        ah_local.reset()
        self.addCleanup(ah_local.reset)


class ClaudeTable(Isolated):
    def test_the_exact_ten_handlers(self):
        self.assertEqual(claude_rows(install.managed_hooks(self.claude), self.claude), CLAUDE_TABLE)

    def test_no_tool_event_handler_matches_bash(self):
        hooks = install.managed_hooks(self.claude)
        for event in TOOL_EVENTS:
            for group in hooks.get(event, []):
                self.assertFalse(matches_bash(group.get("matcher")), (event, group.get("matcher")))

    def test_the_matcher_helper_can_fail(self):
        for matcher in ("Bash", "Bash|PowerShell", ".*", None, "*", "B.*", "Agent|Task|Workflow|Bash"):
            self.assertTrue(matches_bash(matcher), matcher)
        self.assertFalse(matches_bash(DB_MATCHER))

    def test_every_handler_runs_through_the_launcher_and_none_blocks_on_failure(self):
        launcher = str(self.claude / "hooks" / "ah_hook.py")
        for event, groups in install.managed_hooks(self.claude).items():
            for group in groups:
                for handler in group["hooks"]:
                    self.assertEqual(handler["args"][0], launcher, (event, handler))
                    self.assertNotIn("onFailure", handler, (event, handler))
                    self.assertTrue((ROOT / "harness" / "hooks" / handler["args"][1]).is_file(), handler)

    def test_a_local_db_tool_pattern_that_matches_bash_is_not_registered(self):
        local = self.home / "local.json"
        local.write_text(json.dumps({"db_tool_patterns": [{"tool": "Bash"}, {"tool": ".*"},
                                                          {"tool": "mcp__mine__run"}]}))
        import ah_local  # noqa: PLC0415
        ah_local.reset()
        hooks = install.managed_hooks(self.claude)
        matcher = hooks["PreToolUse"][0]["matcher"]
        self.assertIn("mcp__mine__run", matcher)
        self.assertFalse(matches_bash(matcher), matcher)


class ClaudeUpgrade(Isolated):
    USER_HOOK = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/mine/check.sh"}]}
    USER_RULE = "Bash(make test)"

    def old_settings(self) -> dict:
        text = (DATA / "settings_release_1000.json").read_text().replace("/HOME", str(self.home))
        settings = json.loads(text)
        settings["hooks"]["PreToolUse"].insert(0, self.USER_HOOK)
        settings["permissions"]["allow"].append(self.USER_RULE)
        return settings

    def test_the_fixture_is_release_1000(self):
        settings = json.loads((DATA / "settings_release_1000.json").read_text())
        handlers = [h for groups in settings["hooks"].values() for g in groups for h in g["hooks"]]
        self.assertEqual(len(handlers), 52)
        self.assertTrue(any(matches_bash(g.get("matcher")) for e in TOOL_EVENTS for g in settings["hooks"].get(e, [])))

    def test_upgrade_leaves_exactly_the_new_table_plus_the_user_hook_and_rule(self):
        self.claude.mkdir()
        (self.claude / "settings.json").write_text(json.dumps(self.old_settings()))
        install.install(self.home, apply=True, durable_tmp=False)
        after = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(claude_rows(after["hooks"], self.claude), CLAUDE_TABLE)
        self.assertIn(self.USER_HOOK, after["hooks"]["PreToolUse"])
        others = [h for groups in after["hooks"].values() for g in groups for h in g["hooks"]
                  if not install.hook_argv(h) or os.path.dirname(install.hook_argv(h)[0]) != str(self.claude / "hooks")]
        self.assertEqual(others, self.USER_HOOK["hooks"])  # nothing else survived
        allowed = after["permissions"]["allow"]
        self.assertIn(self.USER_RULE, allowed)
        for name in ("commit_policy.py", "merge_gate.py", "spec_flow.py", "resource_budget.py"):
            self.assertFalse([r for r in allowed if name in r], name)
        for event in TOOL_EVENTS:  # the user's own Bash hook is the only one left on Bash
            harness = [g for g in after["hooks"].get(event, []) if g is not self.USER_HOOK and g != self.USER_HOOK]
            self.assertFalse([g for g in harness if matches_bash(g.get("matcher"))], event)
        install.install(self.home, apply=True, durable_tmp=False)
        self.assertEqual(json.loads((self.claude / "settings.json").read_text()), after)  # idempotent

    def test_a_user_rule_like_a_retired_one_stays(self):
        settings = self.old_settings()
        mine = "Bash(python3 ~/.claude/hooks/commit_policy.py check-message --file mine.txt)"
        settings["permissions"]["allow"].append(mine)
        merged = install.merged_settings(settings, self.claude, durable_tmp=False)
        self.assertIn(mine, merged["permissions"]["allow"])
        self.assertNotIn("Bash(python3 ~/.claude/hooks/commit_policy.py check-message *)", merged["permissions"]["allow"])

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_the_commit_msg_backstop_keys_are_unset(self):
        gitconfig = self.home / ".gitconfig"
        gitconfig.write_text("[user]\n\tname = Me\n[hook \"agent-harness-commit-policy\"]\n\tevent = commit-msg\n"
                             "\tcommand = f=/x; exec python3 \"$f\" commit_policy.py git-hook\n"
                             "[hook \"mine\"]\n\tevent = pre-commit\n\tcommand = true\n")
        line = install.remove_git_backstop(self.home, install.GIT_HOOK_KEY, apply=True)
        self.assertIn("unset", line)
        env = {**os.environ, "HOME": str(self.home)}

        def get(key):
            return subprocess.run(["git", "config", "--file", str(gitconfig), "--get-all", key], capture_output=True,
                                  text=True, env=env, timeout=10).stdout.strip()
        self.assertEqual(get("hook.agent-harness-commit-policy.event"), "")
        self.assertEqual(get("hook.agent-harness-commit-policy.command"), "")
        self.assertEqual(get("hook.mine.command"), "true")
        self.assertEqual(get("user.name"), "Me")
        self.assertIn("not registered", install.remove_git_backstop(self.home, install.GIT_HOOK_KEY, apply=True))


@unittest.skipUnless(install_codex is not None and install_codex.tomllib is not None, "install_codex needs Python 3.11")
class CodexTable(Isolated):
    def rows(self, hooks: dict, codex_home: Path) -> list:
        out = []
        for event in sorted(hooks["hooks"]):
            for group in hooks["hooks"][event]:
                for handler in group["hooks"]:
                    argv = install_codex.command_argv(handler["command"])
                    if argv and os.path.dirname(argv[0]) == str(codex_home / "agent-harness"):
                        out.append((event, os.path.basename(argv[0]), tuple(argv[1:]), handler.get("timeout")))
        return out

    def test_the_exact_seven_handlers_and_no_pretooluse(self):
        codex_home = self.home / ".codex"
        hooks = install_codex.merge_hooks({}, codex_home)
        self.assertEqual(self.rows(hooks, codex_home), CODEX_TABLE)
        self.assertNotIn("PreToolUse", hooks["hooks"])
        for groups in hooks["hooks"].values():
            for group in groups:
                for handler in group["hooks"]:
                    self.assertIn("/agent-harness/ah_hook.py", handler["command"])

    def test_upgrade_from_release_1000_keeps_the_users_hooks(self):
        codex_home = self.home / ".codex"
        old = json.loads((DATA / "codex_hooks_release_1000.json").read_text().replace("/HOME", str(self.home)))
        mine = {"hooks": [{"type": "command", "command": "/opt/mine/pre.sh", "timeout": 3}]}
        old["hooks"]["PreToolUse"].append(mine)
        old["hooks"]["Notification"] = [mine]
        merged = install_codex.merge_hooks(old, codex_home)
        self.assertEqual(self.rows(merged, codex_home), CODEX_TABLE)
        self.assertEqual(merged["hooks"]["PreToolUse"], [mine])  # the user's own stays; every harness one went
        self.assertEqual(merged["hooks"]["Notification"], [mine])
        self.assertNotIn("Interrupt", merged["hooks"])
        self.assertEqual(install_codex.merge_hooks(merged, codex_home), merged)


if __name__ == "__main__":
    unittest.main()
