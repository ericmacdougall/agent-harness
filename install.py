#!/usr/bin/env python3
"""Install Agent Harness into a Claude Code user directory without replacing other settings."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
START = "<!-- agent-harness:start -->"
END = "<!-- agent-harness:end -->"
AGENTS = ("task-owner.md", "click-tester.md", "fixer.md", "red-team.md")
HOOKS = ("process.py", "git_safety.py", "github_identity.py", "report_file.py", "usage_guard.py", "wal.py", "wal_note.py", "peer_review.py", "rescue.py", "publish_feature.py", "integrate_local.py", "deliver.py",
         "ticket_adapters.py", "commit_policy.py", "commit_policy.json", "workdir.py",
         "spec_flow.py", "spec_policy.json", "spec_template.md", "provenance.py", "provenance_policy.json", "provenance_hooks.py", "safe_input.py", "review_map.py",
         "review_diagnostics.py", "review_policy.json", "merge_gate.py",
         "heavy_job_guard.py", "run_capped.py", "run_probe.py", "resource_budget.py", "agent_gate.py", "ops_watch.py", "resource_limits.json",
         "domain_gates.py", "domain_checklists.json",
         "command_guard.py", "command_guard_hook.py", "redact.py", "kill_guard.py", "kill_guard_policy.json",
         "doctor.py", "hooks_manifest.json", "rules.json", "ah.py", "ah_kill.py", "liveness.py",
         "model_tiers.py", "model_tiers.json", "escalation.py", "tier_gate.py",
         "ahd.py", "ahd_peek.py", "ahd_policy.json",
         "commit_policy.local.json.example", "spec_policy.local.json.example", "ledger_reminder.py", "log_backup.py", "bg_job.py", "bg_lint.py",
         "dropped_gate.py", "ask_reminders.py")  # dropped-owner gate and ask reminders (goodqa#14791)
GIT_HOOK_KEY = "agent-harness-commit-policy"
MIN_GIT_HOOKS = (2, 54)  # config-based hooks (hook.<name>.event)
TOOLS = ("watch-tests.py",)
SKILLS = ("check-dropped-workstreams/SKILL.md", "check-dropped-workstreams/scan.py")  # thin wrappers over ah
TMPDIR_KEY = "CLAUDE_CODE_TMPDIR"
INSTALL_STATE = "install-state.json"
MAX_SOCKET_PATH = 100  # macOS sun_path is 104 bytes; Claude Code puts sockets in <root>/cc-socks/
NO_TARGET_CHECK = object()
NO_CONTENT_CHECK = object()


class DirectoryPublicationError(OSError):
    """An exclusive directory publish could not be completed safely."""


def managed_scripts(claude: Path) -> set[str]:
    return {str(claude / "hooks" / name)
            for name in ("wal.py", "commit_policy.py", "spec_flow.py", "provenance_hooks.py", "heavy_job_guard.py", "agent_gate.py",
                         "command_guard_hook.py", "kill_guard.py", "tier_gate.py", "merge_gate.py", "ledger_reminder.py", "log_backup.py", "bg_lint.py",
                         "dropped_gate.py")}


# Every agent type: a narrower matcher left general-purpose, claude and Explore owners without any
# SubagentStart/Stop WAL record, so no liveness check could see them stop (goodqa#14613, the Solve drop).
SUBAGENT_MATCHER = ".*"
GOODQA_STATUS_TOOLS = (r"^mcp__.*[Gg][Oo][Oo][Dd][Qq][Aa].*__(close_issue_done|close_issue_wont_fix|update_issue|"
                       r"bulk_update_issues|archive_issue|reassign_issue|call_api)$")


def provenance_hook_groups(claude: Path) -> dict[str, list[dict]]:
    """Requirement-provenance gates (docs/provenance.md). Modes live in provenance_policy.json, not here:
    ask-gate enforces, stop-lint warns. Each hook fails open on its own errors, so none sets onFailure."""
    script = str(claude / "hooks" / "provenance_hooks.py")

    def hook(name: str) -> dict:
        return {"type": "command", "command": "python3", "args": [script, name], "timeout": 10}

    return {
        "PreToolUse": [{"matcher": "AskUserQuestion", "hooks": [hook("ask-gate")]}],
        "Stop": [{"hooks": [hook("stop-lint")]}],
        "UserPromptSubmit": [{"hooks": [hook("prompt")]}],
    }


def merge_gate_hook(claude: Path) -> dict:
    """Merge gate (docs/operations.md#merge-gate): blocks PR merges unless every check on the head is green.
    It rides in the WAL pretool group, whose matcher already covers Bash and the write tools (the waiver state
    files must not be edited by hand). Its own deadline is 40 s; onFailure block turns a crash into a block."""
    return {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "merge_gate.py"), "hook"],
            "timeout": 60, "onFailure": "block"}


def command_guard_group(claude: Path) -> dict:
    """Destructive and config-dump command guard (GoodQA #14471, docs/operations.md). The launcher blocks on its
    own when the analyser fails; onFailure covers the launcher itself. The `hook` verb marks it a fail-closed
    gate for the Go front door (cmd/harness/gates.json); the launcher ignores its arguments."""
    return {"matcher": "Bash|PowerShell", "hooks": [{
        "type": "command", "command": "python3", "args": [str(claude / "hooks" / "command_guard_hook.py"), "hook"],
        "timeout": 30, "onFailure": "block"}]}


def kill_guard_group(claude: Path) -> dict:
    """Broad-kill and unowned-PID kill guard (GoodQA #14506). Its launcher fails closed on its own."""
    return {"matcher": "Bash|PowerShell", "hooks": [{
        "type": "command", "command": "python3", "args": [str(claude / "hooks" / "kill_guard.py"), "hook"],
        "timeout": 30, "onFailure": "block"}]}


def managed_hooks(claude: Path, provenance: bool = True, command_guard: bool = True,
                  log_backup: bool = True) -> dict[str, list[dict]]:
    script = str(claude / "hooks" / "wal.py")
    policy = {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "commit_policy.py"), "hook"],
              "timeout": 60, "onFailure": "block"}  # gh pr create checks GitHub and GoodQA
    # Spec gate: GoodQA status changes; internal budget 40 s, so the explanation arrives before 60 s.
    spec_gate = {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "spec_flow.py"), "hook"],
                 "timeout": 60, "onFailure": "block"}

    # Resource guards fail OPEN (no onFailure=block): a guard bug must never stop all Bash or Agent calls.
    heavy_guard = {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "heavy_job_guard.py")],
                   "timeout": 10}
    agent_gate = {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "agent_gate.py")], "timeout": 10}

    def command(event: str, fail_closed: bool = False) -> dict:
        hook = {"type": "command", "command": "python3", "args": [script, event], "timeout": 10}
        if fail_closed:
            hook["onFailure"] = "block"
        return hook

    # Model ladder (goodqa#14527): rung enforcement on spawns, launch lines and the live-agent cap.
    # Fails open on its own errors (an unreadable tier table denies from inside the hook), so no onFailure.
    def ladder(action: str, fail_closed: bool = False) -> dict:
        hook = {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "tier_gate.py"), action],
                "timeout": 10}
        if fail_closed:
            hook["onFailure"] = "block"
        return hook

    managed = {
        "SessionStart": [{"hooks": [command("session")]}],
        "UserPromptSubmit": [{"hooks": [command("prompt", True)]}],
        "SubagentStart": [{
            "matcher": SUBAGENT_MATCHER,
            "hooks": [command("subagent")],
        }, {
            "hooks": [ladder("start")],
        }],
        "SubagentStop": [{
            "matcher": SUBAGENT_MATCHER,
            "hooks": [command("subagent_stop")],
        }, {
            "hooks": [ladder("stop")],
        }],
        "PreToolUse": [{
            "matcher": "Agent|Task|Workflow|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit",
            "hooks": [command("pretool", True), merge_gate_hook(claude)],
        }, {
            "matcher": "Agent|Task|Workflow|Bash",
            "hooks": [ladder("hook", True)],
        }, {
            # Commit message policy: validates git commit / gh pr merge --squash before they run.
            "matcher": "Bash",
            "hooks": [policy, {"type": "command", "command": "python3",  # advisory bg_lint: warns, never blocks
                               "args": [str(claude / "hooks" / "bg_lint.py")], "timeout": 5}],
        }, {
            # Route heavy Mac work (browsers, full suites, builds) to dev2; advisory for hostile probes.
            "matcher": "Bash",
            "hooks": [heavy_guard],
        }, {
            "matcher": "Agent|Task|Workflow",
            "hooks": [agent_gate],
        }, {
            "matcher": GOODQA_STATUS_TOOLS,
            "hooks": [spec_gate],
        }],
    }
    if command_guard:
        managed["PreToolUse"].insert(0, command_guard_group(claude))
        managed["PreToolUse"].insert(1, kill_guard_group(claude))
    if log_backup:
        # Visible alert when the scheduled log backup has not succeeded for an hour; fails open. Only registered
        # where the backup is opted in (--log-backup, or already installed), so a host without it gets no alert.
        managed["SessionStart"].append({"hooks": [{
            "type": "command", "command": "python3", "args": [str(claude / "hooks" / "log_backup.py"), "session-start"],
            "timeout": 10}]})
    if provenance:
        for event, groups in provenance_hook_groups(claude).items():
            managed.setdefault(event, []).extend(groups)
    # Dropped-owner gate (goodqa#14791, docs/ah-query-spec.md): blocks the main agent's turn end while a DROPPED
    # owner has no recorded disposition; bounded per problem signature; fails open on its own errors.
    managed.setdefault("Stop", []).append({"hooks": [{"type": "command", "command": "python3",
                                                       "args": [str(claude / "hooks" / "dropped_gate.py")], "timeout": 15}]})
    managed.setdefault("SubagentStop", []).append({"matcher": SUBAGENT_MATCHER, "hooks": [{
        "type": "command", "command": "python3", "args": [str(claude / "hooks" / "dropped_gate.py"), "subagent-stop"],
        "timeout": 15}]})
    # Local-ledger reminder (docs/ledger.md): rate limited and dismissible; fails open, so no onFailure.
    reminder = {"type": "command", "command": "python3", "args": [str(claude / "hooks" / "ledger_reminder.py")], "timeout": 3}
    for event in ("SessionStart", "UserPromptSubmit"):
        managed.setdefault(event, []).append({"hooks": [reminder]})
    return managed


def durable_scratch(claude: Path) -> Path:
    """Reboot-surviving home for Claude Code's temp dir (scratchpad, task output)."""
    return claude.parent / ".agent-harness" / "scratch"


def merged_settings(current: dict, claude: Path, durable_tmp: bool = True, provenance: bool = True,
                    command_guard: bool = True, log_backup: bool = True) -> dict:
    settings = json.loads(json.dumps(current))
    env = settings.get("env", {})
    if not isinstance(env, dict):
        raise ValueError("settings.json env must be an object")
    managed_tmp = str(durable_scratch(claude))
    shell_value = os.environ.get(TMPDIR_KEY)
    if durable_tmp and TMPDIR_KEY not in env and shell_value in (None, "", managed_tmp):
        # A value exported in the shell is the user's choice too; settings env would override it.
        # Never overwrite a user's value: setting it (even to /tmp) is the opt-out.
        settings["env"] = {**env, TMPDIR_KEY: managed_tmp}
    elif not durable_tmp and env.get(TMPDIR_KEY) == managed_tmp:
        settings["env"] = {key: value for key, value in env.items() if key != TMPDIR_KEY}
    hooks = settings.setdefault("hooks", {})
    scripts = managed_scripts(claude)
    wanted = managed_hooks(claude, provenance, command_guard, log_backup)
    for event in sorted(set(wanted) | set(managed_hooks(claude, True))):
        managed = wanted.get(event, [])
        entries = hooks.setdefault(event, [])
        had_entries = bool(entries)
        preserved = []
        for item in entries:
            remaining = [
                hook for hook in item.get("hooks", [])
                if not (hook.get("type") == "command"
                        and hook.get("command") == "python3"
                        and (hook.get("args") or [None])[0] in scripts)
            ]
            if remaining == item.get("hooks", []):
                preserved.append(item)
            elif remaining:
                preserved.append({**item, "hooks": remaining})
        entries[:] = preserved
        entries.extend(managed)
        if not entries and had_entries:
            del hooks[event]  # an uninstalled gate leaves no empty event behind; a user's own empty list stays
    allowed = settings.setdefault("permissions", {}).setdefault("allow", [])
    for name in ("wal_note.py", "publish_feature.py", "integrate_local.py", "deliver.py"):
        rule = f"Bash(python3 ~/.claude/hooks/{name} *)"
        if rule not in allowed:
            allowed.append(rule)
    # Read-only policy checks are preapproved; `waive` deliberately is not.
    for action in ("check-message", "check-range", "report"):
        rule = f"Bash(python3 ~/.claude/hooks/commit_policy.py {action} *)"
        if rule not in allowed:
            allowed.append(rule)
    for action in ("check", "report"):  # merge gate reads; `waive` is deliberately not preapproved
        rule = f"Bash(python3 ~/.claude/hooks/merge_gate.py {action} *)"
        if rule not in allowed:
            allowed.append(rule)
    # Read-only spec checks are preapproved; commands that post to tickets are not.
    for action in ("lint", "status"):
        rule = f"Bash(python3 ~/.claude/hooks/spec_flow.py {action} *)"
        if rule not in allowed:
            allowed.append(rule)
    for action in ("check", "capacity"):  # read-only; run_capped.py/run_probe.py run arbitrary commands, so stay prompted
        rule = f"Bash(python3 ~/.claude/hooks/resource_budget.py {action} *)"
        if rule not in allowed:
            allowed.append(rule)
    # ah reads are local or GoodQA reads; ah writes (task, ticket comment, spool) stay prompted.
    for action in ("owners", "user-msg", "disk", "ticket get", "ticket comments", "write result", "task list"):
        rule = f"Bash(python3 ~/.claude/hooks/ah.py {action}*)"
        if rule not in allowed:
            allowed.append(rule)
    rule = "Bash(python3 ~/.claude/hooks/workdir.py prune)"  # dry run only; --apply still asks
    if rule not in allowed:
        allowed.append(rule)
    return settings


def git_hook_status(home: Path, key: str, script: Path, *, apply: bool, git: str = "git") -> str:
    """Register the commit-msg backstop as an additive config-based hook.

    Never touches core.hooksPath, so repository hooks keep running. Prior values
    are restored if any write fails. Older Git ignores hook.<name> keys, so the
    result says the backstop is inactive instead of claiming protection.
    """
    import shlex
    import subprocess
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["HOME"] = str(home)
    config = ["--file", str(home / ".gitconfig")]
    try:
        out = subprocess.run([git, "--version"], capture_output=True, text=True, timeout=10, env=env).stdout
    except (OSError, subprocess.TimeoutExpired):
        return "commit-msg backstop inactive: git not found"
    match = re.search(r"(\d+)\.(\d+)", out)
    version = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
    if version < MIN_GIT_HOOKS:
        return f"commit-msg backstop inactive: git {out.strip()} lacks config-based hooks (needs 2.54+)"
    command = f'f={shlex.quote(str(script))}; [ -f "$f" ] || exit 0; exec python3 "$f" git-hook'
    if not apply:
        return f"would register git hook.{key} (commit-msg)"
    def get(name):
        result = subprocess.run([git, "config", *config, "--get-all", f"hook.{key}.{name}"],
                                capture_output=True, text=True, env=env, timeout=10)
        return result.stdout.splitlines() if result.returncode == 0 else []
    prior = {name: get(name) for name in ("event", "command")}
    try:
        for name, value in (("event", "commit-msg"), ("command", command)):
            subprocess.run([git, "config", *config, "--replace-all", f"hook.{key}.{name}", value],
                           check=True, capture_output=True, env=env, timeout=10)
    except (OSError, subprocess.SubprocessError):
        for name, values in prior.items():
            subprocess.run([git, "config", *config, "--unset-all", f"hook.{key}.{name}"],
                           capture_output=True, env=env, timeout=10)
            for value in values:
                subprocess.run([git, "config", *config, "--add", f"hook.{key}.{name}", value],
                               capture_output=True, env=env, timeout=10)
        raise
    return f"registered git hook.{key} (commit-msg) in {home / '.gitconfig'}"


def merged_instructions(existing: str, instructions: str) -> str:
    block = f"{START}\n{instructions.rstrip()}\n{END}"
    lines = existing.splitlines(keepends=True)
    starts, ends = markdown_marker_lines(lines, START, END)
    if starts or ends:
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            raise ValueError("CLAUDE.md has malformed Agent Harness markers; resolve manually")
        managed = ''.join(lines[starts[0] + 1:ends[0]]).lstrip()
        if not managed.startswith('# Agent Harness engineering workflow\n'):
            raise ValueError('CLAUDE.md markers do not enclose a known Agent Harness block; resolve manually')
        ending = lines[ends[0]][len(END):]
        return ''.join(lines[:starts[0]]) + block + ending + ''.join(lines[ends[0] + 1:])
    return existing.rstrip() + ("\n\n" if existing.strip() else "") + block + "\n"


def markdown_marker_lines(lines: list[str], start: str, end: str) -> tuple[list[int], list[int]]:
    """Find managed marker lines outside Markdown fenced examples."""
    starts, ends = [], []
    fence = None
    for i, line in enumerate(lines):
        plain = line.rstrip('\r\n')
        opening = re.match(r'^ {0,3}(`{3,}|~{3,})', plain)
        if opening:
            run = opening.group(1)
            if fence is None:
                fence = (run[0], len(run))
            elif (run[0] == fence[0] and len(run) >= fence[1]
                  and not plain[opening.end():].strip()):
                fence = None
            continue
        if fence is None:
            if plain == start:
                starts.append(i)
            elif plain == end:
                ends.append(i)
    return starts, ends


@contextlib.contextmanager
def parent_fd(path: Path):
    """Pin each parent directory without following a swapped symlink."""
    parts = path.absolute().parts
    directory = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        yield directory
    finally:
        os.close(directory)


def require_current_parent(path: Path, pinned: int) -> None:
    with parent_fd(path) as current:
        opened, named = os.fstat(pinned), os.fstat(current)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise OSError(f'Parent directory changed for {path.name}')


def require_pinned_parent(path: Path, directory: int, pinned_parent) -> None:
    if pinned_parent is not None:
        opened, pinned = os.fstat(directory), os.fstat(pinned_parent)
        if (opened.st_dev, opened.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise OSError(f'Parent directory replaced for {path.name}')
    require_current_parent(path, directory)


def rename_directory_exclusive(parent: int, staged: str, destination: str) -> None:
    """Publish a staged directory without replacing an empty concurrent winner."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        name, exclusive_flag = 'renameatx_np', 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith('linux'):
        name, exclusive_flag = 'renameat2', 0x1  # RENAME_NOREPLACE
    else:
        raise DirectoryPublicationError('Exclusive directory publication is unavailable on this platform')
    rename = getattr(libc, name, None)
    if rename is None:
        raise DirectoryPublicationError('Exclusive directory publication is unavailable on this platform')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    if rename(parent, os.fsencode(staged), parent, os.fsencode(destination), exclusive_flag):
        error = ctypes.get_errno()
        if not error:
            raise DirectoryPublicationError('Exclusive directory publication failed without an error code')
        if error in (errno.ENOSYS, errno.ENOTSUP, errno.EINVAL):
            raise DirectoryPublicationError('Exclusive directory publication is unavailable on this filesystem')
        raise OSError(error, os.strerror(error))


class DirectoryPins:
    """Keep original directory inodes alive until install or rollback finishes."""

    def __init__(self):
        self.fds = {}
        self.file_fds = []

    def capture(self, path: Path) -> None:
        try:
            with parent_fd(path / '.anchor') as directory:
                self.fds[path] = os.dup(directory)
        except FileNotFoundError:
            self.fds[path] = None

    def fd(self, path: Path):
        return self.fds.get(path)

    def verify(self, path: Path) -> None:
        pinned = self.fds[path]
        if pinned is None:
            try:
                with parent_fd(path) as parent:
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise OSError(f'Directory appeared during installation: {path}')
        with parent_fd(path / '.anchor') as current:
            opened, named = os.fstat(pinned), os.fstat(current)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise OSError(f'Directory replaced during installation: {path}')

    def create(self, path: Path, *, mode: int = 0o700) -> None:
        if path not in self.fds:
            self.fds[path] = None
        if self.fds[path] is not None:
            self.verify(path)
            return
        with parent_fd(path) as parent:
            require_pinned_parent(path, parent, self.fds[path.parent])
            # Build under a fresh unpredictable name, pin that inode, then
            # publish it. Never open the final name to infer which directory
            # our earlier mkdir created: another process can replace it.
            staged = '.agent-harness-dir-' + secrets.token_hex(12)
            os.mkdir(staged, mode=mode, dir_fd=parent)
            directory = os.open(staged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
            try:
                named, opened = os.stat(staged, dir_fd=parent, follow_symlinks=False), os.fstat(directory)
                if ((named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                        or os.listdir(directory)):
                    raise OSError(f'New directory changed before publication: {path}')
                try:
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise OSError(f'Directory appeared during installation: {path}')
                require_pinned_parent(path, parent, self.fds[path.parent])
                try:
                    rename_directory_exclusive(parent, staged, path.name)
                except OSError as error:
                    if error.errno in (errno.EEXIST, errno.ENOTEMPTY):
                        raise DirectoryPublicationError(f'Directory appeared during installation: {path.name}') from error
                    raise
                self.fds[path] = directory
            except BaseException:
                if self.fds[path] is None:
                    try:
                        named, opened = os.stat(staged, dir_fd=parent, follow_symlinks=False), os.fstat(directory)
                        if ((named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino)
                                and not os.listdir(directory)):
                            os.rmdir(staged, dir_fd=parent)
                    except OSError:
                        pass  # An unrelated or moved directory must be left for inspection.
                    os.close(directory)
                raise
        self.verify(path)

    def close(self) -> None:
        for file_fd in self.file_fds:
            os.close(file_fd)
        for directory in self.fds.values():
            if directory is not None:
                os.close(directory)
        self.fds.clear()
        self.file_fds.clear()


def target_identity(directory: int, name: str):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


def require_target(path: Path, directory: int, expected,
                   expected_data=NO_CONTENT_CHECK, expected_mode=None) -> None:
    if expected is not NO_TARGET_CHECK and target_identity(directory, path.name) != expected:
        raise OSError(f'Managed file changed since snapshot: {path.name}')
    if expected_data is NO_CONTENT_CHECK:
        return
    if expected is None:
        if expected_data is not None:
            raise ValueError('Absent targets require an absent content expectation')
        return
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != expected:
            raise OSError(f'Managed file changed since snapshot: {path.name}')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            current = handle.read()
        after = os.fstat(fd)
        if (current != expected_data or stat.S_IMODE(after.st_mode) != expected_mode
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise OSError(f'Managed file contents or mode changed since snapshot: {path.name}')
        if target_identity(directory, path.name) != expected:
            raise OSError(f'Managed file changed since snapshot: {path.name}')
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o600, *, pinned_parent=None,
                 expected_target=NO_TARGET_CHECK, expected_data=NO_CONTENT_CHECK,
                 expected_mode=None, published=None, retain_published_fd=None):
    with parent_fd(path) as directory:
        require_pinned_parent(path, directory, pinned_parent)
        require_target(path, directory, expected_target, expected_data, expected_mode)
        temporary = ".agent-harness-" + secrets.token_hex(12)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), mode)
            written = os.fstat(fd)
            require_pinned_parent(path, directory, pinned_parent)
            require_target(path, directory, expected_target, expected_data, expected_mode)
            # Pin the inode before publication, including when a later fsync
            # fails. A closed inode number can be recycled before rollback.
            if retain_published_fd is not None:
                retain_published_fd.append(os.dup(fd))
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            identity = written.st_dev, written.st_ino
            if published is not None:
                published[path] = identity
            os.fsync(directory)
            require_pinned_parent(path, directory, pinned_parent)
            if target_identity(directory, path.name) != identity:
                raise OSError(f'Managed file changed after replacement: {path.name}')
            require_target(path, directory, identity, data, mode)
            return identity
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def safe_unlink(path: Path, *, pinned_parent=None, expected_target=NO_TARGET_CHECK,
                expected_data=NO_CONTENT_CHECK, expected_mode=None) -> None:
    opened_parent = False
    try:
        with parent_fd(path) as directory:
            opened_parent = True
            require_pinned_parent(path, directory, pinned_parent)
            require_target(path, directory, expected_target, expected_data, expected_mode)
            try:
                os.unlink(path.name, dir_fd=directory)
            except FileNotFoundError:
                pass
            require_pinned_parent(path, directory, pinned_parent)
    except FileNotFoundError:
        if opened_parent:
            raise


def read_regular(path: Path, *, pinned_parent=None, retain_fd=None):
    """Return file bytes and mode, or None if absent; never follow a late symlink/FIFO."""
    opened_parent = False
    try:
        with parent_fd(path) as directory:
            opened_parent = True
            if pinned_parent is None:
                raise OSError(f'Unexpected parent directory for {path.name}')
            require_pinned_parent(path, directory, pinned_parent)
            try:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
            except FileNotFoundError:
                return None
            with os.fdopen(fd, 'rb') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f'{path.name} must remain a regular file')
                contents = handle.read()
                require_pinned_parent(path, directory, pinned_parent)
                if retain_fd is not None:
                    retain_fd.append(os.dup(handle.fileno()))
                return contents, stat.S_IMODE(info.st_mode), (info.st_dev, info.st_ino)
    except FileNotFoundError:
        if opened_parent:
            raise
        return None


def service_commands(claude: Path) -> list[list[str]]:
    """Host services the harness runs: ahd, the deterministic monitor and scheduler (goodqa#14791). Each is
    registered through its own unit installer after the files are in place; detector-only until S2 lands."""
    return [[sys.executable, str(claude / "hooks" / "ahd.py"), "install", "--apply"]]


class ServiceError(RuntimeError):
    """A host service failed to register; the files are already installed and stay installed."""


def install_services(claude: Path, runner=None) -> list[str]:
    import subprocess  # noqa: PLC0415

    runner = runner or (lambda argv: subprocess.run(argv, stdin=subprocess.DEVNULL, check=False, timeout=120,
                                                   capture_output=True, text=True))
    done = []
    for argv in service_commands(claude):
        label = " ".join(argv[1:])
        try:
            result = runner(argv)
        except subprocess.TimeoutExpired as error:
            raise ServiceError(f"service registration timed out after {error.timeout}s: {label}; files are installed, "
                               "re-run `install.py --apply --services` or that command by hand") from error
        rc = getattr(result, "returncode", 0)
        if rc:
            tail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "")[-300:]
            raise ServiceError(f"service registration failed (exit {rc}): {label}; files are installed; {tail.strip()}")
        done.append(label)
    return done


def install(home: Path, apply: bool, durable_tmp: bool = True, provenance: bool = True,
            command_guard: bool = True, log_backup=None, services: bool = False) -> list[str]:
    claude = home.expanduser().resolve() / ".claude"
    if log_backup is None:
        log_backup = log_backup_alert(home, None)
    files = [
        *((ROOT / "harness" / folder / name, claude / folder / name)
          for folder, names in (("agents", AGENTS), ("hooks", HOOKS), ("tools", TOOLS), ("skills", SKILLS))
          for name in names),
    ]
    managed = [destination for _, destination in files] + [claude / "CLAUDE.md", claude / "settings.json"]
    directories = {claude, claude / "agent-harness-backups", *(path.parent for path in managed)}
    if any(path.is_symlink() for path in [*managed, *directories]):
        raise ValueError("Refusing a symlinked destination or directory; inspect the user directory first")
    if any(path.exists() and not path.is_file() for path in managed):
        raise ValueError("Each managed destination must be a regular file")
    if any(path.exists() and not path.is_dir() for path in directories):
        raise ValueError("Each managed directory must be a directory")
    backup_root = claude / "agent-harness-backups"
    pins = DirectoryPins()
    try:
        for directory in (claude.parent, claude, claude / 'agents', claude / 'hooks',
                          claude / 'tools', claude / 'skills', claude / 'skills' / 'check-dropped-workstreams', backup_root):
            pins.capture(directory)
        instructions_path = claude / "CLAUDE.md"
        existing_instructions = read_regular(instructions_path, pinned_parent=pins.fd(claude),
                                             retain_fd=pins.file_fds)
        current_text = existing_instructions[0].decode() if existing_instructions else ""
        instructions = merged_instructions(current_text, (ROOT / "HARNESS.md").read_text())
        settings_path = claude / "settings.json"
        existing_settings = read_regular(settings_path, pinned_parent=pins.fd(claude),
                                         retain_fd=pins.file_fds)
        current_settings = json.loads(existing_settings[0].decode()) if existing_settings else {}
        if not isinstance(current_settings, dict):
            raise ValueError("settings.json must contain an object")
        settings = merged_settings(current_settings, claude, durable_tmp, provenance, command_guard, log_backup)
        # Read every payload before any managed write (also validate it in preview).
        payloads = [(destination, source.read_bytes()) for source, destination in files]
        payloads += [(instructions_path, instructions.encode()),
                     (settings_path, (json.dumps(settings, indent=2) + "\n").encode())]
        changes = [str(path) for path in managed]
        if not apply:
            if services:  # preview: name the service commands a real --apply --services run would execute
                changes.extend("would run service: " + " ".join(argv[1:]) for argv in service_commands(claude))
            return changes
        for note in migrate_local_profiles(claude):
            print(f"  {note}")
        originals = {path: read_regular(path, pinned_parent=pins.fd(path.parent),
                                        retain_fd=pins.file_fds)
                     for path in managed}
        if originals[instructions_path] != existing_instructions or originals[settings_path] != existing_settings:
            raise OSError('User settings or instructions changed during installation preflight; retry')
        # Exclusive creation rejects a real directory that appears after snapshot.
        for directory in (claude, claude / 'agents', claude / 'hooks', claude / 'tools',
                          claude / 'skills', claude / 'skills' / 'check-dropped-workstreams', backup_root):
            pins.create(directory)
        os.fchmod(pins.fd(backup_root), 0o700)  # backups can include env values
        pins.verify(backup_root)
        backups = backup_root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                                 + '-' + secrets.token_hex(4))
        pins.create(backups)
        os.fchmod(pins.fd(backups), 0o700)
        pins.verify(backups)
        for path in managed:
            if originals[path] is not None:
                saved = backups / path.relative_to(claude)
                if saved.parent != backups:  # create each level under the backup root (skills/<name>/ is two deep)
                    rel = saved.parent.relative_to(backups)
                    for i in range(1, len(rel.parts) + 1):
                        pins.create(backups.joinpath(*rel.parts[:i]))
                atomic_write(saved, originals[path][0], pinned_parent=pins.fd(saved.parent),
                             expected_target=None)
        installed = {}
        payload_by_path = dict(payloads)
        try:
            for destination, data in payloads:
                original = originals[destination]
                expected = original[2] if original else None
                installed[destination] = atomic_write(destination, data,
                                                       pinned_parent=pins.fd(destination.parent),
                                                       expected_target=expected,
                                                       expected_data=original[0] if original else None,
                                                       expected_mode=original[1] if original else None,
                                                       published=installed,
                                                       retain_published_fd=pins.file_fds)
        except BaseException as error:
            failures = []
            for path in reversed(installed):
                try:
                    original = originals[path]
                    expected = installed[path]
                    if original is None:
                        safe_unlink(path, pinned_parent=pins.fd(path.parent), expected_target=expected,
                                    expected_data=payload_by_path[path], expected_mode=0o600)
                    else:
                        atomic_write(path, original[0], original[1], pinned_parent=pins.fd(path.parent),
                                     expected_target=expected, expected_data=payload_by_path[path],
                                     expected_mode=0o600)
                except OSError:
                    failures.append(str(path.relative_to(claude)))
            if failures:
                raise RuntimeError(f"Installation failed; rollback incomplete for {', '.join(failures)}; "
                                   f"restore from {backups}") from error
            raise
        if services and not apply:
            changes.extend("would run service: " + " ".join(argv[1:]) for argv in service_commands(claude))
        if apply and services:  # host services last, after every file is in place (goodqa#14791 S1d)
            changes.extend("service: " + c for c in install_services(claude))
        return changes
    finally:
        pins.close()


def _private_harness_dir(home: Path) -> int:
    """Open (creating 0700) ~/.agent-harness without following symlinks; caller closes the fd."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(home, flags)
    try:
        try:
            os.mkdir(".agent-harness", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        return os.open(".agent-harness", flags, dir_fd=parent)
    finally:
        os.close(parent)


def durable_tmp_choice(home: Path, flag) -> bool:
    """--durable-tmp/--no-durable-tmp win; otherwise the saved choice; otherwise on."""
    if flag is not None:
        return flag
    try:
        state = json.loads((home.expanduser().resolve() / ".agent-harness" / INSTALL_STATE).read_text())
        return not (isinstance(state, dict) and state.get("durable_tmp") is False)
    except (OSError, ValueError):
        return True


def save_durable_tmp_choice(home: Path, value: bool) -> None:
    directory = _private_harness_dir(home.expanduser().resolve())
    try:
        temporary = f".{INSTALL_STATE}.{secrets.token_hex(4)}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "w") as handle:
            json.dump({"schema": 1, "durable_tmp": value}, handle)
            handle.write("\n")
        os.replace(temporary, INSTALL_STATE, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        os.close(directory)


def scratch_status(home: Path, apply: bool, durable_tmp: bool = True, run=None) -> str:
    """Create the durable scratch root (0700) when settings point at it; exclude it from Time Machine."""
    import subprocess
    home = home.expanduser().resolve()
    claude = home / ".claude"
    scratch = durable_scratch(claude)
    try:
        settings = json.loads((claude / "settings.json").read_text()) if apply else {}
    except (OSError, ValueError):
        settings = {}
    configured = (settings.get("env") or {}).get(TMPDIR_KEY) if isinstance(settings, dict) else None
    if not apply:
        if not durable_tmp:
            return f"durable scratch: off; would remove {TMPDIR_KEY} only if it is the harness value {scratch}"
        return f"durable scratch: would use {scratch} as {TMPDIR_KEY} unless one is already set"
    if not configured and os.environ.get(TMPDIR_KEY) not in (None, "", str(scratch)):
        return (f"durable scratch: {TMPDIR_KEY} is exported in the shell ({os.environ[TMPDIR_KEY]!r}); "
                "settings left unchanged")
    if configured != str(scratch):
        return (f"durable scratch: {TMPDIR_KEY} is {configured!r}, not managed by the harness; left unchanged"
                if configured else f"durable scratch: {TMPDIR_KEY} not set; scratchpad stays in system temp")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fds = []
    try:
        fds.append(_private_harness_dir(home))
        try:
            os.mkdir("scratch", 0o700, dir_fd=fds[-1])
        except FileExistsError:
            pass
        fds.append(os.open("scratch", flags, dir_fd=fds[-1]))
        os.fchmod(fds[-1], 0o700)
        # Keep Spotlight from indexing task output, which can contain command output.
        os.close(os.open(".metadata_never_index", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600,
                         dir_fd=fds[-1]))
    except OSError as error:
        return f"durable scratch: could not prepare {scratch} ({error.__class__.__name__}); inspect it"
    finally:
        for fd in reversed(fds):
            os.close(fd)
    status = f"durable scratch: {TMPDIR_KEY}={scratch} (0700); restart running sessions to use it"
    if len(str(scratch / "cc-socks" / "999999.sock").encode()) > MAX_SOCKET_PATH:
        status += ("; WARNING: socket paths under this root exceed the macOS limit, "
                   "rerun with --no-durable-tmp or set a shorter CLAUDE_CODE_TMPDIR")
    if sys.platform == "darwin":
        run = run or subprocess.run
        try:
            result = run(["tmutil", "addexclusion", str(scratch)], capture_output=True, text=True, timeout=10)
            status += "; Time Machine exclusion " + ("set" if result.returncode == 0 else
                                                      f"not set (tmutil exit {result.returncode})")
        except (OSError, subprocess.SubprocessError):
            status += "; Time Machine exclusion not set (tmutil unavailable)"
    return status


def install_git_backstop(home: Path, apply: bool) -> str:
    """Run after the file transaction: the hook command exits 0 if its script is missing."""
    home = home.expanduser().resolve()
    return git_hook_status(home, GIT_HOOK_KEY, home / ".claude" / "hooks" / "commit_policy.py", apply=apply)


def netwatch_status(home: Path, apply: bool, flag) -> str:
    """Optional monitor; never fails the harness install.

    With a non-default --home (tests, staging a home) netwatch is skipped
    unless --netwatch is passed, so installer tests never download it."""
    try:
        import netwatch_install
        home = home.expanduser().resolve()
        if home != netwatch_install.real_home() and flag is None:
            return "netwatch: skipped (non-default --home; pass --netwatch to place the binary)"
        enabled = netwatch_install.choice(home, flag)
        if apply and flag is not None:
            try:
                netwatch_install.save_choice(home, enabled)
            except OSError as error:
                return f"netwatch: could not save the choice ({error.__class__.__name__}); nothing changed"
        return netwatch_install.status(home, apply, enabled)
    except Exception as error:  # noqa: BLE001
        return f"netwatch: skipped ({error.__class__.__name__}: {error})"


def migrate_local_profiles(claude: Path, policy_dir: Path | None = None) -> list[str]:
    """Before the shipped policies are overwritten, copy their personal values into new untracked 0600 profiles.
    Never overwrites an existing profile. Without this an upgrade would silently turn ticket enforcement off."""
    notes = []
    hooks = policy_dir if policy_dir is not None else claude / "hooks"  # Codex keeps its policies in ~/.codex/agent-harness
    def keep(name, build):
        old, target = hooks / name, hooks / name.replace(".json", ".local.json")
        if target.exists() or target.is_symlink() or not old.is_file():
            return
        try:
            data = build(json.loads(old.read_text(encoding="utf-8")))
        except (OSError, ValueError, AttributeError):
            return
        if data:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            notes.append(f"migrated personal values from {name} to {target.name} (mode 0600)")
    def commit(policy):
        out = {}
        if policy.get("backstop_repos"):
            out["backstop_repos"] = policy["backstop_repos"]
        keys = ("repos", "org_id", "key_file", "key_secret", "default_project", "projects", "unreachable_projects", "unreachable_reason")
        systems = {n: {k: v for k, v in e.items() if k in keys and v not in ([], {}, "", None)}
                   for n, e in (policy.get("ticket_systems") or {}).items() if isinstance(e, dict)}
        for e in systems.values():  # the loader accepts only these route keys; an old extra key would break commits
            if isinstance(e.get("projects"), dict):
                e["projects"] = {s: {k: v for k, v in r.items() if k in ("project_id", "org_id", "key_file")}
                                 for s, r in e["projects"].items() if isinstance(r, dict)}
        systems = {n: e for n, e in systems.items() if e.get("repos") or e.get("org_id")}
        if systems:
            out["ticket_systems"] = systems
        return out
    def spec(policy):
        out = {k: policy[k] for k in ("projects", "enforced_projects") if policy.get(k)}
        if isinstance(out.get("projects"), dict):
            out["projects"] = {s: {k: v for k, v in r.items() if k in ("project_id", "org_id", "key_file")}
                               for s, r in out["projects"].items() if isinstance(r, dict)}
        return out
    keep("commit_policy.json", commit)
    keep("spec_policy.json", spec)
    return notes


def local_profile_status(home: Path, policy_dir: Path | None = None) -> str:
    """The shipped policy is generic, so a host without commit_policy.local.json has ticket enforcement off."""
    hooks = policy_dir if policy_dir is not None else home.expanduser() / ".claude" / "hooks"
    missing = [name for name in ("commit_policy.local.json", "spec_policy.local.json") if not (hooks / name).is_file()]
    if not missing:
        return f"policy profiles: commit_policy.local.json and spec_policy.local.json present in {hooks}"
    return ("policy profiles: MISSING " + ", ".join(missing) + " -- ticket enforcement, the git backstop and spec "
            "project routing match nothing until you copy each .example beside the installed hooks and fill it in")


def command_guard_status(enabled: bool, runner=None) -> str:
    """Claude Code before 2.1.295 ignores onFailure, so fail-closed then rests on the launcher alone."""
    if not enabled:
        return "command guard: not registered (--no-command-guard)"
    import subprocess
    try:
        out = runner() if runner else subprocess.run(["claude", "--version"], capture_output=True, text=True,
                                                     timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    found = re.search(r"(\d+)\.(\d+)\.(\d+)", out or "")
    version = tuple(int(x) for x in found.groups()) if found else None
    if version is None:
        return "command guard: registered; Claude Code version unknown, fail-closed rests on the launcher"
    if version < (2, 1, 295):
        return ("command guard: registered; WARNING Claude Code %s predates onFailure (2.1.295), fail-closed "
                "rests on the launcher alone" % ".".join(map(str, version)))
    return "command guard: registered with onFailure block"


def log_backup_enabled(home: Path, flag) -> bool:
    """--log-backup/--no-log-backup, else the remembered choice, else on only where the component is installed."""
    try:
        import log_backup_install
        return log_backup_install.choice(home, flag)
    except Exception:  # noqa: BLE001
        return False


def log_backup_alert(home: Path, flag) -> bool:
    """The SessionStart alert stays registered wherever the component is installed, even after --no-log-backup: a
    backup that was switched off on purpose is still a host whose logs are not being backed up, and the alert says so."""
    try:
        import log_backup_install
        return log_backup_install.choice(home, flag) or log_backup_install.component_installed(home.expanduser().resolve())
    except Exception:  # noqa: BLE001
        return False


def log_backup_status(home: Path, apply: bool, flag=None) -> str:
    """Scheduled log backup (script, excludes, launchd or systemd units); never fails the harness install."""
    try:
        import log_backup_install
        enabled = log_backup_install.choice(home, flag)
        if apply and flag is not None:
            log_backup_install.save_choice(home.expanduser().resolve(), flag)
        return log_backup_install.status(home, apply, enabled=enabled)
    except Exception as error:  # noqa: BLE001
        return f"log backup: skipped ({error.__class__.__name__}: {error})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write changes; otherwise only preview paths")
    parser.add_argument("--services", action="store_true",
                        help="also register the host services (the ahd launchd/systemd job) after the files are installed")
    parser.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--no-durable-tmp", dest="durable_tmp", action="store_false", default=None,
                        help=f"stop setting {TMPDIR_KEY} (remembered); remove it if it is the harness value")
    choice.add_argument("--durable-tmp", dest="durable_tmp", action="store_true",
                        help=f"set {TMPDIR_KEY} to ~/.agent-harness/scratch when unset (the default; remembered)")
    netwatch = parser.add_mutually_exclusive_group()
    netwatch.add_argument("--no-netwatch", dest="netwatch", action="store_false", default=None,
                          help="do not install or upgrade the netwatch monitor (remembered)")
    netwatch.add_argument("--netwatch", dest="netwatch", action="store_true",
                          help="install or upgrade the pinned netwatch monitor (the default; remembered)")
    parser.add_argument("--no-provenance-hooks", dest="provenance", action="store_false",
                        help="do not register the provenance hooks (ask-gate, stop-lint, prompt) and remove any "
                             "registered by an earlier install; the files stay installed; not remembered")
    parser.add_argument("--no-command-guard", dest="command_guard", action="store_false",
                        help="do not register the destructive/config-dump command guard and remove an earlier "
                             "registration (rollback); the files stay installed; not remembered")
    backup = parser.add_mutually_exclusive_group()
    backup.add_argument("--log-backup", dest="log_backup", action="store_true", default=None,
                        help="install the scheduled Dropbox log backup (script, units, SessionStart alert) and "
                             "remember the choice; plaintext uploads until encryption lands (GoodQA #14522)")
    backup.add_argument("--no-log-backup", dest="log_backup", action="store_false",
                        help="remember not to install it; where installed, stop its scheduler job (files and "
                             "remote copies stay; see docs/operations.md, Agent log backup, for rollback)")
    args = parser.parse_args()
    durable_tmp = durable_tmp_choice(args.home, args.durable_tmp)
    if args.apply and args.durable_tmp is not None:
        # Save the choice first, so a later failure cannot let a plain reinstall undo an opt-out.
        try:
            save_durable_tmp_choice(args.home, durable_tmp)
        except OSError as error:
            parser.exit(1, f"Install failed: could not save the durable-tmp choice under "
                           f"{args.home / '.agent-harness'} ({error.__class__.__name__}); it must be a "
                           "real directory, not a symlink\n")
    try:
        changes = install(args.home, args.apply, durable_tmp=durable_tmp, provenance=args.provenance,
                          command_guard=args.command_guard, log_backup=log_backup_alert(args.home, args.log_backup),
                          services=args.services)
    except DirectoryPublicationError as error:
        parser.exit(1, f'Install failed: {error}\n')
    action = "Installed" if args.apply else "Would install"
    print(f"{action} Agent Harness in {args.home.expanduser() / '.claude'}")
    for path in changes:
        print(f"  {path}")
    print(f"  {install_git_backstop(args.home, args.apply)}")
    print(f"  {scratch_status(args.home, args.apply, durable_tmp)}")
    print(f"  {netwatch_status(args.home, args.apply, args.netwatch)}")
    print(f"  {local_profile_status(args.home)}")
    print(f"  {command_guard_status(args.command_guard)}")
    print(f"  {log_backup_status(args.home, args.apply, args.log_backup)}")
    if not args.apply:
        print("Run with --apply to install. Existing files will be backed up.")


if __name__ == "__main__":
    main()
