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
# Shipped beside the hooks (tests/test_shipped_modules.py checks it both ways: every import of a shipped module ships,
# and every shipped module is reachable from ENTRY_POINTS; every data file is named by a shipped module or script).
ENTRY_POINTS = (
    # the registered hooks (managed_hooks) and the launcher every one runs through
    "ah_hook.py", "session_env.py", "wal.py", "owner_inbox.py", "autosave.py", "dropped_gate.py", "prod_delete_guard.py",
    # ah and the modules it dispatches to
    "ah.py", "ah_switch.py", "ah_secret.py", "ah_approvals.py", "ah_log_push.py", "ah_reap.py", "successor.py",
    "ah_chat.py", "ah_chat_send.py", "ah_ticket.py", "ah_export.py", "ah_kill.py", "ah_worktree.py",
    "ah_sandbox.py", "ah_doctor.py", "ah_repo.py",
    # tools agents, jobs and the owner run by name
    "peer_review.py", "rescue.py", "kimi_review.py", "deliver.py", "publish_feature.py", "integrate_local.py",
    "wal_note.py", "workdir.py", "task_recovery.py", "bg_job.py", "log_backup.py", "backup_watch.py", "ops_watch.py",
    "gq_browser.py", "installer_scan.py", "git_save.py", "native_admission.py", "native_user_source.py")
DATA_FILES = ("sandbox_base.json", "review_policy.json", "model_tiers.json", "domain_checklists.json",
              "node_check_reporter.mjs", "dropbox_budget.conf",
              # read by modules peer_review.py still imports until the gate branch drops them (commit_policy, spec_flow,
              # provenance, resource_budget); they go with those modules
              "commit_policy.json", "spec_policy.json", "spec_template.md", "provenance_policy.json", "resource_limits.json")
HOOKS = ENTRY_POINTS + (
    # imported by the entry points (the closure)
    "ah_local.py", "ah_roles.py", "caller_identity.py", "domain_gates.py", "git_safety.py", "github_identity.py",
    "liveness.py", "mc_chat.py", "model_tiers.py", "native_context.py", "native_main.py", "process.py", "redact.py",
    "report_file.py", "review_diagnostics.py", "safe_input.py", "ticket_adapters.py", "trivy_gate.py", "usage_guard.py",
    # imported only by peer_review.py, rescue.py or ah.py's transcript reader today; the kill list, kept until the gate
    # branch (and for provenance, a move of ah's transcript reader) removes the last importer
    "commit_policy.py", "escalation.py", "merge_gate.py", "provenance.py", "resource_budget.py", "spec_flow.py",
) + DATA_FILES
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


def record_gate_epoch(home: Path, prior_mtime=None, now=None) -> bool:
    """Write ~/.agent-harness/state/dropped-gate/installed_at.json once: the earlier of now and an already-installed
    gate's mtime. Never rewritten, so a later install cannot move it (ah also pins the earliest epoch it used)."""
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    at = min(now, prior_mtime) if prior_mtime else now
    root = home / ".agent-harness"
    d = root / "state" / "dropped-gate"
    try:
        for p in (root, root / "state", d):
            if p.is_symlink():
                return False
        # mkdir(parents=True) would leave the new parents at the umask default (0755);
        # every other creator of ~/.agent-harness uses the private mode.
        for parent in (root, root / "state"):
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
        d.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(d / "installed_at.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        return False
    try:
        stamp = datetime.fromtimestamp(at, timezone.utc).isoformat()
        os.write(fd, (json.dumps({"at": stamp, "by": "install.py"}) + "\n").encode())
    finally:
        os.close(fd)
    return True


def managed_scripts(claude: Path) -> set[str]:
    """Every script any release of install.py ever registered: an upgrade strips their old handlers, user hooks stay."""
    return {str(claude / "hooks" / name)
            for name in ("wal.py", "commit_policy.py", "spec_flow.py", "provenance_hooks.py", "heavy_job_guard.py", "agent_gate.py",
                         "command_guard_hook.py", "kill_guard.py", "tier_gate.py", "merge_gate.py", "ledger_reminder.py", "log_backup.py", "bg_lint.py",
                         "dropped_gate.py", "prod_delete_guard.py", "wal_cadence.py", "worktree_hygiene.py",
                         "mc_inbox.py", "owner_inbox.py", "mission_gate.py", "status_truth.py", "idle_guard.py", "copy_hygiene.py",
                         "session_env.py", "autosave.py")}


# Every agent type: a narrower matcher left general-purpose, claude and Explore owners without any
# SubagentStart/Stop WAL record, so no liveness check could see them stop (goodqa#14613, the Solve drop).
SUBAGENT_MATCHER = ".*"
# Must equal prod_delete_guard.MATCHER (tests/test_prod_delete_guard.py pins it): the named database tools only. No Bash:
# a Bash call starts no harness hook (docs/direction.md).
PROD_DELETE_MATCHER = r".*d1_database_query|mcp__.*__(execute_sql|run_sql|query|sql)|mcp__.*__hyperdrive_.*"
REMOVED_IN = 1001  # the release that removed the guards, gates, services and flags below (docs/direction.md)


def prod_delete_matcher() -> str:
    """PROD_DELETE_MATCHER plus the extra database tools of ~/.agent-harness/local.json (db_tool_patterns)."""
    sys.path.insert(0, str(ROOT / "harness" / "hooks"))
    try:
        import prod_delete_guard  # noqa: PLC0415
        return prod_delete_guard.matcher()
    except Exception:  # noqa: BLE001
        return PROD_DELETE_MATCHER
    finally:
        sys.path.remove(str(ROOT / "harness" / "hooks"))


def managed_hooks(claude: Path) -> dict[str, list[dict]]:
    """The ten registrations of release 1001 (docs/harness-reference.md, "Hooks"). None matches Bash, none sets
    onFailure, and every one runs through ah_hook.py, so `harness off` silences it. Each exits 0 on its own errors.

    The three that would bring this to seven are `wal.py subagent`, `wal.py subagent_stop` and `dropped_gate.py`
    (cost: `ah owners` cannot see sub-agents and the turn-end handoff nudge becomes a standing rule); that choice is
    the owner's."""
    hooks = claude / "hooks"

    def handler(script: str, *args: str, timeout: int) -> dict:
        return {"type": "command", "command": "python3", "args": [str(hooks / script), *args], "timeout": timeout}

    # autosave (docs/lifecycle.md) saves what the session's checkouts hold nowhere else (own budget 20 s). On Stop and
    # SubagentStop it runs in the background ("async", Claude Code 2.1.332+), so a turn never waits for a push; on
    # SessionEnd it stays synchronous, so the last save finishes before the session goes.
    autosave = handler("autosave.py", timeout=30)
    managed = {
        # session_env makes the session folder, exports AH_SESSION, AH_WORK and TMPDIR and prints one line
        "SessionStart": [{"hooks": [handler("session_env.py", timeout=10)]},
                         # the per-session note log and its one start line
                         {"hooks": [handler("wal.py", "session", timeout=10)]}],
        # the sub-agent note log, and its stop: `ah owners` sees owners start and stop
        "SubagentStart": [{"matcher": SUBAGENT_MATCHER, "hooks": [handler("wal.py", "subagent", timeout=10)]}],
        "SubagentStop": [{"matcher": SUBAGENT_MATCHER, "hooks": [handler("wal.py", "subagent_stop", timeout=10)]},
                         {"matcher": SUBAGENT_MATCHER, "hooks": [dict(autosave, **{"async": True})]}],
        # the file inbox for the owner's answers (OWNER-DECISION-*.md and inbox/ notes)
        "UserPromptSubmit": [{"hooks": [handler("owner_inbox.py", "hook", timeout=5)]}],
        # the save, and the one turn-end handoff nudge, once per set of owners that stopped without a handoff
        "Stop": [{"hooks": [dict(autosave, **{"async": True})]},
                 {"hooks": [handler("dropped_gate.py", timeout=15)]}],
        "SessionEnd": [{"hooks": [dict(autosave)]}],
        # the named database tool check stays until production credentials are scoped (docs/direction.md)
        "PreToolUse": [{"matcher": prod_delete_matcher(), "hooks": [handler("prod_delete_guard.py", timeout=30)]}],
    }
    return through_launcher(managed, claude)


LAUNCHER = "ah_hook.py"  # harness/hooks/ah_hook.py: exits 0 at once while ~/.agent-harness/OFF exists


def through_launcher(managed: dict[str, list[dict]], claude: Path) -> dict[str, list[dict]]:
    """Every managed handler `python3 <hooks>/<script> [args]` becomes `python3 <hooks>/ah_hook.py <script> [args]`,
    so `harness off` silences running sessions too (they read the command at start; the launcher reads the flag on
    every call). Everything else in the handler (timeout, onFailure) stays."""
    hooks_dir = str(claude / "hooks")
    launcher = str(claude / "hooks" / LAUNCHER)
    managed = json.loads(json.dumps(managed))  # some handler dicts are shared between events: wrap each copy once
    for groups in managed.values():
        for group in groups:
            for handler in group["hooks"]:
                args = handler.get("args") or []
                if (handler.get("command") == "python3" and args and os.path.dirname(args[0]) == hooks_dir
                        and os.path.basename(args[0]) != LAUNCHER):
                    handler["args"] = [launcher, os.path.basename(args[0]), *args[1:]]
    return managed


def hook_argv(hook: dict) -> list[str]:
    """[script path, *args] of a Claude handler whether it is wired directly or through the launcher; for tests and
    tools that ask "which script does this run" (the launcher form names the script beside ah_hook.py)."""
    args = [str(a) for a in hook.get("args") or []]
    if len(args) > 1 and os.path.basename(args[0]) == LAUNCHER:
        return [os.path.join(os.path.dirname(args[0]), args[1]), *args[2:]]
    return args


def is_managed_handler(hook: dict, claude: Path, scripts: set[str] | None = None) -> bool:
    """A handler install.py owns: the direct form old installers wrote (`python3 <hooks>/<script>`) or the launcher
    form (`python3 <hooks>/ah_hook.py <script>`), for the scripts in managed_scripts()."""
    scripts = managed_scripts(claude) if scripts is None else scripts
    if hook.get("type") != "command" or hook.get("command") != "python3":
        return False
    args = hook.get("args") or [None]
    if args[0] in scripts:
        return True
    return (args[0] == str(claude / "hooks" / LAUNCHER) and len(args) > 1
            and str(claude / "hooks" / str(args[1])) in scripts)


def durable_scratch(claude: Path) -> Path:
    """Reboot-surviving home for Claude Code's temp dir (scratchpad, task output)."""
    return claude.parent / ".agent-harness" / "scratch"


# Allow rules earlier releases wrote for scripts release 1001 removed: an upgrade takes exactly these out; a rule the
# user wrote, even a similar one, stays.
RETIRED_ALLOW_RULES = tuple(
    [f"Bash(python3 ~/.claude/hooks/commit_policy.py {a} *)" for a in ("check-message", "check-range", "report")]
    + [f"Bash(python3 ~/.claude/hooks/merge_gate.py {a} *)" for a in ("check", "report")]
    + [f"Bash(python3 ~/.claude/hooks/spec_flow.py {a} *)" for a in ("lint", "status")]
    + [f"Bash(python3 ~/.claude/hooks/resource_budget.py {a} *)" for a in ("check", "capacity")])


def merged_settings(current: dict, claude: Path, durable_tmp: bool = True) -> dict:
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
    if not isinstance(hooks, dict):
        raise ValueError("settings.json hooks must be an object")
    scripts = managed_scripts(claude)
    wanted = managed_hooks(claude)
    for event in sorted(set(wanted) | set(hooks)):  # every event: a retired handler may sit on any of them
        managed = wanted.get(event, [])
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"settings.json hooks.{event} must be a list")
        had_entries = bool(entries)
        preserved = []
        for item in entries:
            if not isinstance(item, dict) or not isinstance(item.get("hooks", []), list) \
                    or not all(isinstance(hook, dict) for hook in item.get("hooks", [])):
                raise ValueError(f"settings.json hooks.{event} has an invalid hook group")
            remaining = [hook for hook in item.get("hooks", []) if not is_managed_handler(hook, claude, scripts)]
            if remaining == item.get("hooks", []):
                preserved.append(item)
            elif remaining:
                preserved.append({**item, "hooks": remaining})
        entries[:] = preserved
        entries.extend(managed)
        if not entries and had_entries:
            del hooks[event]  # an uninstalled gate leaves no empty event behind; a user's own empty list stays
    permissions = settings.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise ValueError("settings.json permissions must be an object")
    allowed = permissions.setdefault("allow", [])
    if not isinstance(allowed, list):
        raise ValueError("settings.json permissions.allow must be a list")
    allowed[:] = [rule for rule in allowed if rule not in RETIRED_ALLOW_RULES]
    for name in ("wal_note.py", "publish_feature.py", "integrate_local.py", "deliver.py"):
        rule = f"Bash(python3 ~/.claude/hooks/{name} *)"
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
    rule = "Bash(python3 ~/.claude/hooks/ah_switch.py status*)"  # read-only; off/on are the user's to run
    if rule not in allowed:
        allowed.append(rule)
    return settings


def remove_git_backstop(home: Path, key: str, apply: bool, git: str = "git") -> str:
    """Unset the commit-msg backstop keys earlier releases registered (hook.<key>.event and .command in ~/.gitconfig).
    Only those two keys; everything else in the file stays. Release 1001 checks commit messages nowhere."""
    import subprocess  # noqa: PLC0415
    gitconfig = home.expanduser().resolve() / ".gitconfig"
    if not gitconfig.is_file():
        return "commit-msg backstop: not registered"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["HOME"] = str(home)
    config = ["--file", str(gitconfig)]
    names = []
    try:
        for name in ("event", "command"):
            found = subprocess.run([git, "config", *config, "--get-all", f"hook.{key}.{name}"],
                                   capture_output=True, text=True, env=env, timeout=10)
            if found.returncode == 0 and found.stdout.strip():
                names.append(name)
        if not names:
            return "commit-msg backstop: not registered"
        if not apply:
            return f"commit-msg backstop: would unset hook.{key} in {gitconfig}"
        for name in names:
            subprocess.run([git, "config", *config, "--unset-all", f"hook.{key}.{name}"],
                           capture_output=True, env=env, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        return f"commit-msg backstop: could not unset hook.{key} ({error.__class__.__name__}); remove it by hand"
    return f"commit-msg backstop: unset hook.{key} in {gitconfig} (removed in release {REMOVED_IN})"


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


class DowngradeRefused(ValueError):
    """This checkout's harness/RELEASE is below the host's floor (~/.agent-harness/floor.json)."""


def switch_module():
    """harness/hooks/ah_switch.py from this checkout: the off flag, the stash and the release floor."""
    hooks = str(ROOT / "harness" / "hooks")
    if hooks not in sys.path:
        sys.path.insert(0, hooks)
    import ah_switch  # noqa: PLC0415
    return ah_switch


def instruction_block(text: str) -> str:
    return f"{START}\n{text.rstrip()}\n{END}\n"


def install(home: Path, apply: bool, durable_tmp: bool = True, hooks_only: bool = False,
            allow_downgrade: bool = False, release: int | None = None) -> list[str]:
    """hooks_only: install the hook, agent, tool and skill files only; CLAUDE.md and settings.json are never read or
    written (their review happens separately). The per-file backups are kept.

    Refuses (DowngradeRefused) a release below the host's floor unless allow_downgrade. While the harness is OFF
    (~/.agent-harness/OFF) the files and wiring are installed but the instruction block goes to the off stash, not
    into CLAUDE.md. A successful --apply records the release and commit in install state, snapshots the installed
    files and wiring to ~/.agent-harness/releases/<release>/claude and moves the floor to this release."""
    claude = home.expanduser().resolve() / ".claude"
    switch = switch_module()
    release = switch.read_release(ROOT) if release is None else release
    refusal = switch.downgrade_refusal(claude.parent, "claude", release, allow_downgrade)
    if refusal:
        raise DowngradeRefused(refusal)
    off = switch.is_off(claude.parent)
    stash_record = None
    files = [
        *((ROOT / "harness" / folder / name, claude / folder / name)
          for folder, names in (("agents", AGENTS), ("hooks", HOOKS), ("tools", TOOLS), ("skills", SKILLS))
          for name in names),
    ]
    user_files = [] if hooks_only else [claude / "CLAUDE.md", claude / "settings.json"]
    managed = [destination for _, destination in files] + user_files
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
        settings_path = claude / "settings.json"
        # Read every payload before any managed write (also validate it in preview).
        payloads = [(destination, source.read_bytes()) for source, destination in files]
        existing_instructions = existing_settings = None
        if not hooks_only:
            existing_instructions = read_regular(instructions_path, pinned_parent=pins.fd(claude),
                                                 retain_fd=pins.file_fds)
            current_text = existing_instructions[0].decode() if existing_instructions else ""
            harness_text = (ROOT / "HARNESS.md").read_text()
            if off:  # installed files and wiring, but the rules wait in the off stash until `harness on`
                instructions, stash_record = switch.plan_stash(claude.parent, "claude", current_text,
                                                               block=instruction_block(harness_text))
            else:
                instructions = merged_instructions(current_text, harness_text)
            existing_settings = read_regular(settings_path, pinned_parent=pins.fd(claude),
                                             retain_fd=pins.file_fds)
            current_settings = json.loads(existing_settings[0].decode()) if existing_settings else {}
            if not isinstance(current_settings, dict):
                raise ValueError("settings.json must contain an object")
            settings = merged_settings(current_settings, claude, durable_tmp)
            payloads += [(instructions_path, instructions.encode()),
                         (settings_path, (json.dumps(settings, indent=2) + "\n").encode())]
        changes = [str(path) for path in managed]
        if not apply:
            return changes
        switch.mark_pending(claude.parent, "claude", release)  # the floor watcher leaves a running install alone
        originals = {path: read_regular(path, pinned_parent=pins.fd(path.parent),
                                        retain_fd=pins.file_fds)
                     for path in managed}
        if not hooks_only and (originals[instructions_path] != existing_instructions
                               or originals[settings_path] != existing_settings):
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
        gate_file = claude / "hooks" / "dropped_gate.py"
        try:  # the earlier of now and the gate already installed here: the epoch legacy is measured against
            prior_gate = os.lstat(gate_file).st_mtime if gate_file.is_file() and not gate_file.is_symlink() else None
        except OSError:
            prior_gate = None
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
            with contextlib.suppress(OSError):
                switch.clear_pending(claude.parent, "claude")
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
        if record_gate_epoch(claude.parent, prior_gate):
            changes.append("recorded the dropped-owner gate install time")
        if stash_record is not None:
            switch.save_stash(claude.parent, "claude", stash_record)
            changes.append("harness is OFF: the instruction block is kept in ~/.agent-harness/off-stash until `harness on`")
        changes.append(record_release(claude, switch, release, [d for _, d in files], hooks_only, backups.name))
        return changes
    finally:
        pins.close()


def record_release(claude: Path, switch, release: int, files: list[Path], hooks_only: bool, backup: str) -> str:
    """Install state, the floor snapshot (installed files, managed hook groups, instruction block) and the floor.
    --hooks-only never reads settings.json, so it carries the wiring of the newest earlier snapshot forward."""
    home = claude.parent
    if hooks_only:
        prior = switch.latest_snapshot(home, "claude") or {}
        settings_spec, instructions_spec = prior.get("settings"), prior.get("instructions")
    else:
        settings_spec = {"path": ".claude/settings.json", "hooks_dir": str(claude / "hooks"),
                         "names": sorted(Path(p).name for p in managed_scripts(claude)),
                         "groups": managed_hooks(claude)}
        instructions_spec = {"block": instruction_block((ROOT / "HARNESS.md").read_text())}
    commit = switch.source_commit(ROOT)
    switch.record_install(home, "claude", release, commit, files, settings_spec, instructions_spec, backup)
    return f"release {release} ({commit[:12]}) recorded; floor snapshot in {home / '.agent-harness' / 'releases' / str(release)}"


def floor_watch_status(home: Path, apply: bool, run=None, system=None) -> str:
    """The floor watcher of releases before 1001 rewrote settings.json on every change; it is no longer installed.
    On the real home an --apply stops and deletes an old one, once. A non-default --home is never touched."""
    try:
        switch = switch_module()
        home = home.expanduser().resolve()
        import pwd  # noqa: PLC0415
        if home != Path(pwd.getpwuid(os.getuid()).pw_dir).resolve() and run is None:
            return "floor watcher: skipped (non-default --home)"
        if not apply:
            return "floor watcher: an old one would be removed"
        return switch.remove_floor_watch(home, run, system)
    except Exception as error:  # noqa: BLE001 - optional; never fails the harness install
        return f"floor watcher: skipped ({error.__class__.__name__}: {str(error)[:160]})"


SHIM_MARK = b"agent-harness switch shim"


def shim_status(home: Path, apply: bool, now=None) -> str:
    """~/.agent-harness/bin/harness: `harness off|on|status|floor-check` and nothing else. A file there that is not
    this shim (a Go `harness`, anything) is renamed to harness.retired-<UTC stamp> beside it, kept, never deleted."""
    home = home.expanduser().resolve()
    target = home / ".agent-harness" / "bin" / "harness"
    data = (ROOT / "harness" / "bin" / "harness").read_bytes()
    foreign = target.is_symlink() or (target.exists() and SHIM_MARK not in target.read_bytes()[:4096])
    stamp = datetime.fromtimestamp(now, timezone.utc) if now is not None else datetime.now(timezone.utc)
    retired = target.with_name("harness.retired-" + stamp.strftime("%Y%m%dT%H%M%SZ"))
    if not apply:
        return (f"switch shim: would move {target} to {retired.name} and write the shim" if foreign
                else f"switch shim: would write {target}")
    try:
        switch = switch_module()
        switch.private_dir(home / ".agent-harness")
        switch.private_dir(home / ".agent-harness" / "bin")
        if foreign:
            if retired.exists() or retired.is_symlink():
                raise FileExistsError(str(retired))
            os.rename(target, retired)  # a symlink is renamed itself, never followed
        switch.write_atomic(target, data, 0o755)
    except OSError as error:
        return f"switch shim: could not write {target} ({error.__class__.__name__})"
    if foreign:
        return f"switch shim: moved the other program to {retired}; wrote {target}"
    return f"switch shim: {target} (`harness off`, `harness on`, `harness status`, `harness floor-check`)"


def sandbox_module():
    """harness/hooks/ah_sandbox.py from this checkout: the per-role settings (docs/sandbox.md)."""
    hooks = str(ROOT / "harness" / "hooks")
    if hooks not in sys.path:
        sys.path.insert(0, hooks)
    import ah_sandbox  # noqa: PLC0415
    return ah_sandbox


def sandbox_json(settings: dict) -> bytes:
    """The bytes `ah sandbox show` prints: sorted keys, two-space indent, trailing newline."""
    return (json.dumps(settings, indent=2, sort_keys=True) + "\n").encode()


def sandbox_status(home: Path, apply: bool) -> str:
    """Write ~/.agent-harness/sandbox/<role>.claude.json for each role (0600). Inert: nothing loads them unless a
    session is launched with `--settings <file>`, which is the shadow step. No managed settings, no role selected."""
    home = home.expanduser().resolve()
    try:
        sandbox = sandbox_module()
    except ImportError as error:
        return f"sandbox profiles: not written ({error.__class__.__name__}: ah_sandbox is not in this checkout)"
    written = []
    try:
        switch = switch_module()
        for role in sandbox.ROLES:
            path = Path(sandbox.installed_path(home, role))
            data = sandbox_json(sandbox.claude_settings(role, home=home))
            if not apply:
                written.append(path.name)
                continue
            switch.private_dir(home / ".agent-harness")
            switch.private_dir(path.parent)
            if path.is_symlink() or (path.exists() and not path.is_file()):
                return f"sandbox profiles: refused {path} (not a regular file); nothing else written"
            switch.write_atomic(path, data, 0o600)
            written.append(path.name)
    except (OSError, ValueError) as error:
        return f"sandbox profiles: could not write ({error.__class__.__name__}: {str(error)[:160]})"
    where = home / ".agent-harness" / "sandbox"
    return (f"sandbox profiles: {'wrote' if apply else 'would write'} {', '.join(written)} in {where} "
            "(inert until a session is launched with --settings; see docs/sandbox.md)")


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
        try:  # keep the release record and other keys: only this choice changes
            state = json.loads((home.expanduser().resolve() / ".agent-harness" / INSTALL_STATE).read_text())
        except (OSError, ValueError):
            state = {}
        state = state if isinstance(state, dict) else {}
        state.update(schema=state.get("schema", 1), durable_tmp=value)
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle)
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
    """Release 1001 registers no git hook; an upgrade unsets the one earlier releases added."""
    return remove_git_backstop(home, GIT_HOOK_KEY, apply)


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


def mission_control_status(home: Path, apply: bool, flag) -> str:
    """Optional dashboard; never fails the harness install (mission_control_install.status never raises)."""
    try:
        import mission_control_install
        return mission_control_install.status(home, apply, flag)
    except Exception as error:  # noqa: BLE001
        return f"mission control: skipped ({error.__class__.__name__}: {error})"


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


# Flags release 1001 removed. Each fails loudly with its reason instead of being ignored (a removed setting that
# silently does nothing is how a host drifts).
REMOVED_FLAGS = {
    "--services": "the ahd service it registered is deleted; background jobs come from their own installers",
    "--no-provenance-hooks": "the provenance hooks are deleted; nothing is registered to turn off",
    "--no-command-guard": "the command guard is deleted; no hook reads a shell command",
    "--floor-watch": "the floor watcher is deleted; nothing rewrites settings.json except install.py --apply",
    "--no-floor-watch": "the floor watcher is deleted; an --apply on the real home removes an old one",
}


def removed_flag_message(prog: str, argv: list, removed: dict) -> str | None:
    for word in argv:
        name = word.split("=", 1)[0]
        if name in removed:
            return f"{prog}: {name} was removed in release {REMOVED_IN}: {removed[name]}"
    return None


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    message = removed_flag_message("install.py", argv, REMOVED_FLAGS)
    if message:
        parser.exit(2, message + "\n")
    parser.add_argument("--apply", action="store_true", help="write changes; otherwise only preview paths")
    parser.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    parser.add_argument("--hooks-only", action="store_true",
                        help="install the hook, agent, tool and skill files only; never read or write CLAUDE.md or "
                             "settings.json, and skip the scratch, sandbox, netwatch and log-backup steps (per-file "
                             "backups are kept)")
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
    mission = parser.add_mutually_exclusive_group()
    mission.add_argument("--mission-control", dest="mission_control", action="store_true", default=None,
                         help="install Mission Control (the local fleet dashboard, read only) and, on macOS, its "
                              "LaunchAgent (the default; remembered)")
    mission.add_argument("--no-mission-control", dest="mission_control", action="store_false",
                         help="do not install Mission Control; where installed, stop its LaunchAgent (files and chat "
                              "data stay; remembered)")
    backup = parser.add_mutually_exclusive_group()
    backup.add_argument("--log-backup", dest="log_backup", action="store_true", default=None,
                        help="install the scheduled log backup (script and units) and remember the choice")
    backup.add_argument("--no-log-backup", dest="log_backup", action="store_false",
                        help="remember not to install it; where installed, stop its scheduler job (files and "
                             "remote copies stay; see docs/operations.md, Agent log backup, for rollback)")
    parser.add_argument("--allow-downgrade", action="store_true",
                        help="install even though this checkout's harness/RELEASE is below the host's floor "
                             "(~/.agent-harness/floor.json); the floor then moves down to this release")
    args = parser.parse_args(argv)
    refusal = switch_module().downgrade_refusal(args.home.expanduser().resolve(), "claude",
                                                switch_module().read_release(ROOT), args.allow_downgrade)
    if refusal:  # before anything is written, the remembered choices included
        parser.exit(1, f"install.py: {refusal}\n")
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
        changes = install(args.home, args.apply, durable_tmp=durable_tmp, hooks_only=args.hooks_only,
                          allow_downgrade=args.allow_downgrade)
    except DowngradeRefused as error:
        parser.exit(1, f"install.py: {error}\n")
    except DirectoryPublicationError as error:
        parser.exit(1, f'Install failed: {error}\n')
    action = "Installed" if args.apply else "Would install"
    print(f"{action} Agent Harness in {args.home.expanduser() / '.claude'}" + (" (hooks only)" if args.hooks_only else ""))
    for path in changes:
        print(f"  {path}")
    print(f"  {install_git_backstop(args.home, args.apply)}")
    print(f"  {shim_status(args.home, args.apply)}")
    print(f"  {floor_watch_status(args.home, args.apply)}")
    if args.hooks_only:
        print("  CLAUDE.md and settings.json: not touched (--hooks-only)")
        if not args.apply:
            print("Run with --apply to install. Existing files will be backed up.")
        return
    print(f"  {sandbox_status(args.home, args.apply)}")
    print(f"  {scratch_status(args.home, args.apply, durable_tmp)}")
    print(f"  {netwatch_status(args.home, args.apply, args.netwatch)}")
    print(f"  {log_backup_status(args.home, args.apply, args.log_backup)}")
    print(f"  {mission_control_status(args.home, args.apply, args.mission_control)}")
    if not args.apply:
        print("Run with --apply to install. Existing files will be backed up.")


if __name__ == "__main__":
    main()
