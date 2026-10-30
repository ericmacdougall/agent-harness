#!/usr/bin/env python3
"""Install Agent Harness into a Claude Code user directory without replacing other settings."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
START = "<!-- agent-harness:start -->"
END = "<!-- agent-harness:end -->"
AGENTS = ("task-owner.md", "click-tester.md", "fixer.md", "red-team.md")
HOOKS = ("process.py", "report_file.py", "wal.py", "wal_note.py", "peer_review.py", "rescue.py", "publish_feature.py", "integrate_local.py")
TOOLS = ("watch-tests.py",)
NO_TARGET_CHECK = object()


def managed_hooks(claude: Path) -> dict[str, dict]:
    script = str(claude / "hooks" / "wal.py")

    def command(event: str, fail_closed: bool = False) -> dict:
        hook = {"type": "command", "command": "python3", "args": [script, event], "timeout": 10}
        if fail_closed:
            hook["onFailure"] = "block"
        return hook

    return {
        "SessionStart": {"hooks": [command("session")]},
        "UserPromptSubmit": {"hooks": [command("prompt", True)]},
        "SubagentStart": {
            "matcher": "^(task-owner|click-tester|fixer|red-team)$",
            "hooks": [command("subagent")],
        },
        "PreToolUse": {
            "matcher": "Agent|Task|Workflow|Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit",
            "hooks": [command("pretool", True)],
        },
    }


def merged_settings(current: dict, claude: Path) -> dict:
    settings = json.loads(json.dumps(current))
    hooks = settings.setdefault("hooks", {})
    for event, entry in managed_hooks(claude).items():
        entries = hooks.setdefault(event, [])
        script = str(claude / "hooks" / "wal.py")
        preserved = []
        for item in entries:
            remaining = [
                hook for hook in item.get("hooks", [])
                if not (hook.get("type") == "command"
                        and hook.get("command") == "python3"
                        and (hook.get("args") or [None])[0] == script)
            ]
            if remaining == item.get("hooks", []):
                preserved.append(item)
            elif remaining:
                preserved.append({**item, "hooks": remaining})
        entries[:] = preserved
        entries.append(entry)
    allowed = settings.setdefault("permissions", {}).setdefault("allow", [])
    for name in ("wal_note.py", "publish_feature.py", "integrate_local.py"):
        rule = f"Bash(python3 ~/.claude/hooks/{name} *)"
        if rule not in allowed:
            allowed.append(rule)
    return settings


def merged_instructions(existing: str, instructions: str) -> str:
    block = f"{START}\n{instructions.rstrip()}\n{END}"
    if START in existing or END in existing:
        if existing.count(START) != 1 or existing.count(END) != 1 or existing.index(START) > existing.index(END):
            raise ValueError("CLAUDE.md has malformed Agent Harness markers; resolve manually")
        return existing[: existing.index(START)] + block + existing[existing.index(END) + len(END):]
    return existing.rstrip() + ("\n\n" if existing.strip() else "") + block + "\n"


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
                os.rename(staged, path.name, src_dir_fd=parent, dst_dir_fd=parent)
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


def require_target(path: Path, directory: int, expected) -> None:
    if expected is not NO_TARGET_CHECK and target_identity(directory, path.name) != expected:
        raise OSError(f'Managed file changed since snapshot: {path.name}')


def atomic_write(path: Path, data: bytes, mode: int = 0o600, *, pinned_parent=None,
                 expected_target=NO_TARGET_CHECK, published=None):
    with parent_fd(path) as directory:
        require_pinned_parent(path, directory, pinned_parent)
        require_target(path, directory, expected_target)
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
            require_target(path, directory, expected_target)
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            identity = written.st_dev, written.st_ino
            if published is not None:
                published[path] = identity
            os.fsync(directory)
            require_pinned_parent(path, directory, pinned_parent)
            if target_identity(directory, path.name) != identity:
                raise OSError(f'Managed file changed after replacement: {path.name}')
            return identity
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def safe_unlink(path: Path, *, pinned_parent=None, expected_target=NO_TARGET_CHECK) -> None:
    opened_parent = False
    try:
        with parent_fd(path) as directory:
            opened_parent = True
            require_pinned_parent(path, directory, pinned_parent)
            require_target(path, directory, expected_target)
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


def install(home: Path, apply: bool) -> list[str]:
    claude = home.expanduser().resolve() / ".claude"
    files = [
        *((ROOT / "harness" / folder / name, claude / folder / name)
          for folder, names in (("agents", AGENTS), ("hooks", HOOKS), ("tools", TOOLS))
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
                          claude / 'tools', backup_root):
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
        settings = merged_settings(current_settings, claude)
        # Read every payload before any managed write (also validate it in preview).
        payloads = [(destination, source.read_bytes()) for source, destination in files]
        payloads += [(instructions_path, instructions.encode()),
                     (settings_path, (json.dumps(settings, indent=2) + "\n").encode())]
        changes = [str(path) for path in managed]
        if not apply:
            return changes
        originals = {path: read_regular(path, pinned_parent=pins.fd(path.parent),
                                        retain_fd=pins.file_fds)
                     for path in managed}
        if originals[instructions_path] != existing_instructions or originals[settings_path] != existing_settings:
            raise OSError('User settings or instructions changed during installation preflight; retry')
        # Exclusive creation rejects a real directory that appears after snapshot.
        for directory in (claude, claude / 'agents', claude / 'hooks', claude / 'tools', backup_root):
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
                if saved.parent != backups:
                    pins.create(saved.parent)
                atomic_write(saved, originals[path][0], pinned_parent=pins.fd(saved.parent),
                             expected_target=None)
        attempted = []
        installed = {}
        try:
            for destination, data in payloads:
                attempted.append(destination)
                expected = originals[destination][2] if originals[destination] else None
                installed[destination] = atomic_write(destination, data,
                                                       pinned_parent=pins.fd(destination.parent),
                                                       expected_target=expected, published=installed)
        except BaseException as error:
            failures = []
            for path in reversed(attempted):
                try:
                    original = originals[path]
                    expected = installed.get(path, original[2] if original else None)
                    if original is None:
                        safe_unlink(path, pinned_parent=pins.fd(path.parent), expected_target=expected)
                    else:
                        atomic_write(path, original[0], original[1], pinned_parent=pins.fd(path.parent),
                                     expected_target=expected)
                except OSError:
                    failures.append(str(path.relative_to(claude)))
            if failures:
                raise RuntimeError(f"Installation failed; rollback incomplete for {', '.join(failures)}; "
                                   f"restore from {backups}") from error
            raise
        return changes
    finally:
        pins.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write changes; otherwise only preview paths")
    parser.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    args = parser.parse_args()
    changes = install(args.home, args.apply)
    action = "Installed" if args.apply else "Would install"
    print(f"{action} Agent Harness in {args.home.expanduser() / '.claude'}")
    for path in changes:
        print(f"  {path}")
    if not args.apply:
        print("Run with --apply to install. Existing files will be backed up.")


if __name__ == "__main__":
    main()
