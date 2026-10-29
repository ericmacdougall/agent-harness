#!/usr/bin/env python3
"""Install Agent Harness into a Claude Code user directory without replacing other settings."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
START = "<!-- agent-harness:start -->"
END = "<!-- agent-harness:end -->"
AGENTS = ("task-owner.md", "click-tester.md", "fixer.md", "red-team.md")
HOOKS = ("process.py", "wal.py", "wal_note.py", "peer_review.py", "rescue.py", "publish_feature.py", "integrate_local.py")
TOOLS = ("watch-tests.py",)


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


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".agent-harness-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


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
    current_text = (claude / "CLAUDE.md").read_text() if (claude / "CLAUDE.md").exists() else ""
    instructions = merged_instructions(current_text, (ROOT / "HARNESS.md").read_text())
    settings_path = claude / "settings.json"
    current_settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    if not isinstance(current_settings, dict):
        raise ValueError("settings.json must contain an object")
    settings = merged_settings(current_settings, claude)
    changes = [str(path) for path in managed]
    if not apply:
        return changes
    backup_root = claude / "agent-harness-backups"
    backups = backup_root / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    claude.mkdir(parents=True, exist_ok=True)
    backup_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(backup_root, 0o700)  # backups hold settings.json, which may carry env values
    backups.mkdir(mode=0o700)
    for path in managed:
        if path.exists():
            saved = backups / path.relative_to(claude)
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, saved)
            os.chmod(saved, 0o600)
    for source, destination in files:
        atomic_write(destination, source.read_bytes())
    atomic_write(claude / "CLAUDE.md", instructions.encode())
    atomic_write(settings_path, (json.dumps(settings, indent=2) + "\n").encode())
    return changes


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
