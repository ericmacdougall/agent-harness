"""PreToolUse(Write|Edit|MultiEdit|NotebookEdit): an agent's file tools never write a session transcript.

Why (goodqa#16944, PR 326 review F5): supervisor power reads the model of a call from the client's own transcript
record of that call (supervisor_grant.call_record). The command guard's `transcript-forgery` rule refuses shell
writes under ~/.claude/projects, but nothing stopped a Write or Edit tool call from changing a record's `model` in
place. This hook closes that route.

What it refuses: a file-tool write whose target, after ~ expansion, the payload cwd and symlinks are resolved, is
under <claude>/projects or <claude>/transcripts, for every candidate claude folder: the real home's ~/.claude, $HOME's,
and CLAUDE_CONFIG_DIR's. A target whose path cannot be resolved, or an unreadable payload for one of these tools, is
refused too: the check fails closed.

What stays writable: <projects>/<dir>/memory/**, the auto-memory notes, except any .jsonl file there.

Output: hookSpecificOutput.permissionDecision "deny" with a reason, on exit 0; nothing at all when allowed.
Python 3.9+, standard library and safe_input only. Importing this module has no side effects.
"""
from __future__ import annotations

import json
import os
import pwd
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
PATH_KEYS = ("file_path", "notebook_path", "path")
PROTECTED = ("projects", "transcripts")
MAX_PAYLOAD = 8 << 20


def claude_dirs(env=None) -> list:
    """Every folder Claude Code may keep transcripts in. More candidates can only refuse more."""
    env = os.environ if env is None else env
    out = []
    homes = []
    try:
        homes.append(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        pass
    if env.get("HOME"):
        homes.append(env["HOME"])
    candidates = [os.path.join(h, ".claude") for h in homes]
    if env.get("CLAUDE_CONFIG_DIR"):
        candidates.append(env["CLAUDE_CONFIG_DIR"])
    for candidate in candidates:
        real = os.path.realpath(os.path.expanduser(candidate))
        if real not in out:
            out.append(real)
    return out


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve(target, cwd) -> str:
    """The real absolute path a file tool would write. Symlinks in the existing part of the path are followed."""
    text = os.path.expanduser(str(target))
    if not os.path.isabs(text):
        if not isinstance(cwd, str) or not os.path.isabs(cwd):
            raise ValueError("a relative path with no absolute cwd")
        text = os.path.join(cwd, text)
    return os.path.realpath(text)


def reason_for(payload, env=None) -> str | None:
    """Why this file-tool call is refused, or None to allow. Never raises."""
    try:
        if not isinstance(payload, dict):
            return "the hook payload is unreadable, so a transcript write cannot be ruled out"
        tool = str(payload.get("tool_name") or "")
        if tool not in TOOLS:
            return None
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            return "the %s call has no input to check" % tool
        targets = [tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str) and tool_input.get(k)]
        if not targets:
            return None
        for target in targets:
            if "\x00" in target:
                return "the target path holds a NUL byte"
            real = resolve(target, payload.get("cwd"))
            for claude in claude_dirs(env):
                for name in PROTECTED:
                    root = os.path.join(claude, name)
                    if not _within(real, root) and not _within(real.lower(), root.lower()):
                        continue
                    below = os.path.relpath(real.lower(), root.lower()).split("/")
                    if name == "projects" and len(below) >= 3 and below[1] == "memory" and not real.lower().endswith(".jsonl"):
                        continue  # the auto-memory notes: projects/<dir>/memory/...
                    return ("%s is under %s, where Claude Code keeps session transcripts; only the client writes them "
                            "(memory notes go under projects/<dir>/memory/)" % (real, root))
        return None
    except Exception as error:  # noqa: BLE001 - a check that cannot finish refuses
        return "the transcript guard could not check this call (%s); refused" % type(error).__name__


def decision(reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": "transcript_guard: " + reason}})


def main() -> int:
    try:
        import safe_input  # noqa: PLC0415
        raw = safe_input.read_stdin_bounded(MAX_PAYLOAD).decode("utf-8", "replace")
        payload = safe_input.safe_json_loads(raw)
    except Exception:  # noqa: BLE001
        payload = None
    why = reason_for(payload)
    if why:
        print(decision(why))
    return 0


if __name__ == "__main__":
    sys.exit(main())
