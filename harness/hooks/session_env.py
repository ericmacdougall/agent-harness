#!/usr/bin/env python3
"""SessionStart hook: the session's folder, its temp directory and one line of context (docs/lifecycle.md).

The path is the owner: what a session makes belongs under ~/.agent-harness/work/<session>/. This hook makes that
folder. When Claude Code names an env file (CLAUDE_ENV_FILE) it adds AH_SESSION, AH_WORK and, unless local.json
`session_tmpdir` is false, TMPDIR = ~/.agent-harness/tmp/<first 8 characters of the folder name> (0700; short,
because a unix socket path holds about 104 characters). It prints one line that tells the agent where its files
belong, and a second line when autosave.py measured the folder over local.json `session_quota_gb` (default 10).
Nothing is refused or delayed: no tool call is read, and every failure is silence and exit 0. Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import ah_local  # noqa: E402
    import safe_input  # noqa: E402
    import workdir  # noqa: E402
except ImportError:   # a partial install must not fail a session start
    if __name__ == "__main__":
        sys.exit(0)
    raise

MAX_LINE = 400   # the context line stays under this many characters
GB = 1024 ** 3
SMALL = 256 * 1024


def tmp_dir(name) -> Path:
    """The temp directory of the session whose folder is called `name`. `ah reap` removes it with the folder."""
    return Path.home() / ".agent-harness" / "tmp" / str(name)[:8]


def state_file(name) -> Path:
    """Where autosave.py records the folder's size and what it could not save."""
    return Path.home() / ".agent-harness" / "state" / "git-save" / ("session-%s.json" % name)


def make_tmp(name):
    """Make the temp directory (0700) and return it; None when it cannot be a real directory of this user."""
    path, mask = tmp_dir(name), os.umask(0o077)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None
        os.chmod(path, 0o700)
    except OSError:
        return None
    finally:
        os.umask(mask)
    return path


def write_env(env_file, values) -> None:
    """Append `export NAME=value` lines to Claude Code's env file, leaving out the lines it already holds."""
    try:
        old = safe_input.read_bounded(env_file, SMALL).decode("utf-8", "replace")
    except safe_input.InputRejected:
        old = ""
    lines = ["export %s=%s" % (key, shlex.quote(str(value))) for key, value in values.items()]
    new = [line for line in lines if line not in old.splitlines()]
    if new:
        with open(env_file, "a", encoding="utf-8") as handle:
            handle.write(("" if not old or old.endswith("\n") else "\n") + "".join(line + "\n" for line in new))


def context(folder, ah, home, exported=False, session=None) -> str:
    """The one line an agent reads at session start: full paths when they fit, else paths from ~, else plain `ah`.
    A shell that got no env file (Codex) has no AH_SESSION, which `ah co` needs, so the command carries it."""
    env = "AH_SESSION=%s " % shlex.quote(session) if session and not exported else ""
    def short(path):
        path, base = str(path), str(home).rstrip("/") + "/"
        return "~/" + path[len(base):] if path.startswith(base) else path

    def line(show, tool):
        return ("Session folder: %s%s. Put clones, scratch and test fixtures there, not in the home folder or /tmp. "
                "It is cleaned up after the session ends; unpushed work is saved first. Put anything costly to "
                "recreate in its keep/ folder. For a checkout: %s co <owner/repo>."
                % (show(folder), " ($AH_WORK)" if exported else "", tool))

    for text in (line(str, "%spython3 %s" % (env, ah)), line(short, "%spython3 %s" % (env, short(ah))),
                 line(short, env + "ah")):
        if len(text) < MAX_LINE:
            break
    return text[:MAX_LINE - 1]


def _number(value, above=0):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value > above else None


def quota_line(name) -> str:
    """One line naming the three largest directories when the last measured size is over the quota; else ''."""
    quota = _number(ah_local.get("session_quota_gb")) or 10
    try:
        state = safe_input.safe_json_loads(safe_input.read_bounded(state_file(name), SMALL))
    except (safe_input.InputRejected, ValueError):
        return ""
    size = _number(state.get("bytes"), quota * GB) if isinstance(state, dict) else None
    if size is None:
        return ""
    top = ", ".join("%s %.1f GB" % (re.sub(r"[\x00-\x1f\x7f]+", " ", str(row[0]))[:60], row[1] / GB)
                    for row in (state.get("top") or [])[:3]
                    if isinstance(row, list) and len(row) == 2 and _number(row[1]) is not None)
    return ("This session folder holds %s%.1f GB, over the limit of %g GB (local.json session_quota_gb).%s Delete "
            "what is no longer needed." % ("" if state.get("complete") else "at least ", size / GB, quota,
                                           " Largest: %s." % top if top else ""))


def main() -> int:
    try:
        data = safe_input.safe_json_loads(safe_input.read_stdin_bounded(SMALL) or b"{}")
        session = data.get("session_id") if isinstance(data, dict) else None
        if not isinstance(session, str) or not session.strip():
            return 0
        folder = workdir.ensure_session_dir(session)
        exported, env_file = False, os.environ.get("CLAUDE_ENV_FILE")
        if env_file:
            values = {"AH_SESSION": session, "AH_WORK": str(folder)}
            try:
                if ah_local.get("session_tmpdir") is not False and make_tmp(folder.name):
                    values["TMPDIR"] = str(tmp_dir(folder.name))
                write_env(env_file, values)
                exported = True
            except OSError:
                pass   # the env file cannot be written: the folder and the context line still stand
        text = context(folder, Path(__file__).resolve().parent / "ah.py", Path.home(), exported, session)
        extra = quota_line(folder.name)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                 "additionalContext": text + ("\n" + extra if extra else "")}}))
    except Exception as error:   # noqa: BLE001  this hook never fails a session start
        sys.stderr.write("session_env: skipped (%s)\n" % type(error).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
