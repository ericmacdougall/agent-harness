"""Is a person, not an agent, running this command? The check guard-file installs use for their human branch.

goodqa#16944, PR 326a. `ah install-files` (ah_install) asks `refusal(env)` before it writes a guard file
(guard_files.py); None means the human branch holds. Main's reviewed-release branch (release_receipt.py) is separate
and narrower. The installers and repair are to use it too (goodqa#17032, after the local target goodqa#17031).

The human branch holds when all of these hold:
  * stdin is a terminal. stdout may be a pipe: ~/harness-patch.sh pipes the installers' output into tail;
  * no agent session variable is set (AGENT_ENV);
  * no ancestor process is an agent (claude, codex and their -code / -cli forms);
  * some ancestor is a login session or terminal emulator (INTERACTIVE_ROOTS). A process an agent detached, which is
    reparented to init or launchd, has none.

Threat model: careless or hurried agents, as for the other guards. Names in the process table can be forged, and a
pseudo-terminal can be made, so a deliberate agent can pass this; hard rule 3 forbids that. Known false refusal: a
terminal panel inside the Claude or Codex desktop app has the app as an ancestor, so the user runs the command from
Terminal, iTerm or an ssh session instead. `Env` is the test seam: tests pass a fake, never a flag or a variable.
Stdlib only, Python 3.9+, no side effects on import.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

AGENT_NAME = re.compile(r"^(claude|codex)([-_.].*)?$|claude-code|codex-", re.I)
AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SSE_PORT", "CODEX_THREAD_ID", "CODEX_SESSION_ID",
             "CODEX_SANDBOX", "AH_AGENT_ID")
INTERACTIVE_ROOTS = frozenset({"sshd", "sshd-session", "login", "tmux", "tmux: server", "screen", "mosh-server", "getty",
                               "agetty", "mingetty", "gnome-terminal-server", "konsole", "xterm", "uxterm", "alacritty",
                               "kitty", "wezterm-gui", "tilix", "terminator", "foot", "ghostty", "xfce4-terminal",
                               "mate-terminal", "lxterminal", "Terminal", "iTerm2", "Warp"})
MAX_DEPTH = 64


class Env:
    """The running process as the operating system reports it."""

    def stdin_is_tty(self) -> bool:
        try:
            return os.isatty(sys.stdin.fileno())
        except (AttributeError, OSError, ValueError):
            return False

    def environ(self) -> dict:
        return dict(os.environ)

    def process_table(self) -> dict:
        out = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,command="], capture_output=True, text=True, timeout=20,
                             env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout
        table = {}
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                table[int(parts[0])] = (int(parts[1]), parts[2])
        return table

    def pid(self) -> int:
        return os.getpid()


def process_name(command: str) -> str:
    words = command.split()
    return os.path.basename(words[0]).strip(":").lstrip("-") if words else ""


def agent_ancestor(table: dict, pid: int):
    """(pid, name) of the nearest agent process at or above PID, or None."""
    seen = set()
    while pid in table and pid not in seen and len(seen) < MAX_DEPTH:
        seen.add(pid)
        ppid, command = table[pid]
        words = command.split()
        if any(AGENT_NAME.search(os.path.basename(w)) for w in words[:3]):
            return pid, os.path.basename(words[0])
        pid = ppid
    return None


def interactive_ancestor(table: dict, pid: int):
    """(pid, name) of the first ancestor that is a login session or terminal emulator, or None."""
    seen = {pid}
    while pid in table and len(seen) < MAX_DEPTH:
        pid = table[pid][0]
        if pid in seen or pid not in table:
            return None
        seen.add(pid)
        if process_name(table[pid][1]) in INTERACTIVE_ROOTS:
            return pid, process_name(table[pid][1])
    return None


def refusal(env: Env | None = None) -> str | None:
    """None when a person is running this command; otherwise why not, in one sentence. Never raises."""
    env = env or Env()
    try:
        if not env.stdin_is_tty():
            return "stdin is not a terminal (an agent's shell, a pipe or a script cannot be the human step)"
        marker = [name for name in AGENT_ENV if env.environ().get(name)]
        if marker:
            return "an agent session variable is set (%s)" % marker[0]
        try:
            table = env.process_table()
        except (OSError, subprocess.SubprocessError):
            return "the process table could not be read to prove that no agent is an ancestor"
        found = agent_ancestor(table, env.pid())
        if found:
            return "an agent process (%s, pid %d) is an ancestor of this command" % (found[1], found[0])
        if not interactive_ancestor(table, env.pid()):
            return "no login session or terminal emulator is an ancestor of this command"
        return None
    except Exception as error:  # noqa: BLE001 - any surprise fails closed
        return "the human check failed (%s)" % type(error).__name__
