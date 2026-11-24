"""Was this command launched by a recognised agent process? A speed bump for careless agents, not a boundary.

goodqa#16944, PR 326a. `ah install-files` (ah_install.guard_gate) asks `check(env)` before it writes a guard file
(guard_files.py). When the answer is "not launched by a recognised agent process", the gate's NOT_AGENT_LAUNCHED branch
holds: the only branch for a guard file's downgrade (--allow-older), --resume and --rollback, which are the user's.
Main's reviewed-release branch (release_receipt.py and main's own stamp) is separate.

The branch holds when all of these hold:
  * stdin is a terminal (stdout may be a pipe: ~/harness-patch.sh pipes the installers' output into tail);
  * none of the agent session variables in AGENT_ENV is set (the exact names listed, not every CLAUDE_CODE_* or
    CODEX_* variable: the user may set configuration variables with those prefixes in his own shell profile);
  * no ancestor process is named like an agent (claude, codex and their -code / -cli forms);
  * some ancestor is a login session or a terminal emulator (INTERACTIVE_ROOTS);
  * no ssh connection and no terminal multiplexer is present (environment or ancestor), unless the caller passes
    allow_remote, which the user turns on by typing --from-ssh-or-multiplexer.

What it is not: proof that a person is present. Nothing a same-user process can observe proves that, and an agent can
meet every condition through ordinary routes, without forging anything (PR 345 review at c3ccde2f, F1):
  * `ssh -tt <host> '<line>'`: ssh makes the terminal and the agent is on the other side of the network hop. Refused
    here unless the flag is typed, which an agent can also type;
  * tmux `new-window` or `send-keys` into a tmux server the user started: refused here unless the flag is typed;
  * on the Mac, `open x.command` or osascript `do script`: the chain is Terminal, login and a shell. Not detected here.
The control that closes these is the command guard refusing the install command inside ssh, multiplexer and
script-launch bodies for every caller (goodqa#17065, guard lane). Until it lands this is a speed bump. The facts this
check saw go into the audit row (`facts`), so a run decided this way is visible afterwards.

Known false refusal: a terminal panel inside the Claude or Codex desktop app has the app as an ancestor; the user runs
the command from Terminal or iTerm instead. `Env` is the test seam: tests pass a fake, never a flag or a variable.
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
SSH_ENV = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
MUX_ENV = ("TMUX", "STY", "ZELLIJ")
SSH_NAMES = frozenset({"sshd", "sshd-session", "mosh-server"})
MUX_NAMES = frozenset({"tmux", "tmux: server", "screen", "zellij"})
INTERACTIVE_ROOTS = frozenset({"login", "getty", "agetty", "mingetty", "gnome-terminal-server", "konsole", "xterm",
                               "uxterm", "alacritty", "kitty", "wezterm-gui", "tilix", "terminator", "foot", "ghostty",
                               "xfce4-terminal", "mate-terminal", "lxterminal", "Terminal", "iTerm2", "Warp"}
                              | SSH_NAMES | MUX_NAMES)
MAX_DEPTH = 64
BRANCH = "not_agent_launched"


def parse_ps(out: str) -> dict:
    """{pid: (ppid, command)} from `ps -axo pid=,ppid=,command=` output (macOS and Linux both right-align the numbers)."""
    table = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = (int(parts[1]), parts[2] if len(parts) == 3 else "")
    return table


class Env:
    """The running process as the operating system reports it."""

    def stdin_is_tty(self) -> bool:
        try:
            return os.isatty(sys.stdin.fileno())
        except (AttributeError, OSError, ValueError):
            return False

    def tty_name(self) -> str:
        try:
            return os.ttyname(sys.stdin.fileno())
        except (AttributeError, OSError, ValueError):
            return ""

    def environ(self) -> dict:
        return dict(os.environ)

    def process_table(self) -> dict:
        out = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,command="], capture_output=True, text=True, timeout=20,
                             env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout
        return parse_ps(out)

    def pid(self) -> int:
        return os.getpid()


def process_name(command: str) -> str:
    words = command.split()
    if command.startswith("tmux: server"):
        return "tmux: server"
    return os.path.basename(words[0]).strip(":").lstrip("-") if words else ""


def ancestors(table: dict, pid: int) -> list:
    """[(pid, name)] from PID's parent upwards, stopping at a loop, a missing pid or MAX_DEPTH."""
    out, seen = [], {pid}
    while pid in table and len(seen) < MAX_DEPTH:
        pid = table[pid][0]
        if pid in seen or pid not in table:
            break
        seen.add(pid)
        out.append((pid, process_name(table[pid][1])))
    return out


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
    """(pid, name) of the first ancestor that is a login session, terminal emulator, ssh server or multiplexer."""
    for found in ancestors(table, pid):
        if found[1] in INTERACTIVE_ROOTS:
            return found
    return None


def check(env: Env | None = None, allow_remote: bool = False):
    """(reason, facts). reason is None when the NOT_AGENT_LAUNCHED branch holds, else one sentence. facts is what the check
    saw, for the audit row. Never raises."""
    env = env or Env()
    facts = {"check": "launch_check", "stdin_tty": False}
    try:
        facts["stdin_tty"] = bool(env.stdin_is_tty())
        if not facts["stdin_tty"]:
            return "stdin is not a terminal (an agent's shell, a pipe or a script)", facts
        facts["tty"] = env.tty_name()
        environ = env.environ()
        marker = [name for name in AGENT_ENV if environ.get(name)]
        facts["agent_env"] = marker
        facts["ssh_env"] = [name for name in SSH_ENV if environ.get(name)]
        facts["mux_env"] = [name for name in MUX_ENV if environ.get(name)]
        if marker:
            return "an agent session variable is set (%s)" % marker[0], facts
        try:
            table = env.process_table()
        except (OSError, subprocess.SubprocessError):
            return "the process table could not be read to check for an agent ancestor", facts
        found = agent_ancestor(table, env.pid())
        if found:
            facts["agent_ancestor"] = [found[0], found[1]]
            return "an agent process (%s, pid %d) is an ancestor of this command" % (found[1], found[0]), facts
        chain = ancestors(table, env.pid())
        facts["ssh_ancestor"] = [name for _, name in chain if name in SSH_NAMES]
        facts["mux_ancestor"] = [name for _, name in chain if name in MUX_NAMES]
        root = interactive_ancestor(table, env.pid())
        facts["qualifying_ancestor"] = [root[0], root[1]] if root else None
        if not root:
            return "no login session or terminal emulator is an ancestor of this command", facts
        remote = facts["ssh_env"] + facts["ssh_ancestor"] + facts["mux_env"] + facts["mux_ancestor"]
        facts["allow_remote"] = bool(allow_remote)
        if remote and not allow_remote:
            # the refusal does not name the flag: an agent that reached the user's terminal is not told the word to add
            # (PR 345 review F14); the user's way is in docs/harness-repair.md
            return ("an ssh connection or a terminal multiplexer is present (%s); an agent can reach the user's terminal "
                    "that way, so this is refused here (docs/harness-repair.md, guard files)" % remote[0]), facts
        return None, facts
    except Exception as error:  # noqa: BLE001 - any surprise fails closed
        return "the launch check failed (%s)" % type(error).__name__, facts


def refusal(env: Env | None = None, allow_remote: bool = False) -> str | None:
    """check()'s reason alone."""
    return check(env, allow_remote)[0]
