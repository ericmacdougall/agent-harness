#!/usr/bin/env python3
"""Stop / SubagentStop hook: do not end a turn with work that exists only on this disk.

Vendored from Hawkeye install/claude-hooks/hawkeye-worktree-hygiene.py (ericmacdougall/hawkeye 831ea85) for
rule S18 (goodqa#14908), so T2 and the Mac keep the dev2 protection after dev2 is retired. Harness changes:
  - state in ~/.agent-harness/state/worktree-hygiene/, config in ~/.agent-harness/state/worktree-hygiene.json;
  - default repos dirs are ~/repos and ~/.agent-harness/work (where harness owner worktrees live);
  - HARNESS_WORKTREE_GATE=off (or Hawkeye's HAWKEYE_NO_WORKTREE_GATE=1) opts out; there is no
    ##HAWKEYE-RULES=FALSE switch;
  - committed-but-unpushed work is REPORTED, not blocked, unless block_unpushed is set (config key, or
    HARNESS_WORKTREE_HYGIENE_BLOCK_UNPUSHED=1). Harness owners commit locally and publish through
    deliver.py / publish_feature.py after review, so a stop block that says "git push" would route around
    the identity-checked publication path. Uncommitted work always blocks (once per state), and so do
    commits on a detached HEAD (on no branch, so git gc can drop them): the block asks for `switch -c`;
  - the suggested commit uses the commit policy (commit -F after commit_policy.py check-message), not a
    per-handle identity.
Hawkeye's original text follows.

WHY THIS EXISTS. Eric, 2026-09-25 (AGENTS.md "## Worktree and branch hygiene
(you cannot stop with a mess -- enforced)"): "You may not end your turn or
session while any worktree you created has work that exists only on this
disk: every such worktree's commits must be on an origin branch (a pending
feature branch is fine) and nothing may be left uncommitted." and "No mess of
duplicates on disk: one worktree per branch; remove a worktree as soon as its
branch is merged". The rule names "the harness stop hook" as its enforcement.
This is that hook.

WHAT IT DOES at the end of a turn:
  1. Reads the transcript named in the hook's stdin JSON (the subagent's own
     `agent_transcript_path` on SubagentStop, `transcript_path` on Stop) and
     collects the git worktrees THIS transcript created (`git worktree add`)
     or worked in (Edit/Write/MultiEdit/NotebookEdit under the tree, or a
     mutating `git -C <tree> ...` / `cd <tree> && git ...`, read with a real
     shell lexer: heredoc bodies and quoted text are data, and a directory it
     cannot know -- `-C "$X"`, `cd $(...)` -- is dropped, never pinned on the
     surrounding cwd; see bash_touches). Only LINKED
     worktrees of repos under the repos dir(s) count (default ~/repos;
     HAWKEYE_WORKTREE_HYGIENE_REPOS_DIRS or ~/.hawkeye/harness/
     worktree-hygiene.json {"repos_dirs": [...]} override it).
  2. Drops every worktree that another transcript worked in MORE RECENTLY than
     this one did -- a subagent this session delegated the tree to, or another
     session that took it over. Its owner answers for it, not us; telling this
     agent to commit it would be telling it to commit someone else's
     half-finished edit (2026-09-24, a read-only reviewer obeyed exactly that
     kind of instruction on another agent's live worktree).
  3. BLOCKS (exit 2, stderr = the reason, the same contract the sibling Stop
     hooks hawkeye-wal-cadence.py / hawkeye-adversarial-review.py use --
     https://code.claude.com/docs/en/hooks, fetched 2026-09-25: "A hook that
     blocks by exiting 2 routes the same way as `reason`") when a remaining
     worktree has uncommitted changes, or a HEAD that is contained in no
     origin/* ref. A repo with no `origin` is judged by its other remotes'
     refs; a repo with NO remote at all blocks only when the tree holds commits
     no other branch or tag does, says that the repo has no remote, and asks
     once per session for that tree (a local-only repo cannot push, so a new
     commit there is not a new question). The reason lists exact paths and the
     commands that fix it.
  4. REPORTS, without blocking, merged-but-still-present worktrees, duplicates
     (same branch twice, or a detached tree at the same commit as another) and
     leftover detached worktrees, with cleanup commands -- inside the block
     reason when it blocks, else as a `systemMessage` (shown to the user).

IT MUST NEVER TRAP A SESSION. Hard rules, each tested:
  - `stop_hook_active` true (Claude Code is already continuing because a stop
    hook blocked) -> never block. With this, it blocks at most once per turn.
  - blocks at most ONCE per distinct dirty-state fingerprint per session (the
    agent may genuinely have a reason; the rule is "ask", not "imprison").
  - every git call has a timeout, the whole hook a budget (~12s, never more
    than 15s); running out of time allows the stop.
  - fails OPEN: any internal error, unreadable transcript, git failure or
    malformed input allows the stop.
  - read-only: only read commands, with GIT_OPTIONAL_LOCKS=0 so `git status`
    never takes index.lock or rewrites the index, and core.fsmonitor off so no
    daemon is spawned. It never fetches, commits, prunes or removes anything --
    it prints the commands; the agent decides.
  - opt-out: HAWKEYE_NO_WORKTREE_GATE=1, or `##HAWKEYE-RULES=FALSE` in the
    project's CLAUDE.md/AGENTS.md (the whole managed harness's kill switch).
"""
from __future__ import annotations


def _hidden_no_window():
    return {}  # POSIX only (the Mac and T2); Hawkeye's Windows window-hiding is not needed here


import calendar
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python3 -I drops the script dir
import safe_input  # noqa: E402

STATE_HOME = os.path.join(os.path.expanduser("~"), ".agent-harness")
STATE_DIR = os.path.join(STATE_HOME, "state", "worktree-hygiene")
CONFIG_PATH = os.path.join(STATE_HOME, "state", "worktree-hygiene.json")

DEFAULT_BUDGET_S = 12.0
MAX_BUDGET_S = 15.0
GIT_CALL_TIMEOUT_S = 5.0
MAX_WORKTREES = 24            # worktrees examined per stop, most recently touched first
CHUNK = 8 << 20               # transcript read size
MAX_LINE = 64 << 20           # a "line" longer than this is dropped, not buffered
SHOW_STATUS_LINES = 8

EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
PATH_KEYS = ("file_path", "notebook_path")
# git subcommands that change a worktree's state -- running one inside a tree
# is working in it, as surely as an Edit is.
MUTATING_GIT = frozenset(("commit", "add", "merge", "rebase", "cherry-pick", "reset", "checkout",
                          "switch", "stash", "am", "apply", "revert", "rm", "mv", "restore", "pull"))
# git global options that take a separate value.
GIT_OPTS_WITH_VALUE = frozenset(("-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                                 "--config-env", "--super-prefix"))
WT_ADD_OPTS_WITH_VALUE = frozenset(("-b", "-B", "--reason"))
COMMAND_PREFIXES = frozenset(("sudo", "command", "time", "env", "nice", "nohup", "exec", "builtin"))

_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


class OutOfTime(Exception):
    pass


class Budget(object):
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def left(self) -> float:
        return self.end - time.monotonic()

    def check(self) -> None:
        if self.left() <= 0:
            raise OutOfTime()


# --------------------------------------------------------------------- config

def budget_seconds() -> float:
    try:
        v = float(_env("WORKTREE_HYGIENE_BUDGET_S") or DEFAULT_BUDGET_S)
    except ValueError:
        v = DEFAULT_BUDGET_S
    return max(0.5, min(MAX_BUDGET_S, v))


def _env(suffix: str) -> str:
    """HARNESS_<suffix>, else Hawkeye's HAWKEYE_<suffix> (so dev2-era settings keep working)."""
    return os.environ.get("HARNESS_" + suffix) or os.environ.get("HAWKEYE_" + suffix) or ""


def _config() -> dict:
    if not os.path.lexists(CONFIG_PATH):
        return {}
    try:
        cfg = safe_input.safe_json_loads(safe_input.read_bounded(CONFIG_PATH, 65536).decode("utf-8", "replace"))
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError, safe_input.InputRejected):
        return {}


def block_unpushed() -> bool:
    raw = _env("WORKTREE_HYGIENE_BLOCK_UNPUSHED")
    if raw:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return _config().get("block_unpushed") is True


def repos_dirs() -> list:
    raw = _env("WORKTREE_HYGIENE_REPOS_DIRS")
    dirs = []
    if raw:
        dirs = [d for d in raw.split(os.pathsep) if d.strip()]
    else:
        got = _config().get("repos_dirs")
        if isinstance(got, list):
            dirs = [str(d) for d in got if isinstance(d, str) and d.strip()]
    if not dirs:
        dirs = [os.path.join(os.path.expanduser("~"), "repos"),
                os.path.join(os.path.expanduser("~"), ".agent-harness", "work")]
    out = []
    for d in dirs:
        try:
            out.append(os.path.realpath(os.path.expanduser(d)))
        except (OSError, ValueError):
            continue
    return out


def opted_out(cwd: str) -> bool:
    if os.environ.get("HAWKEYE_NO_WORKTREE_GATE") == "1":
        return True
    return os.environ.get("HARNESS_WORKTREE_GATE", "").strip().lower() == "off"


# ------------------------------------------------------------------------ git

def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                        "GIT_OBJECT_DIRECTORY", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES")
           and not k.startswith("GITHEAD_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C",
                "GIT_PAGER": "cat", "PAGER": "cat"})
    return env


def git(budget: Budget, cwd: str, *args: str) -> "tuple[int, str]":
    """(returncode, stdout). Read-only callers only. Bounded by the per-call
    timeout AND what is left of the hook's budget; on timeout the whole process
    group is killed (a git that forked a helper must not outlive the hook)."""
    t = min(GIT_CALL_TIMEOUT_S, budget.left())
    if t <= 0.05:
        raise OutOfTime()
    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.quotePath=false", "-C", cwd] + list(args)
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env=_git_env(), start_new_session=True, **_hidden_no_window())
    except OSError:
        return 127, ""
    try:
        out, _ = p.communicate(timeout=t)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            p.wait(timeout=1)
        except Exception:        # noqa: BLE001
            pass
        raise OutOfTime()
    return p.returncode, out.decode("utf-8", "replace")


# --------------------------------------------------------- worktree discovery

_TOP_CACHE: dict = {}


def linked_worktree_of(path: str) -> "tuple[str, str] | None":
    """(worktree top, main repo dir) when `path` is inside a LINKED git
    worktree, else None. Filesystem only -- no git process: a `.git` FILE whose
    gitdir has a `commondir` is a linked worktree (a submodule's `.git` file
    points at a gitdir without one; a main checkout has a `.git` directory)."""
    try:
        p = os.path.abspath(os.path.expanduser(path))
    except (TypeError, ValueError):
        return None
    probe = p
    seen = []
    while True:
        if probe in _TOP_CACHE:
            hit = _TOP_CACHE[probe]
            for s in seen:
                _TOP_CACHE[s] = hit
            return hit
        seen.append(probe)
        dotgit = os.path.join(probe, ".git")
        hit = None
        found = False
        if os.path.isfile(dotgit):
            found = True
            hit = _read_linked(probe, dotgit)
        elif os.path.isdir(dotgit):
            found = True               # a main checkout (or plain repo): not a linked worktree
        if found:
            for s in seen:
                _TOP_CACHE[s] = hit
            return hit
        parent = os.path.dirname(probe)
        if parent == probe:
            for s in seen:
                _TOP_CACHE[s] = None
            return None
        probe = parent


def _read_linked(top: str, dotgit: str) -> "tuple[str, str] | None":
    try:
        first = (safe_input.read_bounded(dotgit, 4096).decode("utf-8", "replace").splitlines() or [""])[0].strip()
    except (OSError, safe_input.InputRejected):
        return None
    if not first.startswith("gitdir:"):
        return None
    gd = first[len("gitdir:"):].strip()
    if not os.path.isabs(gd):
        gd = os.path.normpath(os.path.join(top, gd))
    try:
        raw = safe_input.read_bounded(os.path.join(gd, "commondir"), 4096).decode("utf-8", "replace")
        cd = (raw.splitlines() or [""])[0].strip()
    except (OSError, safe_input.InputRejected):
        return None                    # a submodule, not a linked worktree
    common = cd if os.path.isabs(cd) else os.path.normpath(os.path.join(gd, cd))
    main = os.path.dirname(common) if os.path.basename(common) == ".git" else common
    return os.path.normpath(top), os.path.normpath(main)


def under_any(path: str, roots: list) -> bool:
    try:
        rp = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return any(rp == r or rp.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


# ------------------------------------------------------- transcript parsing

def parse_ts(v) -> float:
    if not isinstance(v, str):
        return 0.0
    m = _ISO.match(v.strip())
    if not m:
        return 0.0
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        t = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0))
    except (ValueError, OverflowError):
        return 0.0
    if frac:
        t += float("0." + frac)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        t -= sign * (hh * 3600 + mm * 60)
    return float(t)


def _resolve(p: str, cwd: "str | None") -> "str | None":
    """An absolute path for `p`, or None when it cannot be known: empty, a shell
    expansion ($VAR, $(...), `...`), or relative to an unknown directory."""
    if not p or "$" in p or "`" in p:
        return None
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        if not cwd:
            return None
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


# ------------------------------------------------------------- shell lexing
#
# WHY A LEXER AND NOT shlex PER LINE. A Bash tool call is a shell PROGRAM, and
# the text of a heredoc body, a here-string or a multi-line quoted argument is
# DATA in it, not commands. The per-line shlex split this replaced (blind
# verifier, 2026-09-25) parsed every line on its own, so the Claude Code commit
# idiom `git commit -m "$(cat <<'EOF' ... EOF)"` lost the real command (line 1
# has an unterminated quote) and "ran" every git command its message merely
# quoted -- claiming, and possibly blocking on, a worktree the session never
# touched. This lexer follows the shell's own rules for exactly what matters
# here: quotes (which may span lines), backslash escapes and continuations,
# $(...) / ${...} / `...` (opaque, and marked DYNAMIC: their value is only
# known at run time), comments, control operators, redirections, and heredoc
# bodies (skipped from the next unquoted newline to the delimiter line; <<-
# strips leading tabs). Anything it cannot follow raises ValueError and the
# whole command is ignored -- an unseen touch can only ever mean NOT blocking.

_CONTROL_OPS = ("&&", "||", ";;", "|&", ";", "|", "&", "(", ")")
_REDIR_OPS = ("<<<", "<<-", "&>>", "<<", ">>", ">&", "<&", "&>", ">|", "<>", ">", "<")
_ALL_OPS = tuple(sorted(_CONTROL_OPS + _REDIR_OPS, key=len, reverse=True))
# Bash splits words on blank, tab and newline only: a no-break space, \v or \f
# is an ordinary word character. (CR is also a separator here, on purpose: a
# CRLF-pasted command is read as the command it was meant to be.)
_PLAIN_RUN = re.compile(r"[^ \t\r\n\\'\"$`#;&|()<>]+")
MAX_COMMAND = 256 << 10
# Words that open a compound command or are reserved in command position; the
# simple command proper starts after them.
RESERVED_LEAD = frozenset(("if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time"))


def _skip_backtick(src: str, i: int) -> int:
    """Index just past the ` closing the one before src[i]."""
    n = len(src)
    while i < n:
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == "`":
            return i + 1
        i += 1
    raise ValueError("unterminated `")


def _skip_braces(src: str, i: int) -> int:
    """Index just past the } closing the ${ whose { is at src[i-1]."""
    depth, n = 1, len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unterminated ${")


def _dollar(src: str, i: int) -> int:
    """src[i] == '$': index just past the expansion it starts."""
    if src.startswith("$(", i):
        _toks, j = _lex(src, i + 2, True)       # $(...) and $((...)) nest like a subshell
        return j
    if src.startswith("${", i):
        return _skip_braces(src, i + 2)
    return i + 1                                 # $NAME / $1 / $? -- the name follows as plain text


def _dquote(src: str, i: int) -> "tuple[str, bool, int]":
    """From just past an opening ": (text, dynamic, index past the closing ")."""
    out, dyn, n = [], False, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            return "".join(out), dyn, i + 1
        if c == "\\" and i + 1 < n:
            nx = src[i + 1]
            if nx == "\n":
                i += 2
                continue
            if nx in '"\\$`':
                out.append(nx)
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        if c == "$":
            j = _dollar(src, i)
            out.append(src[i:j])
            dyn = True
            i = j
            continue
        if c == "`":
            j = _skip_backtick(src, i + 1)
            out.append(src[i:j])
            dyn = True
            i = j
            continue
        out.append(c)
        i += 1
    raise ValueError('unterminated "')


def _skip_heredocs(src: str, i: int, pending: list) -> int:
    """Skip the bodies of `pending` heredocs, which start at src[i]."""
    n = len(src)
    for delim, strip_tabs in pending:
        while i < n:
            j = src.find("\n", i)
            line = src[i:] if j < 0 else src[i:j]
            i = n if j < 0 else j + 1
            if strip_tabs:
                line = line.lstrip("\t")
            if line.rstrip("\r") == delim:
                break
    return i


def _lex(src: str, i: int = 0, in_subst: bool = False) -> "tuple[list, int]":
    """Tokens of `src` from `i`: ("w", text, dynamic) | ("op", op) | ("redir", op).
    A newline is ("op", "\\n"). Heredoc delimiters and bodies produce no tokens.
    With in_subst, stops after the `)` that closes a $( whose body starts at i."""
    toks: list = []
    n = len(src)
    buf: list = []
    st = {"started": False, "quoted": False, "dyn": False}
    pending: list = []
    want_delim: list = []           # [strip_tabs] while a << awaits its delimiter word
    depth = 0

    def finish() -> None:
        if st["started"]:
            text = "".join(buf)
            if want_delim:
                pending.append((text, want_delim.pop()))
            else:
                toks.append(("w", text, st["dyn"]))
        del buf[:]
        st["started"] = st["quoted"] = st["dyn"] = False

    while i < n:
        c = src[i]
        m = _PLAIN_RUN.match(src, i)
        if m:
            buf.append(m.group(0))
            st["started"] = True
            i = m.end()
            continue
        if c == "\\":
            if i + 1 < n and src[i + 1] == "\n":
                i += 2
                continue
            if i + 1 < n:
                buf.append(src[i + 1])
                st["started"] = st["quoted"] = True
            i += 2
            continue
        if c == "'":
            j = src.find("'", i + 1)
            if j < 0:
                raise ValueError("unterminated '")
            buf.append(src[i + 1:j])
            st["started"] = st["quoted"] = True
            i = j + 1
            continue
        if c == '"':
            text, dyn, i = _dquote(src, i + 1)
            buf.append(text)
            st["started"] = st["quoted"] = True
            st["dyn"] = st["dyn"] or dyn
            continue
        if c == "$":
            j = _dollar(src, i)
            buf.append(src[i:j])
            st["started"] = st["dyn"] = True
            i = j
            continue
        if c == "`":
            j = _skip_backtick(src, i + 1)
            buf.append(src[i:j])
            st["started"] = st["dyn"] = True
            i = j
            continue
        if c == "#":
            if st["started"]:
                buf.append(c)
                i += 1
                continue
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "\n":
            finish()
            toks.append(("op", "\n"))
            i += 1
            if pending:
                i = _skip_heredocs(src, i, pending)
                del pending[:]
            continue
        if c in " \t\r":
            finish()
            i += 1
            continue
        op = next((o for o in _ALL_OPS if src.startswith(o, i)), None)
        if op is None:                           # not reachable with today's regex; never fatal
            buf.append(c)
            st["started"] = True
            i += 1
            continue
        # ; & | ( ) < >
        if c in "<>" and st["started"] and not st["quoted"] and not st["dyn"] and "".join(buf).isdigit():
            del buf[:]                           # 2>&1, 2>/dev/null: the fd number is not a word
            st["started"] = False
        finish()
        i += len(op)
        if op in ("<<", "<<-"):
            want_delim.append(op == "<<-")
            continue
        if op in _REDIR_OPS:
            toks.append(("redir", op))
            continue
        if in_subst:
            if op == "(":
                depth += 1
            elif op == ")":
                if depth == 0:
                    finish()
                    return toks, i
                depth -= 1
        toks.append(("op", op))
    finish()
    if in_subst:
        raise ValueError("unterminated $(")
    return toks, i


def _simple_commands(src: str) -> list:
    """[(words, op_before, op_after)], words as (text, dynamic); a redirection's
    target word is dropped. "(" and ")" come through as empty commands whose
    op_after / op_before is the paren, so callers can scope a subshell."""
    toks, _ = _lex(src)
    cmds, words, prev, skip = [], [], "", False
    for tok in toks:
        if tok[0] == "w":
            if skip:
                skip = False
                continue
            words.append((tok[1], tok[2]))
        elif tok[0] == "redir":
            skip = True
        else:
            cmds.append((words, prev, tok[1]))
            words, prev, skip = [], tok[1], False
    cmds.append((words, prev, ""))
    return cmds


_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
_APPEND = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+=")
_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PIPE_OPS = ("|", "|&")
_UNCOND = (";", "\n", "")
DECLARE_CMDS = frozenset(("export", "declare", "typeset", "local", "readonly"))


def _expand(text: str, shvars: dict) -> "str | None":
    """A dynamic word's value when every expansion in it is a plain $NAME /
    ${NAME} this same command assigned a literal to (or $HOME); else None."""
    if "$(" in text or "`" in text:
        return None
    missing = []

    def sub(m) -> str:
        name = m.group(1) or m.group(2)
        val = shvars.get(name) if name in shvars else (os.path.expanduser("~") if name == "HOME" else None)
        if val is None:
            missing.append(name)
            return ""
        return val
    out = _VAR_REF.sub(sub, text)
    if missing or "$" in out:
        return None                              # unknown name, or ${X:-y} / $1 / $? ...
    return out


def _conditional(before: str, after: str) -> bool:
    """Did this command's effect on the shell depend on an earlier exit status,
    or run in a subshell (pipeline / background)?"""
    if before in _PIPE_OPS or after in _PIPE_OPS or after == "&":
        return True
    return after == "||" or (before in ("&&", "||") and after in _UNCOND)


def _cd_target(words: list, cwd: "str | None") -> "str | None":
    """Where `cd`/`pushd` leaves the shell, or None when that cannot be known."""
    args = words[1:]
    while args and args[0][0].startswith("-") and args[0][0] != "-":
        if args[0][0] == "--":
            args = args[1:]
            break
        args = args[1:]                          # -P / -L / -e / -@
    if not args:
        return os.path.normpath(os.path.expanduser("~"))
    text, dyn = args[0]
    if dyn or text == "-":
        return None                              # cd "$X", cd $(...), cd - (OLDPWD)
    return _resolve(text, cwd)


def _git_touch(words: list, cwd: "str | None", env: dict) -> "tuple[str, str] | None":
    """(kind, path) for one `git ...` simple command, or None. Where git runs is
    followed through -C, --work-tree/--git-dir and GIT_WORK_TREE/GIT_DIR; when it
    cannot be known the command is DROPPED -- attributing it to the surrounding
    cwd instead would hand this session a worktree it may never have touched."""
    gcwd, git_dir, work_tree = cwd, "GIT_DIR" in env, env.get("GIT_WORK_TREE")
    i = 1
    while i < len(words):
        a, dyn = words[i]
        if a == "-C":
            if i + 1 >= len(words):
                return None
            v, vdyn = words[i + 1]
            if vdyn:
                gcwd = None
            elif v:                              # `git -C ""` is a no-op
                gcwd = _resolve(v, gcwd)
            i += 2
            continue
        if a in ("--git-dir", "--work-tree") or a.startswith(("--git-dir=", "--work-tree=")):
            if "=" in a:
                key, val, i = a.split("=", 1)[0], (a.split("=", 1)[1], dyn), i + 1
            elif i + 1 < len(words):
                key, val, i = a, words[i + 1], i + 2
            else:
                return None
            if key == "--git-dir":
                git_dir = True
            else:
                work_tree = val
            continue
        if a in GIT_OPTS_WITH_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    if work_tree is not None:
        wt_text, wt_dyn = work_tree
        gcwd = None if wt_dyn else _resolve(wt_text, gcwd)
    elif git_dir:
        gcwd = None                              # which work tree goes with that git dir: unknown
    sub = [w[0] for w in words[i:]]
    if not sub:
        return None
    if sub[0] == "worktree" and len(sub) >= 2 and sub[1] == "add":
        j, pos = 2, []
        while j < len(sub):
            a = sub[j]
            if a == "--":
                pos.extend(words[i + j + 1:])
                break
            if a in WT_ADD_OPTS_WITH_VALUE:
                j += 2
                continue
            if a.startswith("-"):
                j += 1
                continue
            pos.append(words[i + j])
            j += 1
        if pos and not pos[0][1]:
            p = _resolve(pos[0][0], gcwd)
            if p:
                return "created", p
        return None
    if sub[0] in MUTATING_GIT and gcwd:
        return "worked", gcwd
    return None


def bash_touches(command: str, cwd: str) -> list:
    """[(kind, abs_path)] a Bash command's `git worktree add <path>` ("created")
    and mutating `git -C <dir> ...` / `cd <dir> && git ...` ("worked").

    The working directory is tracked the way the shell moves it: cd/pushd in
    the command list's own scope; a subshell's ( ... ) cd, or a cd inside a
    pipeline or a background job, does not outlive it; a cd whose effect
    depends on an earlier command's exit status (`test -d x && cd x; git ...`,
    `cd x || true; git ...`), a cd to a shell expansion, `cd -` and popd leave
    the directory UNKNOWN, and a git command run from an unknown directory is
    not attributed to anything. A $NAME is followed only when this same
    command assigned it a literal (`W=/path` then `cd "$W"`), unconditionally
    and outside a subshell; read/for/unset/NAME+=/a conditional assignment
    make it unknown (eval/source/. make every name unknown), and a
    `NAME=v cmd` prefix sets nothing afterwards."""
    out: list = []
    if not isinstance(command, str) or "git" not in command:
        return out
    try:
        return _interpret(_simple_commands(command[:MAX_COMMAND]), cwd)
    except Exception:                  # noqa: BLE001 -- one unreadable command is dropped, not the hook
        return out


def _interpret(cmds: list, cwd: str) -> list:
    out: list = []
    cur: "str | None" = cwd or None
    shvars: dict = {}              # NAME -> literal value, or None once it cannot be known
    stack: list = []
    for k, (words, before, after) in enumerate(cmds):
        # A $NAME / ${NAME} this command assigned a literal to is as good as
        # the literal; anything else stays dynamic (unknown).
        expanded = []
        for w in words:
            e = _expand(w[0], shvars) if w[1] else None
            expanded.append((e, False) if e is not None else w)
        words = expanded
        env: dict = {}
        while words:
            text, dyn = words[0]
            am = _ASSIGN.match(text)
            if am or _APPEND.match(text):
                if am:
                    env[am.group(1)] = (am.group(2), dyn)
                else:
                    env[_APPEND.match(text).group(1)] = ("", True)   # NAME+=x: not followed
                words = words[1:]
            elif text in COMMAND_PREFIXES or text in RESERVED_LEAD:
                words = words[1:]
            else:
                break
        if not words and env:
            # A bare `NAME=value` sets a shell variable (a prefix before a
            # command only sets that command's environment -- not this).
            cond = _conditional(before, after)
            for name, (val, dyn) in env.items():
                shvars[name] = None if (cond or dyn) else val
        if words:
            name = words[0][0]
            if name in DECLARE_CMDS:
                cond = _conditional(before, after)
                for text, dyn in words[1:]:
                    am = _ASSIGN.match(text)
                    if am:
                        shvars[am.group(1)] = None if (cond or dyn) else am.group(2)
                    elif _NAME.match(text) and text not in shvars:
                        shvars[text] = None
            elif name in ("eval", "source", "."):
                for known in list(shvars):       # it may re-set any of them
                    shvars[known] = None
            elif name in ("read", "unset", "mapfile", "readarray", "for", "select") or (
                    name == "printf" and len(words) > 2 and words[1][0] == "-v"):
                # They set (or clear) the names they are given to something
                # this hook cannot know.
                for text, _dyn in words[1:]:
                    if _NAME.match(text):
                        shvars[text] = None
                    if name in ("for", "select"):
                        break
            if name in ("cd", "pushd", "popd"):
                target = _cd_target(words, cur) if name != "popd" else None
                if before in _PIPE_OPS or after in _PIPE_OPS or after == "&":
                    pass                         # runs in a subshell: no effect here
                elif after == "||":
                    nxt = cmds[k + 1][0] if k + 1 < len(cmds) else []
                    cur = target if nxt and nxt[0][0] in ("exit", "return") else None
                elif before in ("&&", "||") and after in _UNCOND:
                    cur = None                   # ran only if an earlier command did
                else:
                    cur = target
            elif os.path.basename(name) == "git":
                hit = _git_touch(words, cur, env)
                if hit:
                    out.append(hit)
        if after == "(":
            stack.append((cur, dict(shvars)))
        elif after == ")" and stack:
            cur, shvars = stack.pop()
    return out


def entry_touches(rec: dict) -> list:
    """[(kind, abs_path, ts)] for one transcript record."""
    if not isinstance(rec, dict) or rec.get("type") != "assistant":
        return []
    msg = rec.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, list):
        return []
    ts = parse_ts(rec.get("timestamp"))
    cwd = rec.get("cwd") if isinstance(rec.get("cwd"), str) else ""
    out = []
    for c in content:
        if not isinstance(c, dict) or c.get("type") != "tool_use":
            continue
        name = c.get("name")
        inp = c.get("input") if isinstance(c.get("input"), dict) else {}
        if name in EDIT_TOOLS:
            for k in PATH_KEYS:
                p = _resolve(inp.get(k) if isinstance(inp.get(k), str) else "", cwd)
                if p:
                    out.append(("worked", p, ts))
        elif name == "Bash":
            for kind, p in bash_touches(inp.get("command"), cwd):
                out.append((kind, p, ts))
    return out


_SELF_PREFILTER = (b'"Edit"', b'"Write"', b'"MultiEdit"', b'"NotebookEdit"', b"git")


def iter_lines(path: str, budget: Budget, needles=None):
    """Complete lines of `path`; with `needles`, only lines containing one of
    them (whole chunks without any are skipped at memchr speed)."""
    carry = b""
    with open(path, "rb") as fh:
        while True:
            budget.check()
            chunk = fh.read(CHUNK)
            if not chunk:
                if carry and (needles is None or any(n in carry for n in needles)):
                    yield carry
                return
            buf = carry + chunk
            cut = buf.rfind(b"\n")
            if cut < 0:
                carry = buf if len(buf) < MAX_LINE else b""
                continue
            body, carry = buf[:cut], buf[cut + 1:]
            if len(carry) >= MAX_LINE:
                carry = b""
            if needles is not None and not any(n in body for n in needles):
                continue
            for ln in body.split(b"\n"):
                if needles is None or any(n in ln for n in needles):
                    yield ln


def touches_in(path: str, budget: Budget, needles=None) -> list:
    out = []
    for ln in iter_lines(path, budget, needles):
        if b'"tool_use"' not in ln:
            continue
        if needles is None and not any(n in ln for n in _SELF_PREFILTER):
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        out.extend(entry_touches(rec))
    return out


def projects_root(transcript: str) -> str:
    env = os.environ.get("HAWKEYE_WORKTREE_HYGIENE_TRANSCRIPTS_ROOT")
    if env:
        return env
    d = os.path.dirname(os.path.abspath(transcript))
    while True:
        if os.path.basename(d) == "projects":
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.path.join(os.path.expanduser("~"), ".claude", "projects")


def other_transcripts(root: str, mine: str, since: float, budget: Budget) -> list:
    """Every *.jsonl under `root` except `mine`, modified after `since`, newest first."""
    out = []
    try:
        mine_real = os.path.realpath(mine)
    except (OSError, ValueError):
        mine_real = mine
    for dp, dns, fns in os.walk(root):
        budget.check()
        dns[:] = [d for d in dns if d not in ("tool-results", "node_modules")]
        for fn in fns:
            if not fn.endswith(".jsonl"):
                continue
            p = os.path.join(dp, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mtime <= since:
                continue
            if os.path.realpath(p) == mine_real:
                continue
            out.append((st.st_mtime, p))
    out.sort(reverse=True)
    return [p for _, p in out]


def path_needles(top: str) -> list:
    forms = {top}
    try:
        forms.add(os.path.realpath(top))
    except (OSError, ValueError):
        pass
    out = []
    for f in forms:
        out.append(f.encode("utf-8", "replace"))
        esc = json.dumps(f)[1:-1].encode("utf-8", "replace")
        if esc not in out:
            out.append(esc)
    return out


# ------------------------------------------------------------ worktree state

class Tree(object):
    def __init__(self, top: str, main: str):
        self.top = top
        self.main = main
        self.created = False
        self.last = 0.0            # this transcript's most recent touch
        self.owner_other = ""      # a more recent other transcript, when one exists
        self.branch = ""
        self.head = ""
        self.status: list = []
        # Where the tree's commits are durable. remote_kind: "origin" (the rule's
        # own "origin branch"), "other" (no origin, but other remotes -- any of
        # their refs counts), "none" (no remote at all: every commit is on this
        # disk only, so what matters is whether this tree holds commits no other
        # branch or tag does), "unknown" (git could not say -- never a reason to
        # block).
        self.remote_kind = "unknown"
        self.remotes: list = []
        self.on_remote = False        # origin/other: HEAD is contained in a remote-tracking ref
        self.local_only = 0           # none: commits reachable only from this tree's HEAD/branch
        self.default_ref = ""
        self.merged = False

    @property
    def disk_only(self) -> bool:
        """HEAD carries commits that exist only on this disk."""
        if self.remote_kind in ("origin", "other"):
            return not self.on_remote
        if self.remote_kind == "none":
            return self.local_only > 0
        return False

    @property
    def push_remote(self) -> str:
        if self.remote_kind == "origin":
            return "origin"
        if self.remote_kind == "other" and len(self.remotes) == 1:
            return self.remotes[0]
        return "<remote>"


def inspect_tree(t: Tree, budget: Budget) -> bool:
    """Fill `t` from read-only git. False when git cannot answer (then the tree
    is left alone: an unknown state is never a reason to block)."""
    rc, head = git(budget, t.top, "rev-parse", "--verify", "-q", "HEAD")
    if rc != 0:
        return False
    t.head = head.strip()
    rc, br = git(budget, t.top, "symbolic-ref", "-q", "--short", "HEAD")
    t.branch = br.strip() if rc == 0 else ""
    rc, st = git(budget, t.top, "status", "--porcelain=v1", "--untracked-files=normal",
                 "--ignore-submodules=dirty")
    if rc != 0:
        return False
    t.status = sorted(ln for ln in st.splitlines() if ln.strip())
    rc, rem = git(budget, t.top, "remote")
    if rc != 0:
        return True                    # remote_kind stays "unknown": uncommitted work still counts
    t.remotes = [r for r in rem.split() if r]
    if not t.remotes:
        # No remote at all. Every commit here is on this disk only; the ones
        # that are THIS tree's work are those no other branch or tag holds.
        t.remote_kind = "none"
        args = ["rev-list", "--count", t.head, "--not"]
        if t.branch:
            args.append("--exclude=" + t.branch)
        rc, cnt = git(budget, t.top, *(args + ["--branches", "--tags"]))
        try:
            t.local_only = int(cnt.strip()) if rc == 0 else 0
        except ValueError:
            t.local_only = 0
        return True
    t.remote_kind = "origin" if "origin" in t.remotes else "other"
    names = ["origin"] if t.remote_kind == "origin" else t.remotes
    rc, refs = git(budget, t.top, "for-each-ref", "--count=1", "--contains", t.head,
                   "--format=%(refname)", *["refs/remotes/%s/" % r for r in names])
    t.on_remote = rc == 0 and bool(refs.strip())
    for r in names:
        for cand in ("HEAD", "main", "master"):
            ref = "refs/remotes/%s/%s" % (r, cand)
            rc, sha = git(budget, t.top, "rev-parse", "--verify", "-q", ref + "^{commit}")
            if rc == 0 and sha.strip():
                t.default_ref = ref
                break
        if t.default_ref:
            break
    return True


def branch_has_merged_work(t: Tree, budget: Budget) -> bool:
    """HEAD is in the default branch AND the branch did real work that got
    there -- not a fresh worktree still sitting on the commit it was cut from."""
    if not (t.branch and t.default_ref and not t.status and t.on_remote):
        return False
    rc, _ = git(budget, t.top, "merge-base", "--is-ancestor", t.head, t.default_ref)
    if rc != 0:
        return False
    rc, oldest = git(budget, t.top, "reflog", "show", "--format=%H", "refs/heads/" + t.branch, "--")
    lines = [ln.strip() for ln in oldest.splitlines() if ln.strip()] if rc == 0 else []
    if lines and lines[-1] != t.head:
        return True
    # No usable reflog: a --no-ff merge names HEAD as a non-first parent.
    rc, parents = git(budget, t.top, "log", "--merges", "--format=%P", "-n", "400", t.default_ref)
    if rc == 0:
        for ln in parents.splitlines():
            if t.head in ln.split()[1:]:
                return True
    return False


def all_worktrees(main: str, budget: Budget) -> list:
    rc, out = git(budget, main, "worktree", "list", "--porcelain")
    if rc != 0:
        return []
    res, cur = [], {}
    for ln in out.splitlines() + [""]:
        if not ln.strip():
            if cur.get("worktree"):
                res.append(cur)
            cur = {}
            continue
        k, _, v = ln.partition(" ")
        cur[k] = v if v else True
    return res


# ------------------------------------------------------------------- output

def q(p: str) -> str:
    return shlex.quote(p)


def blocking_text(blockers: list, push: bool = True) -> str:
    out = []
    for t in blockers:
        where = ("branch %s" % t.branch) if t.branch else ("detached HEAD at %s" % t.head[:12])
        out.append("  %s  [%s]" % (t.top, where))
        if t.status:
            out.append("    uncommitted: %d path(s)" % len(t.status))
            for ln in t.status[:SHOW_STATUS_LINES]:
                out.append("        " + ln)
            if len(t.status) > SHOW_STATUS_LINES:
                out.append("        ... and %d more (git -C %s status --short)" % (
                    len(t.status) - SHOW_STATUS_LINES, q(t.top)))
        if t.disk_only and t.remote_kind == "origin":
            out.append("    commits on no origin branch: HEAD %s is contained in no origin/* ref"
                       % t.head[:12])
            out.append("        (see them: git -C %s log --oneline HEAD --not --remotes=origin)" % q(t.top))
        elif t.disk_only and t.remote_kind == "other":
            out.append("    commits on no remote branch: this repo has no `origin` remote, and HEAD %s is "
                       "contained in no remote-tracking ref of %s" % (t.head[:12], ", ".join(t.remotes)))
            out.append("        (see them: git -C %s log --oneline HEAD --not --remotes)" % q(t.top))
        elif t.disk_only and t.remote_kind == "none":
            excl = ("--exclude=%s " % q(t.branch)) if t.branch else ""
            out.append("    this repository has no remote at all, so every commit in it exists only on this")
            out.append("    disk -- and %d commit(s) at HEAD %s are on no other branch or tag either"
                       % (t.local_only, t.head[:12]))
            out.append("        (see them: git -C %s log --oneline HEAD --not %s--branches --tags)" % (q(t.top), excl))
            out.append("    If this repo is deliberately local-only, say so in your reply and stop: this")
            out.append("    asks once per session for this tree, not after every commit. Otherwise ask")
            out.append("    the user where it should live, then:")
            out.append("      git -C %s remote add origin <url>" % q(t.main))
        out.append("    fix:")
        if t.status:
            out.append("      git -C %s add -A" % q(t.top))
            out.append("      python3 ~/.claude/hooks/commit_policy.py check-message --file <message file>")
            out.append("      git -C %s commit -F <message file>" % q(t.top))
        if not push:
            if t.disk_only and not t.branch:
                out.append("    commits on a detached HEAD at %s are on no branch: git gc can drop them once"
                           % t.head[:12])
                out.append("    this tree moves, so name the work before you stop:")
                out.append("      git -C %s switch -c <new-branch>" % q(t.top))
            continue
        br = t.branch
        if not br:
            br = "<new-branch>"
            out.append("      git -C %s switch -c %s     (detached: name the work first)" % (q(t.top), br))
        rem = "origin" if t.remote_kind == "none" else t.push_remote
        out.append("      git -C %s push -u %s %s" % (q(t.top), rem, q(br) if t.branch else br))
        out.append("      git -C %s fetch -q %s && git -C %s rev-parse HEAD %s/%s   "
                   "(the two must match)" % (q(t.top), rem, q(t.top), rem, q(br) if t.branch else br))
    return "\n".join(out)


def report_lines(owned: list, budget: Budget, dup_info: dict) -> list:
    out = []
    for t in owned:
        if t.merged:
            out.append("  MERGED, still on disk: %s  [branch %s is in %s]" % (
                t.top, t.branch, t.default_ref.replace("refs/remotes/", "")))
            out.append("      git -C %s worktree remove %s" % (q(t.main), q(t.top)))
            out.append("      git -C %s branch -d %s" % (q(t.main), q(t.branch)))
            rc, _ = git(budget, t.top, "rev-parse", "--verify", "-q", "refs/remotes/origin/" + t.branch)
            if rc == 0:
                out.append("      git -C %s push origin --delete %s" % (q(t.main), q(t.branch)))
        elif not t.branch and not t.status and t.on_remote:
            out.append("  LEFTOVER DETACHED worktree: %s  [at %s, nothing in it that origin lacks]"
                       % (t.top, t.head[:12]))
            out.append("      when its job is done: git -C %s worktree remove %s" % (q(t.main), q(t.top)))
        for other, why, theirs in dup_info.get(t.top, []):
            out.append("  DUPLICATE: %s and %s %s" % (t.top, other, why))
            if theirs:
                out.append("      %s is not this session's: leave it, and tell its owner if it looks abandoned"
                           % other)
            elif not t.status and t.on_remote:
                out.append("      keep one: git -C %s worktree remove %s" % (q(t.main), q(t.top)))
    return out


def duplicates(owned: list, budget: Budget, owned_tops: set) -> dict:
    res: dict = {}
    by_main: dict = {}
    for t in owned:
        by_main.setdefault(t.main, []).append(t)
    for main, trees in by_main.items():
        entries = all_worktrees(main, budget)
        for t in trees:
            for e in entries:
                p = os.path.normpath(str(e.get("worktree")))
                # The primary checkout is never "a duplicate": it is the repo.
                if p == t.top or p == os.path.normpath(main):
                    continue
                e_branch = str(e.get("branch") or "").replace("refs/heads/", "")
                e_head = str(e.get("HEAD") or "")
                detached = bool(e.get("detached")) or not e_branch
                why = ""
                if t.branch and e_branch == t.branch:
                    why = "have the same branch (%s) checked out" % t.branch
                elif e_head and e_head == t.head and (detached or not t.branch):
                    why = "sit at the same commit %s (one of them detached)" % t.head[:12]
                if why:
                    res.setdefault(t.top, []).append((p, why, p not in owned_tops))
    return res


# -------------------------------------------------------------------- state

def _key(session: str) -> str:
    return hashlib.sha256(session.encode("utf-8", "replace")).hexdigest()[:16]


def seen_before(kind: str, session: str, fp: str) -> bool:
    return os.path.isfile(os.path.join(STATE_DIR, kind, "%s-%s" % (_key(session), fp)))


def mark(kind: str, session: str, fp: str) -> bool:
    """Record that `fp` was asked/noted/reported. False when it cannot be
    recorded -- and then the caller must NOT block: a block it cannot remember
    having made is a block it would repeat on every stop."""
    try:
        d = os.path.join(STATE_DIR, kind)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "%s-%s" % (_key(session), fp)), "w", encoding="utf-8") as fh:
            fh.write(str(int(time.time())))
        return True
    except OSError:
        return False


def prune_state(budget: Budget) -> None:
    """Keep the state dir from growing forever: drop markers older than 14 days
    (bounded work per stop)."""
    cutoff = time.time() - 14 * 86400
    n = 0
    for kind in ("asked", "noted", "reported"):
        d = os.path.join(STATE_DIR, kind)
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for name in names:
            n += 1
            if n > 400 or budget.left() < 1:
                return
            p = os.path.join(d, name)
            try:
                if os.path.getmtime(p) < cutoff:
                    os.unlink(p)
            except OSError:
                pass


def fingerprint(parts: list) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(repr(p).encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()[:32]


# --------------------------------------------------------------------- main

BLOCK_HEADER = """WORK THAT EXISTS ONLY ON THIS DISK -- commit it and push it before you stop.

Rule S18 (worktree and branch hygiene): you may not end your turn while any
worktree you created or worked in has work that exists only on this disk. Every
such worktree's commits must be on an origin branch (a pending feature branch
is fine) and nothing may be left uncommitted. A session limit or a crash loses
whatever is only here.
"""

BLOCK_HEADER_COMMIT = """WORK THAT EXISTS ONLY ON THIS DISK -- commit it before you stop.

Rule S18 (worktree and branch hygiene): you may not end your turn while any
worktree you created or worked in has uncommitted changes, or commits on a
detached HEAD that no branch holds. Commit coherent,
recoverable increments; a session limit or a crash loses whatever is only in
the working tree. (Committed work is published later through deliver.py.)
"""

BLOCK_FOOTER = """
If one of these is NOT yours (another session or agent is working in it), do
not commit it -- say so and stop. Bounded, on purpose: this asks once per
distinct state per session, and never while a stop hook is already making you
continue. HARNESS_WORKTREE_GATE=off disables it; do not set it without the
user's say-so."""

REPORT_HEADER = ("Worktree cleanup (rule S18, worktree and branch hygiene: remove a worktree as "
                 "soon as its branch is merged, and delete the merged branch locally and on origin; "
                 "never remove one another session owns):")


def run(ev: dict, budget: Budget) -> "tuple[int, str, str]":
    """(exit code, stderr text, stdout text)."""
    event = ev.get("hook_event_name")
    if event not in (None, "Stop", "SubagentStop"):
        return 0, "", ""
    cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) else os.getcwd()
    if opted_out(cwd):
        return 0, "", ""
    if event == "SubagentStop" and isinstance(ev.get("agent_transcript_path"), str):
        transcript = ev.get("agent_transcript_path")
    else:
        transcript = ev.get("transcript_path")
    if not isinstance(transcript, str) or not os.path.isfile(transcript):
        return 0, "", ""
    session = str(ev.get("session_id") or "")
    if ev.get("agent_id"):
        session = "%s:%s" % (session, ev.get("agent_id"))
    session = session or os.path.realpath(transcript)
    stop_active = ev.get("stop_hook_active") is True

    roots = repos_dirs()
    trees: dict = {}
    for kind, path, ts in touches_in(transcript, budget):
        hit = linked_worktree_of(path)
        if not hit:
            continue
        top, main = hit
        if not os.path.isdir(top) or not under_any(main, roots):
            continue
        t = trees.get(top)
        if t is None:
            t = trees[top] = Tree(top, main)
        t.created = t.created or kind == "created"
        t.last = max(t.last, ts)
    if not trees:
        return 0, "", ""
    cands = sorted(trees.values(), key=lambda x: x.last, reverse=True)[:MAX_WORKTREES]

    # Ownership: a more recent touch by any other transcript hands the tree to it.
    since = min(t.last for t in cands) - 1.0
    needles_by_top = {t.top: path_needles(t.top) for t in cands}
    all_needles = [n for ns in needles_by_top.values() for n in ns]
    by_top = {t.top: t for t in cands}
    for other in other_transcripts(projects_root(transcript), transcript, since, budget):
        for kind, path, ts in touches_in(other, budget, all_needles):
            hit = linked_worktree_of(path)
            if not hit or hit[0] not in by_top:
                continue
            t = by_top[hit[0]]
            if ts > t.last and not t.owner_other:
                t.owner_other = other
    owned = [t for t in cands if not t.owner_other]
    if not owned:
        return 0, "", ""

    live = []
    for t in owned:
        if inspect_tree(t, budget):
            live.append(t)
    push = block_unpushed()
    # a detached HEAD's commits are on no branch (gc can drop them), so they block even in report-only mode
    blockers = [t for t in live if t.status or (t.disk_only and (push or not t.branch))]
    for t in live:
        if t not in blockers:
            t.merged = branch_has_merged_work(t, budget)
    owned_tops = {t.top for t in owned}
    rep = report_lines(live, budget, duplicates(live, budget, owned_tops))
    for t in live:
        if t.disk_only and not t.status and not push and t.branch:
            where = ("branch %s" % t.branch) if t.branch else ("detached HEAD at %s" % t.head[:12])
            rep.insert(0, "  UNPUSHED: %s  [%s, HEAD %s is on no %s branch]; publish it through deliver.py prepare "
                          "(or publish_feature.py) once reviewed" % (t.top, where, t.head[:12],
                                                                     "remote" if t.remote_kind != "none" else "other"))

    if blockers:
        # A no-remote tree is keyed without its HEAD: its agent cannot push, so a
        # new commit there is not a new question -- only new uncommitted work is.
        fp = fingerprint(sorted((t.top, "" if t.remote_kind == "none" else t.head, t.disk_only,
                                 tuple(t.status)) for t in blockers))
        if not stop_active and not seen_before("asked", session, fp) and mark("asked", session, fp):
            text = (BLOCK_HEADER if push else BLOCK_HEADER_COMMIT) + "\n" + blocking_text(blockers, push)
            if rep:
                text += "\n\n" + REPORT_HEADER + "\n" + "\n".join(rep)
            return 2, text + "\n" + BLOCK_FOOTER + "\n", ""
        # Already asked about exactly this, or a stop hook is already making the
        # agent continue (then it is NOT marked asked: the next ordinary stop
        # still gets its one ask). Let it stop, but tell the operator once
        # what is left behind.
        if not seen_before("noted", session, fp):
            mark("noted", session, fp)
            why = ("a stop hook is already making it continue, so not blocking" if stop_active
                   else "already asked once")
            msg = ("Stopping with work that exists only on this disk (%s): " % why
                   + "; ".join("%s%s%s" % (t.top, " uncommitted" if t.status else "",
                                           (" local-only (the repo has no remote)" if t.remote_kind == "none"
                                            else " unpushed") if t.disk_only else "")
                               for t in blockers))
            if rep:
                msg += "\n" + REPORT_HEADER + "\n" + "\n".join(rep)
            return 0, "", json.dumps({"systemMessage": msg})
        return 0, "", ""
    if rep:
        fp = fingerprint(rep)
        if not seen_before("reported", session, fp):
            mark("reported", session, fp)
            return 0, "", json.dumps({"systemMessage": REPORT_HEADER + "\n" + "\n".join(rep)})
    return 0, "", ""


def main() -> int:
    budget = Budget(budget_seconds())
    try:
        raw = safe_input.read_stdin_bounded().decode("utf-8", "replace") if not sys.stdin.isatty() else ""
        ev = safe_input.safe_json_loads(raw) if raw.strip() else {}
        if not isinstance(ev, dict):
            return 0
    except (OSError, ValueError, safe_input.InputRejected):
        return 0
    try:
        code, err, out = run(ev, budget)
    except (OutOfTime, Exception):     # noqa: BLE001 -- fail OPEN, always
        return 0
    try:
        prune_state(budget)
    except Exception:                  # noqa: BLE001
        pass
    if out:
        sys.stdout.write(out + "\n")
    if err:
        sys.stderr.write(err)
    return code


if __name__ == "__main__":
    sys.exit(main())
