#!/usr/bin/env python3
"""Merge gate (GoodQA #14502, matrix D11): a PreToolUse hook that blocks PR merges unless every required and every
reported check run and commit status on the exact head SHA concluded success.

Why: an owner merged netwatch PR #1 while staticcheck and Windows vet were red. Nothing in the harness looked at CI.

What it covers: `gh pr merge`, `gh api` REST pulls/N/merge, GraphQL mergePullRequest / enablePullRequestAutoMerge,
curl or interpreter calls to the same endpoints, wrapped in sh -c, bash -c, ssh, eval, xargs, env, timeout, sudo,
subshells and so on. Merges that cannot be tied to one PR (branch-merge endpoints, hidden queries, xargs targets,
dynamic targets) are blocked and no waiver can attach to them.

Policy decisions (docs/operations.md, "Merge gate"):
  * every check run and status must be success; the allowlist is explicit, unknown conclusions block.
  * neutral and skipped are accepted only for checks that are NOT required; a required check must be success.
  * the required set is the union of branch protection (base branch), rulesets and `gh pr checks --required`, and it
    must be known. When `gh pr checks --required` is the only readable source the PR must also report
    mergeStateStatus CLEAN or HAS_HOOKS, because that source only lists checks that already reported.
  * zero reported checks block unless no ACTIVE workflow can run on the head (GitHub CI switched off): workflow files
    are read at the PR base and the verified head, new files at the head are classified too, unknown means capable.
  * the merge command must carry the verified full head SHA (--match-head-commit, REST sha, GraphQL expectedHeadOid),
    so GitHub itself refuses a head that moved after the check.
  * waiver: `waive` records repo, PR, head, ticket, reason and approver; it is single use, expires in 24 hours and is
    audited. The log is hash-chained: tamper-evident, not authenticated (same-user trust).
Everything it cannot determine blocks (exit 2). Exit 1 (a traceback) is allowed by both agents, so every fault in the
hook ends in exit 2 for commands that mention gh, merge, an HTTP client or the state files.

Stdlib only, Python 3.9.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import safe_input  # noqa: E402
except Exception as _import_error:  # a broken install must block a merge, not crash with exit 1 (= allow)
    if sys.argv[1:2] == ["hook"]:
        sys.stderr.write("merge-gate: cannot load its helper module (" + type(_import_error).__name__ + "); blocking.\n")
        sys.exit(2)
    raise

CALL_TIMEOUT_MAX = 10.0
CALL_TIMEOUT_DEFAULT = 8.0
DEADLINE_SECONDS = 40.0
MAX_COMMAND_CHARS = 200_000
MAX_TOKENS = 5_000
MAX_DEPTH = 5
MAX_STDIN_BYTES = 8 * 1024 * 1024
MAX_GH_OUTPUT = 4 * 1024 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_REASONS = 20
WAIVER_TTL_SECONDS = 24 * 3600
# The waive stamp is minted in PreToolUse, before the command runs. The hook refuses to mint for anything the shell
# could run differently (see _stamp_waive), but it cannot see what happens after it allows the command: the user can
# deny the permission prompt, or a later PreToolUse hook can block it. Such a stamp stays unconsumed, and an identical
# waive (same repo, PR, head and ticket) run by another route within this TTL is recorded as hook-approved. That is
# a provenance error bounded to this TTL, not a merge bypass (goodqa#15684; authority itself is goodqa#15732).
STAMP_TTL_SECONDS = 120
WAIVER_FILE = "merge-gate-waivers.jsonl"
WAIVER_HEAD_FILE = "merge-gate-waivers.head"
AUDIT_FILE = "merge-gate-audit.jsonl"
APPROVALS_DIR = "merge-gate-approvals"
LOCK_FILE = "merge-gate.lock"
ZERO = "0" * 64
NONREQUIRED_OK = {"SKIPPED", "NEUTRAL"}
CLEAN_STATES = {"CLEAN", "HAS_HOOKS"}

SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;", "<", ">", ">>", "<<", "<<<", ">&", "&>"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"}
INTERPRETERS = re.compile(r"^(python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php|lua|osascript)$")
HTTP_CLIENTS = re.compile(r"^(curl|wget|http|https|httpie|nc|ncat|openssl)$")
SHELL_TOOLS = {"bash", "shell", "local_shell", "exec_command", "unified_exec", "write_stdin", "container.exec",
               "powershell"}
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "apply_patch"}
# Things that run a string as a command; if one is present next to a merge string we cannot see the real command.
RAW_MERGE = re.compile(
    r"\bpr\s+merge\b|pulls/[^/\s]+/merge\b|mergePullRequest|enablePullRequestAutoMerge|enqueuePullRequest|"
    r"mergeBranch|/repos/[\w.-]+/[\w.-]+/merges\b|\balias\s+(?:set|import)\b[^\n]*--shell", re.I)
# Commands that only print, search or record text: a merge string that is merely an argument of one of these
# (a commit message, a grep pattern) is not a merge. Not exempt when piped into a shell or other executor.
DATA_COMMANDS = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "head", "tail", "wc", "ls",
                 "less", "more", "diff", "pytest", "py.test", "tee", "file", "stat", "basename", "dirname"}
EXEC_CONSUMERS = SHELLS | {"eval", "source", ".", "parallel", "env", "sudo", "su", "watch", "ssh"}
WRAPPER_WORDS = {"env", "command", "sudo", "time", "nohup", "nice", "exec", "builtin", "stdbuf", "timeout", "doas",
                 "setsid", "ionice"}
MERGE_HINT = re.compile(r"\bgh\b|merge|pulls|graphql|api\.github", re.I)
DYNAMIC_WORD = re.compile(r"^(?:\$|\$\w+|\$\{[^}]*\}\w*)$")  # a command word that is only a variable or substitution
GH_HINT = re.compile(r"\bgh\b|merge|curl|wget|\bhttps?\b|python|node|perl|ruby|ssh|eval|graphql|pulls|api\.github", re.I)
STATE_NAMES = re.compile(r"merge-gate[-/](?:waivers|audit|approvals)|main-stamps", re.I)
# #134 red-team P2: the peer_review run that mints a merge authorization (pr stage with a GitHub binding)
# any option order (B2): `peer_review.py --github-repo o/r --pr 5 pr ...` binds as well
PEER_REVIEW_AUTH = re.compile(r"peer_review(?:\.py)?\b[^\n;&|]*\s--(?:github-repo|pr)\b")
STATE_GLOB = re.compile(r"merge-gate-[wa*?\[]", re.I)  # subagents: globs and split spellings of the state files
WAIVE_CMD = re.compile(r"merge_gate(?:\.py)?['\"]?\s+(?:--\S+\s+\S+\s+)*waive\b")
WAIVE_ANY = re.compile(r"waive|add_waiver|consume_waiver|put_stamp|take_stamp", re.I)
GRAPHQL_MERGE = re.compile(r"mergePullRequest|enablePullRequestAutoMerge|enqueuePullRequest", re.I)
REST_MERGE = re.compile(r"(?:repos/([^/\s'\"]+)/([^/\s'\"]+)/)?pulls/(\d+)/merge\b")
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def repo_key(value):
    """The comparable identity of a GitHub owner/repo, or None. GitHub names are ASCII and case-insensitive
    (GoodQA #15565), so only A-Z fold; str.lower()/casefold() would map KELVIN SIGN to 'k' or SHARP S to 'ss'
    and let a different name compare equal, so any non-ASCII or malformed value has no identity at all."""
    if not isinstance(value, str) or not REPO_NAME.fullmatch(value):
        return None
    return value.translate(ASCII_LOWER)


VALUE_FLAGS = {"-R", "--repo", "--match-head-commit", "-b", "--body", "-F", "--body-file", "-t", "--subject",
               "-A", "--author-email", "-X", "--method", "-H", "--header", "-f", "--raw-field", "--field", "-q",
               "--jq", "--input", "--hostname", "--cache", "-p", "--preview", "--template"}
SHORT_VALUE = ("-R", "-X", "-f", "-F", "-H", "-b", "-t", "-A", "-q", "-p")


class GateError(Exception):
    """The gate could not determine something; the merge blocks."""


class Corrupt(Exception):
    """The waiver log failed its integrity check; no waiver is honoured."""


class Merge:
    def __init__(self, kind, **kw):
        self.kind = kind  # pr_merge | rest | graphql | unverifiable | check
        self.slug = kw.get("slug")
        self.number = kw.get("number")
        self.target = kw.get("target")
        self.head_vals = kw.get("head_vals", [])
        self.head_unknown = kw.get("head_unknown", False)
        self.node_ids = kw.get("node_ids", [])
        self.auto = kw.get("auto", False)
        self.repo_ok = kw.get("repo_ok", True)
        self.reason = kw.get("reason", "")
        self.binding = kw.get("binding", "--match-head-commit <full head sha>")

    def key(self):
        return (self.kind, self.slug, self.number, self.target, tuple(self.head_vals), self.head_unknown,
                tuple(self.node_ids), self.auto, self.repo_ok, self.reason)


def clean(text, limit=80):
    text = CTRL.sub("?", str(text))
    return text if len(text) <= limit else text[:limit - 3] + "..."


# ---------------------------------------------------------------------------------------------------- detection

def _strip_comments(text):
    """Remove shell comments (an unquoted # at a word start) so flags written in a comment are not credited to the
    command. Quote aware; leaves the newline. An unbalanced quote leaves the rest untouched."""
    out, quote, i, n = [], None, 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c == "\\" and i + 1 < n:
            out.append(c + text[i + 1])
            i += 1
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|()"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def tokenize(text):
    """(tokens, crude). shlex with punctuation splitting; unquoted newlines become ';'; a crude scan when quoting is
    unbalanced (heredocs)."""
    text = _strip_comments(text.replace("`", " $( "))
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = []
        for t in lex:
            if "\n" in t:
                rest = t.replace("\n", "")
                if rest:
                    tokens.append(rest)
                tokens.append(";")
            else:
                tokens.append(t)
        return tokens, False
    except ValueError:
        crude = re.sub(r"['\"`]", " ", text)
        crude = re.sub(r"([;&|()<>])", r" \1 ", crude).replace("\n", " ; ")
        return crude.split(), True


def _ends(tokens):
    """ends[i] = index of the first separator at or after i (len(tokens) when none); one pass."""
    n = len(tokens)
    ends, nxt = [n] * (n + 1), n
    for i in range(n - 1, -1, -1):
        if tokens[i] in SEPARATORS:
            nxt = i
        ends[i] = nxt
    return ends


def _command_word(seg):
    """Basename of the command a segment runs: skips assignments, wrappers and their options."""
    i = 0
    while i < len(seg):
        t = seg[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in ("!", "{", "}"):
            i += 1
        elif os.path.basename(t) in WRAPPER_WORDS or t.startswith("-") or re.match(r"^\d+[smhd]?$", t):
            i += 1
        else:
            return os.path.basename(t)
    return ""


def _strip_heredocs(tokens):
    """Drop the body of a heredoc whose consumer only stores or prints text (cat, git commit -F -, tee)."""
    out, i, n = [], 0, len(tokens)
    while i < n:
        t = tokens[i]
        if t in ("<<", "<<-") and i + 1 < n:
            seg_start = len(out)
            while seg_start > 0 and out[seg_start - 1] not in (";", "&&", "||", "|", "&", "(", ")"):
                seg_start -= 1
            word = _command_word(out[seg_start:])
            delim = tokens[i + 1]
            k = i + 2
            while k < n and tokens[k] != delim:
                k += 1
            line_end = i + 2
            while line_end < n and tokens[line_end] not in (";", "&&", "||"):
                line_end += 1
            tail = tokens[i + 2:line_end]
            piped_on = [os.path.basename(x) for j, x in enumerate(tail) if j and tail[j - 1] in ("|", "|&")]
            if any(w in SHELLS or w in ("eval", "source", ".", "xargs", "sudo", "env") or INTERPRETERS.match(w)
                   for w in piped_on):
                out.append(t)
                i += 1
                continue
            if word not in SHELLS and word not in ("eval", "source", ".", "xargs") and not INTERPRETERS.match(word):
                out.extend((t, delim))
                i = k + 1
                continue
        out.append(t)
        i += 1
    return out


LITERAL_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=([^$`\s;&|()<>{}'\"\\]*)$")
ANY_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=")
VAR_TOKEN = re.compile(r"^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})$")
OPENERS, CLOSERS = {"if", "while", "until", "for", "select", "case", "{", "("}, {"fi", "done", "esac", "}", ")"}
REASSIGNERS = {"for", "select"}
# Builtins that can assign a name, often through a glued flag (printf -vX, read -aX, declare -n R=X) or a deferred
# string (trap): any of them makes every name unknown, like eval and source (goodqa#15122 fixture red-team F1).
OPAQUE_ASSIGNERS = {"eval", "source", ".", "read", "mapfile", "readarray", "declare", "typeset", "local", "let",
                    "getopts", "printf", "unset", "export", "readonly", "trap", "coproc", "wait"}


def _literal_assignments(tokens):
    """{name: [(token index, value)]} for a NAME=literal that is a statement of its own at top level (start of the
    command or after ';', never inside a group, loop, branch, function, pipeline or && / || list). A name assigned any
    other way (substitution, prefix assignment, read, loop variable, unset) maps to None. eval, source or a dot
    command, or any other builtin that can assign (OPAQUE_ASSIGNERS), anywhere make every name unknown. goodqa#15122
    AC-3."""
    out = {}
    if any(os.path.basename(t) in OPAQUE_ASSIGNERS for t in tokens):
        return out
    depth = 0
    for i, t in enumerate(tokens):
        if t in OPENERS:
            depth += 1
        elif t in CLOSERS:
            depth -= 1
        m = ANY_ASSIGN.match(t)
        if m:
            name = m.group(1)
            lit = LITERAL_ASSIGN.match(t)
            k = i - 1
            while k >= 0 and tokens[k] not in SEPARATORS and ANY_ASSIGN.match(tokens[k]):
                k -= 1
            j = i + 1
            while j < len(tokens) and tokens[j] not in SEPARATORS and ANY_ASSIGN.match(tokens[j]):
                j += 1
            before = tokens[k] if k >= 0 else ";"
            after = tokens[j] if j < len(tokens) else ";"
            standalone = lit and depth == 0 and before == ";" and after == ";" and "=" not in t[len(name) + 1:]
            if standalone and out.get(name, []) is not None:
                out.setdefault(name, []).append((i, lit.group(2)))
            else:
                out[name] = None
        elif os.path.basename(t) in REASSIGNERS:
            for x in tokens[i + 1:i + 16]:
                if x in SEPARATORS:
                    break
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", x):
                    out[x] = None
    return out


def _resolve(token, index, assigns):
    """The literal value of a whole-token $NAME / ${NAME} assigned exactly once, before `index`, by a top-level
    statement of the same command; None when it cannot be known."""
    m = VAR_TOKEN.match(token)
    if not m or not assigns:
        return None
    entries = assigns.get(m.group(1) or m.group(2))
    if not entries or len(entries) != 1 or entries[0][0] >= index:
        return None
    return entries[0][1]


GIT_VALUE_GLOBALS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
# git subcommands that never run another program from their arguments: a token named gh there is a remote, branch
# or path (goodqa#15122 AC-4). Others (submodule foreach, bisect run, rebase --exec, alias) keep the gh scan.
GIT_PLAIN = {"push", "fetch", "pull", "remote", "ls-remote", "clone", "branch", "checkout", "switch", "log", "show",
             "diff", "status", "tag", "rev-parse", "rev-list", "merge-base", "add", "commit", "restore", "worktree"}


def _git_subcommand(seg):
    """(index, name) of the git subcommand in a segment whose command word is git, else (None, None)."""
    i = next((j for j, t in enumerate(seg) if os.path.basename(t) == "git"), None)
    if i is None:
        return None, None
    i += 1
    while i < len(seg):
        if seg[i] in GIT_VALUE_GLOBALS:
            i += 2
        elif seg[i].startswith("-"):
            i += 1
        else:
            return i, seg[i]
    return None, None


PUSH_VALUE_FLAGS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
DEFAULT_BRANCHES = {"main", "master"}


PUSH_CONFIG = re.compile(r"^(?:alias\.|remote\.[^=]*\.push(?:=|$)|push\.|branch\.[^=]*\.(?:merge|remote|pushremote)(?:=|$))",
                         re.I)


def _git_push_to_default(seg, start, assigns, appended=False):
    """True for a `git push` that names main or master as a destination, pushes every branch, or names a destination
    the hook cannot read: that is a merge without a pull request (goodqa#15122 NEG-4). A push to any other named
    branch is not a merge (AC-4). `seg` starts at the git token, `start` is its index in the full token list."""
    for j, t in enumerate(seg[:-1]):
        if t == "--config-env" or (t == "-c" and PUSH_CONFIG.match(seg[j + 1].lstrip("'\""))):
            return True  # a git alias or push setting given on the command line can push anywhere (red-team F2)
    k, sub = _git_subcommand(seg)
    if sub != "push":
        return False
    if appended:
        return True  # xargs / parallel append the refspecs at run time
    pos, deleting, k = [], False, k + 1
    while k < len(seg):
        t = seg[k]
        if t in ("--all", "--mirror", "--branches"):
            return True
        if t in ("-d", "--delete"):
            deleting = True
        elif t in PUSH_VALUE_FLAGS:
            k += 1
        elif t.startswith("--repo="):
            pass
        elif not t.startswith("-"):
            pos.append(_resolve(t, start + k, assigns) or t)
        k += 1
    for spec in pos[1:]:
        dest = spec.rsplit(":", 1)[-1] if ":" in spec else spec
        dest = dest.lstrip("+")
        for prefix in ("refs/", "heads/"):
            if dest.startswith(prefix):
                dest = dest[len(prefix):]  # git also reads heads/main as refs/heads/main (red-team F2)
        if re.search(r"[$`*?\[]", dest) or dest in DEFAULT_BRANCHES or (deleting and spec.lstrip("+") in DEFAULT_BRANCHES):
            return True
    return False


# rg --pre, ack --pager, less/more and pytest can run programs; they are not free text here.
FREE_TEXT_COMMANDS = (DATA_COMMANDS - {"less", "more", "pytest", "py.test", "rg", "ag", "ack"}) | \
    {"cd", "true", "test", "[", "pwd", "date"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"}
REDIRECTS = {"<", ">", ">>", "<<", "<<-", "<<<", ">&", "&>", ">|", "<&", "<>"}
SPLITTERS = {";", "&&", "||", "|", "|&", "&", "(", ")", ";;"}
# gh subcommands whose verbs only read or post text; --web/-w (a browser) is refused separately
GH_TEXT = {"issue": {"comment", "create", "view", "list", "edit", "close", "reopen"},
           "pr": {"comment", "create", "view", "list", "edit", "checks", "diff", "review", "close", "ready"},
           "api": None, "search": None}
SAFE_GIT_CONFIG = {"core.hookspath=/dev/null"}
SAFE_GIT_GLOBALS = {"--no-pager", "-P"}
# subcommands that can run hooks (githooks(5): commit hooks, post-index-change, reference-transaction): free text only
# with core.hooksPath=/dev/null (Opus-xhigh delta review N2)
GIT_HOOKED = {"commit", "add", "status", "branch", "tag"}
# options whose next word is taken as text, even when it starts with '-' (a quoted "$( )" body is safe there)
TEXT_VALUE_FLAGS = {"--body", "-b", "--title", "-t", "--message", "-m", "--note", "--subject"}
_LOG_LONG = {"--no-ext-diff", "--no-textconv", "--oneline", "--stat", "--name-only", "--name-status", "--format", "--pretty", "--grep", "--author",
             "--since", "--until", "--all", "--graph", "--decorate", "--reverse", "--first-parent", "--max-count",
             "--follow", "--date", "--merges", "--no-merges", "--patch", "--abbrev-commit", "--no-color", "--numstat",
             "--shortstat", "--invert-grep", "--all-match", "--fixed-strings", "--regexp-ignore-case"}
# Per git subcommand: (exact long options, short flags without a value, short flags that take the rest as value).
# Anything else (abbreviated or unknown long options, other short flags) is not free text: git accepts unambiguous
# abbreviations and joined short flags, so a deny-list cannot be complete (goodqa#15122 Opus-high review F1/F2).
GIT_OPTIONS = {
    "commit": ({"--message", "--file", "--quiet", "--signoff", "--allow-empty", "--no-edit"}, "aqsv", "mF"),
    "log": (_LOG_LONG, "pqs", "nSG"),
    "show": (_LOG_LONG, "pqs", "nSG"),
    "diff": ({"--stat", "--name-only", "--name-status", "--cached", "--staged", "--numstat", "--shortstat",
              "--no-color", "--word-diff", "--unified", "--exit-code", "--quiet", "--check", "--no-ext-diff",
              "--no-textconv"}, "pqsuwRb", "U"),
    "status": ({"--short", "--branch", "--porcelain", "--untracked-files", "--ignored"}, "sbz", "u"),
    "add": ({"--all", "--update", "--verbose", "--dry-run", "--intent-to-add"}, "Anuv", ""),
    "grep": ({"--line-number", "--ignore-case", "--files-with-matches", "--count", "--word-regexp",
              "--extended-regexp", "--fixed-strings", "--cached", "--untracked", "--no-index", "--heading", "--break",
              "--quiet", "--invert-match", "--all-match", "--max-depth", "--line-regexp"}, "nilcwEFhHIvqx", "e"),
    "rev-parse": ({"--abbrev-ref", "--show-toplevel", "--verify", "--short", "--git-dir", "--is-inside-work-tree",
                   "--symbolic-full-name"}, "q", ""),
    "branch": ({"--list", "--contains", "--merged", "--no-merged", "--all", "--remotes", "--show-current", "--sort",
                "--format", "--verbose"}, "alrv", ""),
    "tag": ({"--list", "--contains", "--points-at", "--sort", "--format"}, "l", "n"),
}


def _git_args_ok(sub, args):
    """Every option of a git subcommand is on its allow-list; positional words (paths, revisions, patterns) are text."""
    longs, flags, valued = GIT_OPTIONS[sub]
    for t in args:
        if t == "--":
            return True  # the rest are paths
        if t.startswith("--"):
            if t.split("=", 1)[0] not in longs:
                return False
        elif t.startswith("-") and len(t) > 1:
            for j, c in enumerate(t[1:]):
                if c in valued:
                    break  # the rest of the word is the value
                if c not in flags:
                    return False
    return True
HOOK_SCRIPT = re.compile(r"^(?:~|%s)/\.claude/hooks/(?:wal_note|ah|commit_policy|provenance|spec_flow)\.py$"
                         % re.escape(str(Path.home())))
# assignments that change which program runs or what it loads
ENV_RISKY = re.compile(r"^(?:HOME|PATH|ENV|BASH_ENV|IFS|CDPATH|PYTHON\w*|LD_\w+|DYLD_\w+|GIT_\w+|GH_\w+|PAGER|EDITOR|"
                       r"VISUAL|SHELLOPTS|BASHOPTS|PS4|PROMPT_COMMAND|XDG_CONFIG_HOME)\+?=")
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "<>"}


def _waiver_text(text):
    plain = re.sub(r"[\"'\\$]", "", text)
    return "merge_gate" in plain.lower() and bool(WAIVE_ANY.search(plain))


def _simple_commands(tokens, writes=None):
    """Split on separators that start a new command; drop each redirection operator with its target word. A redirect
    whose target is a separator (process substitution) yields an unknown command; `writes` collects file targets."""
    out, cur, i = [], [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in SPLITTERS:
            out.append(cur)
            cur = []
        elif t in REDIRECTS:
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if target in SPLITTERS or not target:
                out.append(["<process-substitution>"])
            elif writes is not None and (t in WRITE_REDIRECTS or (t == ">&" and not target.isdigit())):
                writes.append(target)
            i += 1
        elif re.match(r"^\d+$", t) and i + 1 < len(tokens) and tokens[i + 1] in REDIRECTS:
            pass
        elif re.match(r"^[;&|()<>]+$", t):
            out.append(["<operator %s>" % t])  # an operator run the splitter does not know (>( or <( substitution)
        else:
            cur.append(t)
        i += 1
    out.append(cur)
    return [c for c in out if c]


def _free_text(words):
    """True when a simple command can only print, search or record text: it runs no code given in its arguments."""
    i = 0
    while i < len(words) and (words[i] in KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i])):
        i += 1
    if i == len(words):
        return True  # assignments only (their values are checked for substitutions by the caller)
    word, rest = words[i], words[i + 1:]
    if word == "printf" and any(t.startswith("-v") for t in rest):
        return False  # printf -v assigns a variable (HOME, PATH)
    if "/" not in word and word in FREE_TEXT_COMMANDS:
        return True
    if word in ("git", "gh") and not _literal_args(rest):
        return False  # a word the shell builds at run time can become an option (delta review N1)
    if word == "gh":
        if any(t.startswith("--web") or (t.startswith("-") and not t.startswith("--") and "w" in t) for t in rest):
            return False  # opens a browser (also joined short flags such as -cw, delta review N3)
        plain = [t for t in rest if not t.startswith("-")]
        if not plain or plain[0] not in GH_TEXT:
            return False
        verbs = GH_TEXT[plain[0]]
        return verbs is None or (len(plain) > 1 and plain[1] in verbs)
    if word == "git":
        k, hooks_off = 0, False
        while k < len(rest) and rest[k].startswith("-"):
            if rest[k] == "-c" and k + 1 < len(rest) and rest[k + 1].lower() in SAFE_GIT_CONFIG:
                hooks_off, k = True, k + 2
            elif rest[k] in SAFE_GIT_GLOBALS:
                k += 1
            else:
                return False  # other -c settings and -C (another repository's config) are not free text
        if k >= len(rest) or rest[k] not in GIT_OPTIONS:
            return False
        if rest[k] in GIT_HOOKED and not hooks_off:
            return False  # hooks are programs; these subcommands are free text only with core.hooksPath=/dev/null
        return _git_args_ok(rest[k], rest[k + 1:])
    if word in ("python3", "python"):
        return bool(rest) and bool(HOOK_SCRIPT.match(rest[0]))
    return False


def _literal_args(args):
    """No argument word of git or gh may be built at run time: a word starting with '$' (a variable or substitution
    that can expand to an option) is allowed only as the value of a text option such as --body; the caller refuses
    unquoted $ and globs in the raw command."""
    for j, t in enumerate(args):
        if t.startswith("$") and not (j and args[j - 1] in TEXT_VALUE_FLAGS and t.startswith("$(")):
            return False
    return True


def _unquoted_expansion(text):
    """True when the raw command has a $, glob or brace character outside quotes: its expansion is split into words
    that the hook cannot see (delta review N1; main's closure check: {--output=/f,--oneline} is brace expansion)."""
    state, i = None, 0
    while i < len(text):
        c = text[i]
        if c == "\\" and state != "'":
            i += 2
            continue
        if state is None:
            if c in "'\"":
                state = c
            elif c in "$*?[{}":
                return True
        elif c == state:
            state = None
        i += 1
    return False


def _substitutions(token):
    """The text of each $( ) or backtick substitution inside one token (tokenize turns backticks into $( )."""
    out, start = [], token.find("$(")
    while start != -1:
        end = token.rfind(")")
        out.append(token[start + 2:end if end > start else len(token)])
        start = token.find("$(", end if end > start else len(token))
    return out


def _waiver_attempt(command, _depth=0):
    """True when the command can run merge_gate's exception record. A subagent command that names merge_gate and an
    exception word is allowed only when every simple command in it is a known free-text form (print, search, git
    commit/log, a gh issue/pr body, the harness's own note and ticket helpers) and every $( )
    substitution inside it is free text too. Anything else keeps the old text rule (goodqa#15122 AC-2, NEG-1;
    fixture red-team F4: a deny-list of code runners missed awk, sed, find -exec, make and git aliases)."""
    if not _waiver_text(command):
        return False
    if _depth > MAX_DEPTH:
        return True
    tokens, crude = tokenize(command.replace("\\\n", ""))
    if crude or len(tokens) > MAX_TOKENS:
        return True
    tokens = _strip_heredocs(tokens)
    if any(t == "$" for t in tokens):
        return True  # an unquoted $( ) substitution
    if any(ENV_RISKY.match(t) for t in tokens):
        return True  # HOME, PATH, PYTHONPATH and the like change which code a free-text form runs
    writes = []
    commands = _simple_commands(tokens, writes)
    # any git or python word, also after if/while/then (review F1: _command_word does not skip keywords)
    runs_code = any(os.path.basename(t) in ("git", "python3", "python") for w in commands for t in w)
    if any(os.path.basename(t) in ("git", "gh") for w in commands for t in w) and \
            _unquoted_expansion(_strip_comments(command)):
        return True  # unquoted $ or glob next to git or gh: run-time words can become options (delta review N1)
    if runs_code and (writes or any(os.path.basename(t) == "tee" for w in commands for t in w)):
        return True  # a file written next to a git or python run could be the hook or script that runs
    for words in commands:
        if not _free_text(words):
            return True
        for t in words:
            if any(_waiver_attempt(inner, _depth + 1) or not _plain_text(inner, _depth + 1) for inner in _substitutions(t)):
                return True
    return False


def _plain_text(text, depth):
    """A substitution body that is itself only free-text commands (even when it does not name merge_gate)."""
    if depth > MAX_DEPTH:
        return False
    tokens, crude = tokenize(text.replace("\\\n", ""))
    if crude or any(t == "$" for t in tokens):
        return False
    tokens = _strip_heredocs(tokens)
    return all(_free_text(w) and all(_plain_text(i, depth + 1) for t in w for i in _substitutions(t))
               for w in _simple_commands(tokens))


def _read_small(path, cwd):
    if not cwd:
        raise GateError("no working directory to resolve a query file")
    target = path if os.path.isabs(path) else os.path.join(cwd, path)
    try:
        return safe_input.read_bounded(target, 1 << 20).decode("utf-8", "replace")
    except (safe_input.InputRejected, OSError):
        raise GateError("query file cannot be read")


def _parse_gh_args(args):
    pos, flags, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos.extend(args[i + 1:])
            break
        if a.startswith("--") and "=" in a:
            name, value = a.split("=", 1)
            flags.append((name, value))
        elif a.startswith("-") and len(a) > 1:
            if a in VALUE_FLAGS:
                flags.append((a, args[i + 1] if i + 1 < len(args) else ""))
                i += 1
            elif not a.startswith("--") and len(a) > 2:
                # a cluster such as -sR other/repo or -fsha=...: letters up to the first value flag are booleans
                for pos_in, c in enumerate(a[1:], 1):
                    if "-" + c in SHORT_VALUE:
                        rest = a[pos_in + 1:]
                        if rest:
                            flags.append(("-" + c, rest))
                        else:
                            flags.append(("-" + c, args[i + 1] if i + 1 < len(args) else ""))
                            i += 1
                        break
                    flags.append(("-" + c, None))
                else:
                    pass
            else:
                flags.append((a, None))
        else:
            pos.append(a)
        i += 1
    return pos, flags


def _flag_values(flags, *names):
    return [v for n, v in flags if n in names and v is not None]


def _gh_merge(args, in_xargs, ctx, cwd):
    pos, flags = _parse_gh_args(args)
    if not pos:
        return []
    words = pos[:2] if pos[0] == "pr" else pos[:1]
    if any(not re.match(r"^[a-z][a-z0-9_-]*$", p) for p in words):
        # goodqa#15122 AC-3: a subcommand word assigned once from a literal in the same command is read as that word.
        # A merge reached that way stays unverifiable (NEG-3): only reads are let through.
        assigns, start = ctx.get("assigns"), ctx.get("args_index", 0)
        resolved = [(_resolve(t, start + j, assigns) or t) for j, t in enumerate(args)]
        if resolved != list(args):
            rpos, _ = _parse_gh_args(resolved)
            rwords = rpos[:2] if rpos and rpos[0] == "pr" else rpos[:1]
            if rpos and all(re.match(r"^[a-z][a-z0-9_-]*$", p) for p in rwords) and \
                    not _gh_merge(resolved, in_xargs, dict(ctx, assigns=None), cwd):
                return []
        return [Merge("unverifiable", reason="gh subcommand is built at runtime")]
    names = {n for n, _ in flags}
    repo_ok = ctx["implicit_ok"]
    if "--help" in names or "-h" in names:
        return []
    if pos[0] == "alias" and len(pos) > 1 and pos[1] in ("set", "import"):
        if pos[1] == "import" or "--shell" in names or re.search(
                r"merge|\$|`", " ".join(pos[2:] + [v for _, v in flags if v]), re.I):
            return [Merge("unverifiable", reason="gh alias that can expand to a merge")]
        return []
    if pos[0] == "pr" and len(pos) > 1 and pos[1] == "merge":
        if "--disable-auto" in names:
            return []
        if in_xargs:
            return [Merge("unverifiable", reason="xargs supplies the merge target at run time")]
        target = pos[2] if len(pos) > 2 else None
        if target and ("$" in target or "`" in target or target.startswith("-")):
            return [Merge("unverifiable", reason="merge target is built at runtime; use a literal number or URL")]
        slug = number = None
        repo_flag = _flag_values(flags, "-R", "--repo")
        if repo_flag:
            slug = repo_flag[-1]
        if target:
            m = re.match(r"^https://github\.com/([\w.-]+)/([\w.-]+)/pull/(\d+)/?$", target)
            if m:
                slug, number = m.group(1) + "/" + m.group(2), m.group(3)
            elif target.isascii() and target.isdigit():
                number = target
        explicit = slug is not None
        return [Merge("pr_merge", slug=slug, number=number, target=None if number else target,
                      head_vals=[v.lower() for v in _flag_values(flags, "--match-head-commit")],
                      auto="--auto" in names, repo_ok=explicit or repo_ok,
                      binding="--match-head-commit <full head sha>")]
    if pos[0] == "api" and len(pos) > 1:
        endpoint = re.sub(r"^https?://[^/]+/", "", pos[1]).lstrip("/")
        method = (_flag_values(flags, "-X", "--method") or [""])[-1].upper()
        fields = _flag_values(flags, "-f", "-F", "--field", "--raw-field")
        has_body = bool(fields) or "--input" in names
        method = method or ("POST" if has_body else "GET")
        if endpoint.startswith("graphql"):
            return _graphql_merge(flags, pos[2:], fields, cwd, ctx.get("command"))
        if method == "GET":
            return []
        last = endpoint.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        if re.search(r"[$`]", last) or (re.search(r"[$`]", endpoint) and last == "merge"):
            return [Merge("unverifiable", reason="the gh api endpoint is built at run time and the method writes")]
        m = re.match(r"^repos/([^/]+)/([^/]+)/pulls/(\d+)/merge/?(?:\?.*)?$", endpoint)
        if m:
            slug = None if "{" in m.group(1) or "{" in m.group(2) else m.group(1) + "/" + m.group(2)
            shas = [f.split("=", 1)[1].lower() for f in fields if f.startswith("sha=")]
            return [Merge("rest", slug=slug, number=m.group(3), head_vals=shas, head_unknown="--input" in names,
                          repo_ok=slug is not None or repo_ok, binding="-f sha=<full head sha>")]
        if re.match(r"^repos/[^/]+/[^/]+/merges/?$", endpoint):
            return [Merge("unverifiable", reason="the branch merge endpoint has no pull request to check")]
    return []


def _graphql_merge(flags, rest, fields, cwd, ctx_command=None):
    text = " ".join(rest + [v for _, v in flags if v])
    values = {}
    for field in fields:
        key, _, value = field.partition("=")
        if re.match(r"^[@]", value) or value.startswith(("$", "`")):
            if key == "query" or key == "":
                if value.startswith("@") and value != "@-":
                    if (ctx_command or "").count(value[1:]) > 1:
                        return [Merge("unverifiable", reason="the GraphQL query file is also written by the same command")]
                    try:
                        text += " " + _read_small(value[1:], cwd)
                    except GateError as error:
                        return [Merge("unverifiable", reason=str(error))]
                else:
                    return [Merge("unverifiable", reason="the GraphQL query is read from stdin or built at runtime")]
        values.setdefault(key, []).append(value)
    for name, value in flags:
        if name == "--input":
            if value in (None, "-"):
                return [Merge("unverifiable", reason="gh api graphql --input reads a body the hook cannot see")]
            try:
                text += " " + _read_small(value, cwd)
            except GateError as error:
                return [Merge("unverifiable", reason=str(error))]
    if re.search(r"mergeBranch", text, re.I):
        return [Merge("unverifiable", reason="the mergeBranch mutation has no pull request to check")]
    if not GRAPHQL_MERGE.search(text):
        return []
    return [_graphql_from_text(text, values)]


def _graphql_from_text(text, values=None):
    values = values or {}
    heads = [h.lower() for h in re.findall(r"expectedHeadOid\s*:\s*\"([0-9a-fA-F]{40,64})\"", text)]
    heads += [v.lower() for v in values.get("expectedHeadOid", [])]
    occurrences = len(re.findall(r"expectedHeadOid", text))
    unknown = occurrences > len(heads) - len(values.get("expectedHeadOid", []))
    ids = sorted(set(re.findall(r"\bPR_[A-Za-z0-9_-]+", text)))
    return Merge("graphql", head_vals=heads, head_unknown=unknown, node_ids=ids,
                 auto=bool(re.search(r"enablePullRequestAutoMerge", text, re.I)),
                 binding="expectedHeadOid: \"<full head sha>\"")


def _http_scan(tokens):
    """curl, wget or an interpreter talking to the GitHub API."""
    found = []
    text = " ".join(tokens)
    if GRAPHQL_MERGE.search(text):
        found.append(_graphql_from_text(text))
    elif re.search(r"mergeBranch", text, re.I):
        found.append(Merge("unverifiable", reason="the mergeBranch mutation has no pull request to check"))
    m = REST_MERGE.search(text)
    if m:
        slug = m.group(1) + "/" + m.group(2) if m.group(1) else None
        shas = [s.lower() for s in re.findall(r"\bsha\W{1,4}([0-9a-fA-F]{40,64})", text)]
        found.append(Merge("rest", slug=slug, number=m.group(3), head_vals=shas, repo_ok=slug is not None,
                           binding="\"sha\": \"<full head sha>\""))
    if re.search(r"/repos/[\w.-]+/[\w.-]+/merges\b", text):
        found.append(Merge("unverifiable", reason="the branch merge endpoint has no pull request to check"))
    return found


def _normalize_code(code):
    code = re.sub(r"\$\{?IFS[^}\s]*\}?", " ", code)  # gh${IFS}pr${IFS}merge
    return re.sub(r"[\"'`\\,\[\]]", " ", code)


def find_merges(command, cwd=None, _depth=0, _ctx=None):
    ctx = dict(_ctx or {"implicit_ok": True, "http": False})
    ctx.setdefault("command", command)
    if _depth > MAX_DEPTH:
        return [Merge("unverifiable", reason="commands nested too deeply to inspect")]
    if len(command) > MAX_COMMAND_CHARS:
        return [Merge("unverifiable", reason="command too large to inspect")] if GH_HINT.search(command) else []
    tokens, _ = tokenize(command.replace("\\\n", ""))
    if len(tokens) > MAX_TOKENS:
        return [Merge("unverifiable", reason="command has too many tokens to inspect")] if GH_HINT.search(command) else []
    tokens = _strip_heredocs(tokens)
    n = len(tokens)
    base = [os.path.basename(t) for t in tokens]
    assigns = _literal_assignments(tokens)
    if any(b in ("cd", "pushd", "popd", "chdir", "ssh", "docker", "podman", "kubectl", "su", "tmux", "-C", "--chdir")
           for b in base) or any(t.startswith(("GH_REPO=", "GH_HOST=", "--chdir=")) for t in tokens):
        ctx["implicit_ok"] = False
    ends = _ends(tokens)
    segments, s_i = [], 0
    while s_i < n:
        if tokens[s_i] in SEPARATORS:
            s_i += 1
            continue
        segments.append((s_i, ends[s_i], tokens[ends[s_i]] if ends[s_i] < n else ""))
        s_i = ends[s_i] + 1
    words = [_command_word(tokens[a:b]) for a, b, _ in segments]
    found, http_tokens, raw = [], [], []
    for index, (a, b, sep) in enumerate(segments):
        seg = tokens[a:b]
        handled, seen_xargs = False, False
        for i in range(a, b):
            name = base[i]
            if name == "xargs":
                seen_xargs = True
            if re.match(r"^gh(?:\$|\{)[^\s]*$", name) and name not in ("gh", "gh.exe") and \
                    not re.search(r"\s", tokens[i]):
                found.append(Merge("unverifiable", reason="a gh command glued together at run time"))
                handled = True
            if name in ("gh", "gh.exe") and words[index] == "git" and "git" in base[a:i] and \
                    _git_subcommand(seg)[1] in GIT_PLAIN and _git_subcommand(seg)[0] < i - a and \
                    not any("alias." in t or t.startswith("!") for t in seg):
                continue  # `git push gh ...`: a remote, branch or path named gh (goodqa#15122 AC-4)
            if name in ("gh", "gh.exe"):
                found.extend(_gh_merge(tokens[i + 1:b], seen_xargs, dict(ctx, assigns=assigns, args_index=i + 1), cwd))
                handled = True
            elif name in SHELLS:
                rest = tokens[i + 1:b]
                for k, t in enumerate(rest[:-1]):
                    if re.match(r"^-[A-Za-z]*c[A-Za-z]*$", t):
                        script = next((x for x in rest[k + 1:] if x != "--" and not x.startswith("-")), None)
                        if script is not None:
                            found.extend(find_merges(script, cwd, _depth + 1, ctx))
                            handled = True
                        break
            elif name in ("ssh", "eval", "su", "env"):
                sub_ctx = dict(ctx, implicit_ok=ctx["implicit_ok"] and name != "ssh")
                for t in tokens[i + 1:b]:
                    if re.search(r"\s", t):
                        found.extend(find_merges(t, cwd, _depth + 1, sub_ctx))
                        handled = True
            elif INTERPRETERS.match(name):
                http_tokens.extend(tokens[a:b])
                for t in tokens[i + 1:b]:
                    if re.search(r"\s", t) or "merge" in t.lower():
                        found.extend(find_merges(_normalize_code(t), cwd, _depth + 1, dict(ctx, http=True)))
                        handled = True
            elif HTTP_CLIENTS.match(name):
                http_tokens.extend(tokens[a:b])
                handled = True
        if handled:
            continue
        word = words[index]
        g = next((j for j in range(a, b) if base[j] == "git"), None)
        if g is not None and word in ("git", "xargs", "parallel"):
            if _git_push_to_default(tokens[g:b], g, assigns, appended=word != "git"):
                raw.append(Merge("unverifiable", reason="a git push to main or master (or to every branch, or to a "
                                                        "branch built at run time) merges without a pull request; "
                                                        "push a named feature branch and merge the reviewed PR"))
                continue
        first = next((t for t in seg if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t)
                      and os.path.basename(t) not in WRAPPER_WORDS and not t.startswith("-")), "")
        full_command = " ".join(tokens)
        if DYNAMIC_WORD.match(first) and sep not in ("|", "|&"):
            # goodqa#15122 AC-3: a command word assigned once from a literal earlier in the same command is read as
            # that word; a merge it reaches stays unverifiable (NEG-3), anything else is judged as the plain command.
            at = a + seg.index(first)
            value = _resolve(first, at, assigns)
            if value is not None and value:
                text = " ".join(shlex.quote(_resolve(t, at + j, assigns) or t) for j, t in enumerate(tokens[at:b]))
                if find_merges(text, cwd, _depth + 1, ctx):
                    raw.append(Merge("unverifiable", reason="the command word is built at run time and the command "
                                                            "mentions gh or a merge"))
                continue
        # goodqa#15317: a command word that is a variable this command never binds (an environment value such as a relay
        # path) cannot carry text from another segment, so only its own segment can name a merge. A variable that is
        # assigned, read into, looped over or exported here, or any other dynamic word, keeps the whole-command rule.
        hint_scope = full_command
        name_match = re.fullmatch(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})", first)
        before_sep = segments[index - 1][2] if index else ""
        wrote_file = any(t.startswith(">") or t == "tee" or os.path.basename(t) == "tee" for t in tokens[:a])
        merge_anywhere = bool(RAW_MERGE.search(_normalize_code(" ".join(tokens))))  # F2: any merge text keeps the whole rule
        if name_match and word != "eval" and before_sep not in ("|", "|&") and not wrote_file and not merge_anywhere:
            var = name_match.group(1) or name_match.group(2)
            if not re.search(r"(?<![$\w{])" + re.escape(var) + r"(?!\w)", full_command.replace("${" + var + "}", " ")
                             .replace("$" + var, " ")):
                hint_scope = " ".join(tokens[a:b])
        if MERGE_HINT.search(hint_scope) and (DYNAMIC_WORD.match(first) or (
                word == "eval" and any("$" in t for t in seg[1:]))):
            raw.append(Merge("unverifiable", reason="the command word is built at run time and the command mentions "
                                                    "gh or a merge"))
            continue
        nxt = words[index + 1] if index + 1 < len(segments) else ""
        next_seg = tokens[segments[index + 1][0]:segments[index + 1][1]] if index + 1 < len(segments) else []
        consumer = nxt in EXEC_CONSUMERS or bool(INTERPRETERS.match(nxt)) or (
            nxt == "xargs" and any(os.path.basename(t) in SHELLS or t in ("eval", "gh") for t in next_seg))
        piped = sep in ("|", "|&") and consumer
        exempt = word in DATA_COMMANDS or (word == "git" and not any("alias." in t or t.startswith("!") for t in seg))
        if exempt and not piped:
            continue
        text = _normalize_code(" ".join(seg))
        if ctx["http"]:
            text = REST_MERGE.sub(" ", GRAPHQL_MERGE.sub(" ", text))  # the HTTP scan classifies these
        if RAW_MERGE.search(text):
            raw.append(Merge("unverifiable", reason="a merge string appears in a command the hook cannot read as a "
                                                      "plain gh call (variable, wrapper, script or other client)"))
        elif re.search(r"base64\s+(?:-d|--decode|-D)", text) and nxt in SHELLS:
            raw.append(Merge("unverifiable", reason="decoded text is piped into a shell"))
    if ctx["http"]:
        http_tokens = tokens
    if http_tokens:
        found.extend(_http_scan(http_tokens))
    found.extend(raw)
    seen, unique = set(), []
    for merge in found:
        if merge.key() not in seen:
            seen.add(merge.key())
            unique.append(merge)
    return unique


# ---------------------------------------------------------------------------------------------------- gh runner

class SubprocessGh:
    """The real runner: gh with a timeout, a process group killed on timeout, output capped."""

    def __init__(self):
        self.timeout = CALL_TIMEOUT_DEFAULT
        try:
            self.timeout = float(os.environ.get("MERGE_GATE_CALL_TIMEOUT", CALL_TIMEOUT_DEFAULT))
        except ValueError:
            pass
        self.timeout = max(0.5, min(self.timeout, CALL_TIMEOUT_MAX))

    def __call__(self, args, timeout, cwd=None):
        timeout = min(timeout, self.timeout)
        env = dict(os.environ, GH_PROMPT_DISABLED="1", NO_COLOR="1", GH_NO_UPDATE_NOTIFIER="1")
        proc = subprocess.Popen(["gh"] + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd if cwd and os.path.isdir(cwd) else None, env=env,
                                start_new_session=True)
        buffers, state = {"out": [], "err": []}, {"over": False}

        def pump(stream, key):
            total = 0
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                total += len(chunk)
                if total > MAX_GH_OUTPUT:
                    state["over"] = True
                    self._kill(proc)
                    return
                buffers[key].append(chunk)

        threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
                   threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
        for t in threads:
            t.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._kill(proc)
            proc.wait()
            raise
        finally:
            self._kill(proc)  # a grandchild may hold the pipes
        for t in threads:
            t.join(2)
        if state["over"]:
            return 1, "", "gh output exceeded the cap"
        return (proc.returncode, b"".join(buffers["out"]).decode("utf-8", "replace"),
                b"".join(buffers["err"]).decode("utf-8", "replace"))

    @staticmethod
    def _kill(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass


class Client:
    """Wraps a runner with the total deadline and JSON parsing; every failure raises GateError."""

    def __init__(self, runner, deadline, cwd=None):
        self.runner, self.deadline, self.cwd = runner, deadline, cwd

    def raw(self, args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0.2:
            raise GateError("the gate ran out of time before GitHub answered")
        try:
            return self.runner(args, min(CALL_TIMEOUT_MAX, remaining), self.cwd)
        except subprocess.TimeoutExpired:
            raise GateError("a gh call timed out (" + clean(args[0] + " " + (args[1] if len(args) > 1 else "")) + ")")
        except (OSError, ValueError) as error:
            raise GateError("gh could not run (" + type(error).__name__ + ")")

    def json(self, args, what):
        rc, out, err = self.raw(args)
        if rc != 0:
            raise GateError(f"gh failed reading {what}: " + clean(err or out, 100))
        try:
            return safe_input.safe_json_loads(out, max_depth=40, max_bytes=MAX_GH_OUTPUT)
        except ValueError:
            raise GateError(f"gh returned unreadable data for {what}")


# ---------------------------------------------------------------------------------------------------- evaluation

def _verdict_run(status, conclusion):
    status, conclusion = str(status or "").upper(), str(conclusion or "").upper()
    if status != "COMPLETED":
        return "bad", "not finished (" + (status or "unknown") + ")"
    if conclusion == "SUCCESS":
        return "ok", conclusion
    if conclusion in NONREQUIRED_OK:
        return "soft", conclusion
    return "bad", conclusion or "no conclusion"


def _verdict_status(state):
    state = str(state or "").upper()
    return ("ok", state) if state == "SUCCESS" else ("bad", state or "unknown")


def _entries(pr, runs, statuses, head, reasons):
    entries = []
    for item in pr.get("statusCheckRollup") or []:
        if not isinstance(item, dict):
            reasons.append("the check rollup holds an unreadable entry")
            continue
        if item.get("__typename") == "StatusContext" or "context" in item:
            v, d = _verdict_status(item.get("state"))
            entries.append(dict(name=item.get("context"), src="rollup", kind="status", v=v, d=d, ts="", app=None))
        else:
            v, d = _verdict_run(item.get("status"), item.get("conclusion"))
            entries.append(dict(name=item.get("name"), src="rollup", kind="run", v=v, d=d,
                                ts=item.get("startedAt") or "", app=None, wf=item.get("workflowName")))
    for run in runs.get("check_runs") or []:
        if str(run.get("head_sha", head)).lower() != head:
            reasons.append("check-runs returned a check for another commit")
        v, d = _verdict_run(run.get("status"), run.get("conclusion"))
        app = (run.get("app") or {}).get("id")
        entries.append(dict(name=run.get("name"), src="api", kind="run", v=v, d=d,
                            ts=run.get("started_at") or "", app=app))
    for status in statuses.get("statuses") or []:
        v, d = _verdict_status(status.get("state"))
        entries.append(dict(name=status.get("context"), src="status", kind="status", v=v, d=d, ts="", app=None))
    groups = {}
    for e in entries:
        groups.setdefault((e["src"], e["kind"], e["name"], e.get("wf"), e.get("app")), []).append(e)
    kept = []
    for group in groups.values():
        if len(group) > 1 and all(e["ts"] for e in group):
            group = [max(group, key=lambda e: e["ts"])]
        kept.extend(group)
    return kept


def _protection(client, slug, base):
    """('ok', {context: app_id}) | ('none', {}) | ('error', None)"""
    try:
        rc, out, err = client.raw(["api", f"repos/{slug}/branches/{base}/protection/required_status_checks"])
    except GateError:
        return "error", None
    if rc != 0:
        return ("none", {}) if "not protected" in (out + err).lower() else ("error", None)
    try:
        data = safe_input.safe_json_loads(out, max_depth=20, max_bytes=MAX_GH_OUTPUT)
        if isinstance(data.get("checks"), list):
            found = {c["context"]: c.get("app_id") for c in data["checks"] if isinstance(c, dict) and c.get("context")}
        else:
            found = {c: None for c in data.get("contexts") or []}
    except (ValueError, AttributeError, TypeError):
        return "error", None
    return ("ok", found) if found else ("none", {})


def _rules(client, slug, base):
    try:
        rc, out, err = client.raw(["api", f"repos/{slug}/rules/branches/{base}"])
        if rc != 0:
            return "error", None
        data = safe_input.safe_json_loads(out, max_depth=20, max_bytes=MAX_GH_OUTPUT)
        found = {}
        for rule in data:
            if isinstance(rule, dict) and rule.get("type") == "required_status_checks":
                for c in (rule.get("parameters") or {}).get("required_status_checks") or []:
                    if isinstance(c, dict) and c.get("context"):
                        found[c["context"]] = c.get("integration_id")
        return ("ok", found) if found else ("none", {})
    except (GateError, ValueError, TypeError):
        return "error", None


def _pr_required(client, slug, number):
    try:
        rc, out, err = client.raw(["pr", "checks", str(number), "-R", slug, "--required", "--json", "name,bucket,state"])
        if rc != 0:
            return ("none", {}) if "no required checks" in (out + err).lower() else ("error", None)
        data = safe_input.safe_json_loads(out, max_depth=10, max_bytes=MAX_GH_OUTPUT)
        found = {c["name"]: None for c in data if isinstance(c, dict) and c.get("name")}
        return ("ok", found) if found else ("none", {})
    except (GateError, ValueError, TypeError):
        return "error", None


INERT_TRIGGERS = {"workflow_dispatch", "schedule", "release", "workflow_call", "repository_dispatch"}
_ON_KEY = re.compile(r"^(?:on|\"on\"|'on')\s*:(.*)$")
_TOP_KEY = re.compile(r"^[A-Za-z_][\w-]*\s*:")
_TRIGGER_LINE = re.compile(r"^([A-Za-z_]+)\s*:\s*$")
_SUB_KEY = re.compile(r"^([A-Za-z_][\w-]*)\s*:")


def _real_value(value):
    """True for a one-line scalar or flow list that holds at least one non-empty, non-null item."""
    v = value.strip()
    if v.startswith("[") and v.endswith("]"):
        items = [i.strip().strip("'\"").strip() for i in v[1:-1].split(",")]
        return bool(items) and all(i and _real_value(i) for i in items)
    if v[:1] in "{[!&*|>?" or not v:
        return False
    v = v.strip("'\"").strip()
    return bool(v) and v.lower() not in ("null", "~")


def _trigger_names(text):
    """Return {trigger: set(sub-keys)} from a workflow's top-level `on:`, or None unless every line was understood.

    Deliberately strict: any construct this small reader does not know (documents, anchors, aliases, tabs, quoted or
    complex keys, multi-line flow values, a second `on:`) yields None, which callers treat as able to run on a PR head.
    """
    if "\t" in text or re.search(r"(?m)^(?:---|\.\.\.)", text) or re.search(r"(?m)(?:^|\s)[&*][\w-]+|<<\s*:", text):
        return None
    lines = [re.sub(r"\s+#.*$", "", ln.rstrip()) for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    for ln in lines:  # every top-level line must be a plain `key:`; flow maps, `? key`, `}` and quoted keys are unknown
        if ln.strip() and not ln[0].isspace() and not _TOP_KEY.match(ln) and not _ON_KEY.match(ln):
            return None
    significant = [ln for ln in lines if ln.strip()]
    if not significant or significant[0][0].isspace():  # an indented root could hide a column-0 decoy inside a scalar
        return None
    if any(re.match(r"^\s+(?:on|\"on\"|'on')\s*:", ln) for ln in lines):  # a second, nested or indented `on`
        return None
    if re.search(r"(?i)pull_request|merge_group|workflow_run", re.sub(r"(?m)^\s*#.*$", "", text)) and \
            not re.search(r"(?m)^\s+(?:pull_request|merge_group|workflow_run)\w*\s*:", text):
        return None  # a PR trigger word that is not a plain key (quoted, escaped, in a flow value): unknown
    for ln in significant:  # a top-level value that opens a quote or flow collection may span lines: unknown
        if not ln[0].isspace() and re.search(r"[:]\s*(?:[\"'{\[](?![^\"'}\]]*[\"'}\]]\s*$)|[|>])", ln) and not _ON_KEY.match(ln):
            return None
    starts = [i for i, ln in enumerate(lines) if _ON_KEY.match(ln)]
    if len(starts) != 1:
        return None
    i = starts[0]
    rest = _ON_KEY.match(lines[i]).group(1).strip()
    if rest:  # on: push   |   on: [push, pull_request]   (one line only)
        if re.fullmatch(r"[A-Za-z_]+", rest):
            return {rest: set()}
        if re.fullmatch(r"\[\s*[A-Za-z_]+(?:\s*,\s*[A-Za-z_]+)*\s*\]", rest):
            return {n: set() for n in re.findall(r"[A-Za-z_]+", rest)}
        return None
    found, current, base, sub, pending = {}, None, None, None, None
    for ln in lines[i + 1:]:
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        body = ln.strip()
        if indent == 0:
            if not _TOP_KEY.match(body):
                return None
            break
        base = indent if base is None else base
        if indent < base:
            return None
        if indent == base:
            m = _TRIGGER_LINE.match(body)
            if not m:
                return None
            current, sub, pending = m.group(1), None, None
            found[current] = set()
        elif current is None:
            return None
        else:
            sub = indent if sub is None else sub
            if indent == sub:
                m = _SUB_KEY.match(body)
                if m:
                    value = body[m.end():].strip()
                    if value and not _real_value(value):
                        return None  # `tags: null`, `[ ]`, `''`, `!!null ''` and friends: unknown
                    found[current].add(m.group(1) if value else m.group(1) + ":empty")
                    pending = None if value else (current, m.group(1))
                elif body.startswith("- "):
                    found[current].add("-")  # a list directly under the trigger
                else:
                    return None
            elif indent < sub:
                return None
            elif pending:  # block value under `key:`: only `- item` lines with real scalars make it non-empty
                if not (body.startswith("- ") and _real_value(body[2:].strip())):
                    return None
                found[pending[0]].discard(pending[1] + ":empty")
                found[pending[0]].add(pending[1])
            elif not (body.startswith("- ") or body.startswith("[") or body.startswith("]")):
                pass
    return found or None


def _can_run_on_pr_head(triggers):
    """True when any trigger could create a check run on a pull request head (unknown means yes: fail closed)."""
    if triggers is None:
        return True
    for name, keys in triggers.items():
        if name in INERT_TRIGGERS:
            continue
        if name == "push" and keys == {"tags"}:
            continue  # runs only for tag pushes, never for a pull request head
        return True
    return False


INACTIVE_STATES = {"disabled_manually", "disabled_inactivity", "disabled_fork"}
DELETED_STATE = "deleted"  # the file may have been restored since: classified wherever it exists


def _is_404(err, out):
    """gh prints `(HTTP 404)` on stderr for a real not-found; a bare 404 inside other text (ids, 5xx bodies) is not."""
    text = (err or "") + " " + (out or "")
    if re.search(r"(?i)no commit found|ref(erence)? .*not found|unknown revision", text):
        return False  # an unresolvable ref is not an absent file: the file may exist at that ref
    return bool(re.search(r"\(HTTP 404\)", err or "")) or bool(re.search(r'"status"\s*:\s*"404"', out or ""))


def _get_file(client, slug, path, ref):
    """Text of a workflow file at a ref; None when the file does not exist there (404); GateError otherwise."""
    rc, out, err = client.raw(["api", f"repos/{slug}/contents/{path}?ref={urllib.parse.quote(ref, safe='')}"])
    if rc != 0:
        if _is_404(err, out):
            return None
        raise GateError("gh failed reading a workflow file: " + clean(err or out, 100))
    try:
        data = safe_input.safe_json_loads(out, max_depth=40, max_bytes=MAX_GH_OUTPUT)
        return base64.b64decode(data["content"]).decode("utf-8")
    except (KeyError, TypeError, ValueError):
        raise GateError("a workflow file is unreadable")


def _workflow_dir(client, slug, ref):
    """Paths of workflow files at a ref; a missing directory is an empty list, any other failure is unreadable."""
    rc, out, err = client.raw(["api", f"repos/{slug}/contents/.github/workflows?ref={urllib.parse.quote(ref, safe='')}"])
    if rc != 0:
        if _is_404(err, out):
            return []
        raise GateError("gh failed reading the workflow directory: " + clean(err or out, 100))
    try:
        listing = safe_input.safe_json_loads(out, max_depth=40, max_bytes=MAX_GH_OUTPUT)
    except ValueError:
        raise GateError("the workflow directory is unreadable")
    if not isinstance(listing, list):
        raise GateError("the workflow directory is unreadable")
    return [str(i.get("path") or "") for i in listing if isinstance(i, dict) and re.search(r"\.ya?ml$", str(i.get("name") or ""), re.I)]


def _ci_capable_workflows(client, slug, head, base):
    """Reasons to block when a workflow may report on this head. Raises GateError when it cannot tell.

    A PR can edit the workflow that decides whether its own CI runs, so every active workflow is read at the PR base
    AND the verified head and counts as inert only if both versions are; files that exist only at the head (added by
    the PR, not yet listed by the API) are classified too."""
    wf = client.json(["api", f"repos/{slug}/actions/workflows?per_page=100"], "workflows")
    total, listed = int(wf.get("total_count", -1)), wf.get("workflows")
    if not isinstance(listed, list) or total < 0 or total > len(listed):
        raise GateError("the workflow list is incomplete")
    paths, inactive, deleted = [], set(), set()
    for item in listed:
        if not isinstance(item, dict) or item.get("state") not in INACTIVE_STATES | {"active", DELETED_STATE}:
            raise GateError("the workflow list holds an entry with an unknown state")
        path = str(item.get("path") or "")
        if item["state"] in INACTIVE_STATES:
            inactive.add(path)
        else:
            (deleted if item["state"] == DELETED_STATE else set()).add(path)
            paths.append(path)
    for ref in (head, base):  # added by the PR, or only on a non-default base: not in the API list until it runs
        for path in _workflow_dir(client, slug, ref):
            if path not in inactive and path not in paths:
                paths.append(path)
    reasons = []
    for path in paths:
        if not re.match(r"^\.github/workflows/[\w./-]+$", path) or ".." in path:
            reasons.append("a workflow has an unreadable path")
            continue
        texts = [(label, _get_file(client, slug, path, ref)) for ref, label in ((base, "base"), (head, "head"))]
        if all(t is None for _, t in texts):
            if path in deleted:
                continue  # a deleted workflow whose file is still gone at both refs
            reasons.append("a workflow file listed by GitHub could not be found at the base or the head")
            continue
        for label, text in texts:
            if text is not None and _can_run_on_pr_head(_trigger_names(text)):
                reasons.append("no checks have reported yet but workflow " + clean(path, 60)
                               + " can run (at the PR " + label + ")")
                break
    return reasons


def evaluate_pr(client, slug, number, target=None):
    """Return (info, reasons) where info has slug, number, head and reasons list the (waivable) check problems."""
    ref = [str(number)] if number else ([target] if target else [])
    if target and not re.match(r"^[A-Za-z0-9._/-]+$", target) or (target or "").startswith("-"):
        raise GateError("the merge target is not a plain PR number, URL or branch")
    fields = "number,url,headRefOid,baseRefName,state,mergeStateStatus,statusCheckRollup"
    view = ["pr", "view"] + ref + (["-R", slug] if slug else []) + ["--json", fields]
    pr = client.json(view, "the pull request")
    if not isinstance(pr, dict):
        raise GateError("the pull request data is unreadable")
    head = str(pr.get("headRefOid") or "").lower()
    if not SHA.fullmatch(head):
        raise GateError("the pull request head SHA is missing")
    m = re.match(r"^https://[^/]+/([\w.-]+)/([\w.-]+)/pull/(\d+)", str(pr.get("url") or ""))
    if not m:
        raise GateError("the pull request URL is unreadable")
    real_slug, real_number = m.group(1) + "/" + m.group(2), int(m.group(3))
    if repo_key(real_slug) is None:
        raise GateError("the pull request repository name is unreadable")
    if slug and repo_key(slug) != repo_key(real_slug):
        raise GateError("the pull request belongs to " + clean(real_slug) + ", not " + clean(slug))
    if number and int(number) != real_number:
        raise GateError("the pull request number differs from the target")
    slug, number = real_slug, real_number
    base = str(pr.get("baseRefName") or "")
    if not re.match(r"^[A-Za-z0-9._/-]+$", base) or base.startswith("-"):
        raise GateError("the base branch name is unreadable")
    if str(pr.get("state") or "").upper() != "OPEN":
        raise GateError("the pull request is not open")
    runs = client.json(["api", f"repos/{slug}/commits/{head}/check-runs?per_page=100"], "check runs")
    statuses = client.json(["api", f"repos/{slug}/commits/{head}/status?per_page=100"], "commit statuses")
    if not isinstance(runs, dict) or not isinstance(statuses, dict):
        raise GateError("check data is unreadable")
    reasons = []
    try:
        if int(runs.get("total_count", 0)) > len(runs.get("check_runs") or []):
            reasons.append("the check-runs list is truncated; not every check could be read")
        if int(statuses.get("total_count", 0)) > len(statuses.get("statuses") or []):
            reasons.append("the status list is truncated; not every status could be read")
    except (TypeError, ValueError):
        raise GateError("check counts are unreadable")
    prot, rules, req = _protection(client, slug, base), _rules(client, slug, base), _pr_required(client, slug, number)
    required, apps = {}, {}
    for state, found in (prot, rules, req):
        for name, app in (found or {}).items():
            required[name] = True
            if app not in (None, -1):
                apps.setdefault(name, set()).add(app)
    known = req[0] in ("ok", "none") or (prot[0] in ("ok", "none") and rules[0] in ("ok", "none"))
    if not known:
        reasons.append("the required checks could not be read (branch protection, rulesets and gh pr checks all failed)")
    elif not (prot[0] in ("ok", "none") and rules[0] in ("ok", "none")):
        if str(pr.get("mergeStateStatus") or "").upper() not in CLEAN_STATES:
            reasons.append("required checks are known only from gh pr checks --required, which lists checks that "
                           "already reported, and mergeStateStatus is " + clean(pr.get("mergeStateStatus") or "missing")
                           + " (needs CLEAN or HAS_HOOKS)")
    entries = _entries(pr, runs, statuses, head, reasons)
    # #134 red-team P1/B1: a review authorization never covers a check that failed, is still pending or queued, or
    # has not reported. A PR merged seconds after its push has had no CI at all.
    unsettled = sorted({clean(e["name"]) for e in entries if e["v"] == "bad"})
    for e in entries:
        name = clean(e["name"])
        if e["v"] == "bad":
            reasons.append(f"check '{name}' is {clean(e['d'])}")
        elif e["v"] == "soft" and e["name"] in required:
            reasons.append(f"required check '{name}' concluded {clean(e['d'])} (policy: a required check must be success)")
    for name in sorted(required):
        mine = [e for e in entries if e["name"] == name]
        if not mine:
            reasons.append(f"required check '{clean(name)}' has not reported on this head")
            unsettled.append(clean(name))
        elif name in apps and not any(e["src"] == "api" and e["app"] in apps[name] and e["v"] == "ok" for e in mine):
            reasons.append(f"required check '{clean(name)}' has no success from the required app")
    no_ci = False
    if known and not required:
        # Nothing is required, so the workflows decide. goodqa#15282 red-team H3: a report from outside the repo's
        # workflows (a commit status anyone with push can post, an external app, a lone skipped run) is not CI, so the
        # workflows are classified even when something reported, and a head with no success counts as unchecked.
        succeeded = any(e["v"] == "ok" for e in entries)
        try:
            found = _ci_capable_workflows(client, slug, head, base)
        except (GateError, ValueError, TypeError, AttributeError):
            found = None
        if found is None:
            reasons.append("no required checks and the workflow list could not be read")
            unsettled.append("(workflows unreadable)")
        elif not found:
            no_ci = True  # no workflow could run: evaluate_merge asks for exact-head evidence
        elif not succeeded:
            reasons.extend(found)
            unsettled.append("(no checks reported)" if not entries else "(no check succeeded)")
    again = client.json(["pr", "view", str(number), "-R", slug, "--json", "headRefOid"], "the pull request head")
    if str((again or {}).get("headRefOid") or "").lower() != head:
        raise GateError("the pull request head moved while the checks were read")
    return {"slug": slug, "number": number, "head": head, "no_ci": no_ci, "unsettled": unsettled}, reasons


def _resolve_graphql(client, node_ids):
    if len(node_ids) != 1:
        raise GateError("the GraphQL merge must name exactly one pull request node id")
    query = "query($id:ID!){node(id:$id){... on PullRequest{number url headRefOid}}}"
    data = client.json(["api", "graphql", "-f", "query=" + query, "-f", "id=" + node_ids[0]], "the pull request node")
    node = ((data or {}).get("data") or {}).get("node") or {}
    m = re.match(r"^https://[^/]+/([\w.-]+)/([\w.-]+)/pull/(\d+)", str(node.get("url") or ""))
    if not m:
        raise GateError("the pull request node could not be resolved")
    return m.group(1) + "/" + m.group(2), int(m.group(3))


def evaluate_merge(merge, client, state_dir, now, command_hash):
    """Return (allowed, text, audit_info). Never raises GateError."""
    info = {"repo": None, "pr": None, "head": None}
    hard, soft = [], []  # hard reasons cannot be waived
    waived = None
    try:
        if merge.kind == "unverifiable":
            raise GateError(merge.reason or "the merge cannot be tied to one pull request")
        if not merge.repo_ok:
            raise GateError("the repository cannot be determined (a cd, ssh, GH_REPO or GH_HOST changes it): pass "
                            "-R owner/repo or a full PR URL")
        slug, number = merge.slug, merge.number
        if merge.kind == "graphql":
            slug, number = _resolve_graphql(client, merge.node_ids)
        details, soft = evaluate_pr(client, slug, number, merge.target)
        info.update(repo=details["slug"], pr=details["number"], head=details["head"], no_ci=details.get("no_ci"),
                    unsettled=details.get("unsettled") or [])
        if details.get("no_ci"):
            # goodqa#15282 (amends goodqa#14669 AC-1): with GitHub CI switched off nothing was checked, so the merge
            # needs positive evidence instead: an exact-head waiver, or the one a bound PR review authorization writes
            soft.append("GitHub CI is switched off for this repository, so no check ran on this head; the merge needs "
                        "an exact-head waiver or a PR review authorization (peer_review.py pr --github-repo --pr)")
        if merge.kind != "check":
            if merge.head_unknown or not merge.head_vals:
                hard.append(f"the merge must carry the verified head: add {merge.binding.replace('<full head sha>', details['head'])}")
            elif any(h != details["head"] for h in merge.head_vals):
                hard.append("the head SHA in the merge command is not the verified head " + details["head"][:12])
    except GateError as error:
        hard.append(str(error))
    if not hard and not soft:
        return True, "", info
    # red-team M1: `merge_gate.py check` is a read-only query; it must never spend the single-use evidence
    if not hard and info["head"] and merge.kind != "check":
        wid = consume_waiver(state_dir, info["repo"], info["pr"], info["head"], command_hash, now=now,
                             review_ok=not info.get("unsettled"))
        if wid:
            info["waiver"] = wid
            return True, "", info
    reasons = [clean(r, 300) for r in (hard + soft)][:MAX_REASONS]
    where = f" of {clean(info['repo'])}#{info['pr']} (head {info['head'][:12]})" if info["head"] else ""
    text = f"merge-gate: BLOCKED merge{where}.\n" + "\n".join("  - " + r for r in reasons)
    if info["head"] and not hard:
        text += ("\nWait for the checks, or have the main agent record a single-use waiver: python3 "
                 f"{HERE / 'merge_gate.py'} waive --repo {info['repo']} --pr {info['pr']} --head {info['head']} "
                 "--ticket 'GoodQA #N' --reason '<why>'")
    return False, text, info


# ---------------------------------------------------------------------------------------------------- state files

def _lock(state_dir):
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = open(state_dir / LOCK_FILE, "a+")
    if fcntl is None:
        return handle
    deadline = time.monotonic() + 5
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except OSError:
            if time.monotonic() > deadline:
                handle.close()
                raise Corrupt("the waiver log is locked")
            time.sleep(0.05)


def _unlock(handle):
    try:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _read_waivers(state_dir):
    """Verify the hash chain and the head record; return the records. Raises Corrupt."""
    path = state_dir / WAIVER_FILE
    head_path = state_dir / WAIVER_HEAD_FILE
    if not path.exists():
        if head_path.exists():
            raise Corrupt("the waiver log is missing")
        return []
    try:
        data = safe_input.read_bounded(str(path), MAX_STATE_BYTES)
    except (safe_input.InputRejected, OSError) as error:
        raise Corrupt("the waiver log cannot be read")
    records, prev, last = [], ZERO, ZERO
    for raw in data.splitlines():
        try:
            record = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise Corrupt("the waiver log holds a line that is not JSON")
        if not isinstance(record, dict) or record.get("prev") != prev:
            raise Corrupt("the waiver log chain does not verify")
        prev = last = hashlib.sha256(raw).hexdigest()
        records.append(record)
    try:
        head = json.loads(safe_input.read_bounded(str(head_path), 4096).decode("utf-8"))
    except (safe_input.InputRejected, OSError, ValueError):
        raise Corrupt("the waiver log head record is missing or unreadable")
    if head.get("n") != len(records) or head.get("last") != last:
        raise Corrupt("the waiver log was truncated or edited")
    return records


def _append_waiver_record(state_dir, record):
    records = _read_waivers(state_dir)
    prev = ZERO
    if records:
        raw = (state_dir / WAIVER_FILE).read_bytes().splitlines()[-1]  # input-ok: file already bounded by _read_waivers
        prev = hashlib.sha256(raw).hexdigest()
    record = dict(record, v=1, prev=prev)
    line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = os.open(str(state_dir / WAIVER_FILE), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp = state_dir / (WAIVER_HEAD_FILE + ".tmp")
    tmp.write_text(json.dumps({"n": len(records) + 1, "last": hashlib.sha256(line).hexdigest()}), encoding="utf-8")
    os.chmod(str(tmp), 0o600)
    os.replace(str(tmp), str(state_dir / WAIVER_HEAD_FILE))
    return record


def _active(records, repo, pr, head, now, review_ok=True):
    used = {r.get("waiver") for r in records if r.get("event") == "consume"}
    for r in records:
        if not review_ok and r.get("approval_source") == "settled-review":
            continue  # #134 red-team P1/B1: a review authorization never passes a failing, pending or missing check
        if (r.get("event") == "waive" and r.get("id") not in used and repo_key(repo) is not None
                and repo_key(r.get("repo")) == repo_key(repo)
                and r.get("pr") == pr and r.get("head") == head and now < float(r.get("ts", 0)) + WAIVER_TTL_SECONDS):
            return r
    return None


def stamp_key(repo, pr, head, ticket):
    return hashlib.sha256(f"{repo.lower()}|{pr}|{head}|{ticket}".encode("utf-8")).hexdigest()


def add_waiver(state_dir, repo, pr, head, ticket, reason, approved_by, source="asserted", now=None):
    state_dir = Path(state_dir)
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", str(repo)):
        raise ValueError("repo must be owner/name")
    if not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be a positive integer")
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", str(head)):  # red-team L1: no trailing newline
        raise ValueError("head must be the full lowercase SHA")
    if not re.match(r"^GoodQA (?:[\w-]+)?#\d+$", str(ticket)):
        raise ValueError("ticket must look like 'GoodQA #123' or 'GoodQA project#123'")
    if not (10 <= len(str(reason)) <= 500) or CTRL.search(str(reason)):
        raise ValueError("reason must be 10 to 500 printable characters")
    if not re.match(r"^main:[A-Za-z0-9_.:()-]{3,80}$", str(approved_by)):
        raise ValueError("approved_by must be a main-prefixed agent id")
    lock = _lock(state_dir)
    try:
        record = _append_waiver_record(state_dir, {
            "event": "waive", "id": "mgw-" + uuid.uuid4().hex[:12], "ts": now or time.time(), "repo": repo.lower(),
            "pr": pr, "head": head, "ticket": ticket, "reason": reason, "approved_by": approved_by,
            "approval_source": source})
    finally:
        _unlock(lock)
    return record


def add_review_waiver(state_dir, reference, *, store=None, now=None):
    """Authorize only a loaded, settled, independent pure PR PASS FINAL.

    All merge binding and reviewer identity comes from validated evidence; callers
    cannot supply hashes or override them. Deterministic replay stays idempotent.
    """
    import usage_guard

    store = store or usage_guard.UsageStore()
    evidence = store.inspect(reference)
    review = evidence.get('review')
    if not isinstance(review, dict):
        raise ValueError('merge authorization needs typed PR review FINAL evidence')
    usage_guard.validate_review_metadata(review, result=evidence.get('result'))
    usage = evidence.get('usage') if isinstance(evidence.get('usage'), dict) else {}
    reviewer = review.get('reviewer', '')
    reviewer_harness = review.get('reviewer_harness')
    expected_prefix = {'openai': 'Codex ', 'claude': 'Claude '}.get(reviewer_harness)
    if (evidence.get('review_finalization') != 'SETTLED'
            or evidence.get('execution') != 'COMPLETED' or evidence.get('result') != 'CHECK_OK'
            or evidence.get('reason') != 'NONE'
            or evidence.get('invocation', {}).get('purpose') != 'peer-review-pr'
            or review.get('stage') != 'PR' or review.get('verdict') != 'ACCEPT'
            or review.get('findings') != [] or review.get('ticketed')
            or not all(key in review for key in ('repo', 'pr', 'head', 'report_sha256'))
            or evidence.get('subject', {}).get('head') != review['head']
            or review.get('author_harness') not in {'claude', 'openai'}
            or reviewer_harness not in {'claude', 'openai'}
            or reviewer_harness == review['author_harness']
            or not expected_prefix or not reviewer.startswith(expected_prefix)
            or type(usage.get('provider_launches')) is not int or usage['provider_launches'] < 1):
        raise ValueError('FINAL is not settled independent pure PR PASS evidence')
    repo, pr, head = review['repo'], review['pr'], review['head']
    report_sha256, final_sha256 = review['report_sha256'], reference['sha256']
    state_dir = Path(state_dir)
    wid = "mgw-review-" + hashlib.sha256(
        f"{repo.lower()}|{pr}|{head}|{report_sha256}|{final_sha256}".encode("utf-8")).hexdigest()[:24]
    lock = _lock(state_dir)
    try:
        records = _read_waivers(state_dir)
        existing = next((row for row in records if row.get("event") == "waive" and row.get("id") == wid), None)
        if existing is not None:
            expected = (repo.lower(), pr, head, report_sha256, final_sha256)
            actual = (existing.get("repo"), existing.get("pr"), existing.get("head"),
                      existing.get("report_sha256"), existing.get("final_sha256"))
            if actual != expected:
                raise Corrupt("review waiver id does not match its evidence")
            return existing
        record = _append_waiver_record(state_dir, {
            "event": "waive", "id": wid, "ts": now if now is not None else time.time(),
            "repo": repo.lower(), "pr": pr, "head": head,
            "ticket": "peer-review:" + report_sha256,
            "reason": "Settled independent PR PASS bound to report and FINAL bytes",
            "approved_by": "main:peer-review", "approval_source": "settled-review",
            "reviewer": reviewer, "report_sha256": report_sha256, "final_sha256": final_sha256})
    finally:
        _unlock(lock)
    return record


def consume_waiver(state_dir, repo, pr, head, command_hash, now=None, review_ok=True):
    state_dir = Path(state_dir)
    try:
        lock = _lock(state_dir)
    except (Corrupt, OSError):
        return None
    try:
        records = _read_waivers(state_dir)
        waiver = _active(records, repo, pr, head, now or time.time(), review_ok)
        if not waiver:
            return None
        _append_waiver_record(state_dir, {"event": "consume", "waiver": waiver["id"], "ts": now or time.time(),
                                          "command_sha256": command_hash})
        return waiver["id"]
    except (Corrupt, OSError):
        return None
    finally:
        _unlock(lock)


def put_stamp(state_dir, key, approved_by, now=None):
    folder = Path(state_dir) / APPROVALS_DIR
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = folder / (key + ".tmp")
    tmp.write_text(json.dumps({"approved_by": approved_by, "ts": now or time.time()}), encoding="utf-8")
    os.chmod(str(tmp), 0o600)
    os.replace(str(tmp), str(folder / (key + ".json")))


def take_stamp(state_dir, key, now=None):
    path = Path(state_dir) / APPROVALS_DIR / (key + ".json")
    try:
        data = json.loads(safe_input.read_bounded(str(path), 4096).decode("utf-8"))
        path.unlink()
        if (now or time.time()) - float(data["ts"]) > STAMP_TTL_SECONDS:
            return None
        return str(data["approved_by"])
    except (OSError, ValueError, KeyError, safe_input.InputRejected):
        return None


def _audit(state_dir, record):
    try:
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = state_dir / AUDIT_FILE
        if path.exists() and path.stat().st_size > 5 * 1024 * 1024:
            os.replace(str(path), str(state_dir / (AUDIT_FILE + ".1")))
        fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass


def report_text(state_dir):
    state_dir = Path(state_dir)
    lines = ["Merge gate waivers and decisions"]
    try:
        records = _read_waivers(state_dir)
    except Corrupt as error:
        return "\n".join(lines + [f"CORRUPT: {error}. No waiver is honoured until the log is reviewed."])
    used = {r.get("waiver"): r for r in records if r.get("event") == "consume"}
    waivers = [r for r in records if r.get("event") == "waive"]
    lines.append(f"waivers: {len(waivers)}")
    for w in waivers:
        state = "used" if w["id"] in used else ("expired" if time.time() > w["ts"] + WAIVER_TTL_SECONDS else "unused")
        lines.append(f"  {w['id']} {w['repo']}#{w['pr']} head {w['head'][:12]} {w['ticket']} {state} "
                     f"approved_by {w['approved_by']} ({w['approval_source']}) at "
                     f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(w['ts']))}: {clean(w['reason'], 120)}")
    try:
        tail = safe_input.read_tail(str(state_dir / AUDIT_FILE), 32768).decode("utf-8", "replace").splitlines()[-15:]
    except (safe_input.InputRejected, OSError):
        tail = []
    lines.append(f"recent decisions: {len(tail)}")
    for raw in tail:
        try:
            r = json.loads(raw)
            lines.append(f"  {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(r.get('ts', 0)))} {r.get('outcome')} "
                         f"{r.get('repo')}#{r.get('pr')} {str(r.get('head'))[:12]}")
        except ValueError:
            continue
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------- hook

def command_text(tool_input):
    """str command, or None when the shape is not a command we understand (lists of str are argv)."""
    value = tool_input.get("command", tool_input.get("cmd")) if isinstance(tool_input, dict) else tool_input
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value and all(isinstance(i, str) for i in value):
        if len(value) >= 3 and os.path.basename(value[0]) in SHELLS and value[1] in ("-c", "-lc", "-ec", "-ic"):
            return value[2]
        return " ".join(shlex.quote(i) for i in value)
    return None


def touched_paths(tool_input):
    paths = []
    if isinstance(tool_input, dict):
        for key in ("file_path", "notebook_path", "path"):
            if isinstance(tool_input.get(key), str):
                paths.append(tool_input[key])
        for key in ("input", "patch", "command"):
            value = tool_input.get(key)
            if isinstance(value, str) and "*** Begin Patch" in value:
                paths.extend(re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", value, re.M))
    return paths


def _edit_tool(payload):
    """The canonical field is authoritative even when malformed; aliases cannot repair it."""
    value = payload.get('tool_name') if 'tool_name' in payload else payload.get('toolName')
    return value.lower() if isinstance(value, str) and value.isascii() else ''


def _patch_paths(value):
    if not isinstance(value, str) or len(value) > MAX_COMMAND_CHARS:
        raise GateError('unsupported patch input')
    lines = value.splitlines()
    if (not 2 <= len(lines) <= 10000 or lines[0] != '*** Begin Patch'
            or lines[-1] != '*** End Patch'):
        raise GateError('incomplete patch envelope')
    paths, operation, moved = [], None, False
    for line in lines[1:-1]:
        header = re.fullmatch(r'\*\*\* (Add|Update|Delete) File: (.+)', line)
        if header:
            operation, moved = header[1], False
            paths.append(header[2])
        elif line.startswith('*** Move to: '):
            if operation != 'Update' or moved:
                raise GateError('ambiguous patch move')
            moved = True
            paths.append(line[len('*** Move to: '):])
        elif line == '*** End of File' and operation == 'Update':
            pass
        elif line.startswith('***') or operation is None:
            raise GateError('unsupported patch header')
        elif operation == 'Delete' and line:
            raise GateError('unexpected delete body')
        elif operation == 'Add' and not line.startswith('+'):
            raise GateError('unsupported add body')
        elif operation == 'Update' and line and not line.startswith((' ', '+', '-', '@@')):
            raise GateError('unsupported update body')
    if not paths or len(paths) > 128:
        raise GateError('missing or excessive patch targets')
    return paths


def _edit_paths(tool, value):
    if tool == 'apply_patch':
        if isinstance(value, dict):
            fields = [key for key in ('input', 'patch', 'command', 'cmd') if key in value]
            if len(fields) != 1 or set(value) != set(fields):
                raise GateError('ambiguous patch envelope')
            value = value[fields[0]]
        return _patch_paths(value)
    if not isinstance(value, dict):
        raise GateError('unsupported edit envelope')
    fields = [key for key in ('file_path', 'path', 'notebook_path') if key in value]
    if len(fields) > 1:
        raise GateError('ambiguous edit target')
    if 'edits' in value:
        edits = value['edits']
        if tool != 'multiedit' or not isinstance(edits, list) or not 1 <= len(edits) <= 128:
            raise GateError('unsupported nested edits')
        paths = []
        for entry in edits:
            if not isinstance(entry, dict) or 'edits' in entry:
                raise GateError('unsupported nested edit')
            nested = [key for key in ('file_path', 'path', 'notebook_path') if key in entry]
            if fields:
                if nested:
                    raise GateError('conflicting nested edit target')
            elif len(nested) == 1:
                paths.append(entry[nested[0]])
            else:
                raise GateError('missing nested edit target')
        return [value[fields[0]]] if fields else paths
    if not fields:
        raise GateError('missing edit target')
    return [value[fields[0]]]


def _effective_target(value, payload, *, home_form=False):
    """Snapshot of lexical and resolved destinations, not an atomic write capability."""
    if (not isinstance(value, str) or not value or len(value) > 4096
            or value != value.strip() or CTRL.search(value)):
        raise GateError('invalid edit target')
    if value.startswith('~'):
        if not home_form or not value.startswith('~/'):
            raise GateError('ambiguous home expansion')
        value = str(Path.home() / value[2:])
    target = Path(value)
    if not target.is_absolute():
        cwd = payload.get('cwd')
        # Native and Claude tool hooks supply the actual operation cwd. An absent
        # value cannot be reconstructed from this guard's possibly different cwd.
        if not isinstance(cwd, str) or not Path(cwd).is_absolute() or CTRL.search(cwd):
            raise GateError('relative target needs an absolute operation cwd')
        if not Path(cwd).is_dir():
            raise GateError('operation cwd unavailable')
        target = Path(cwd) / target
    lexical = Path(os.path.normpath(str(target)))
    try:
        resolved = target.resolve(strict=False)
        # Inspect the effective object too: an unresolved raw component before
        # '..' can fail stat while normalization still names an existing alias.
        ancestor = resolved
        while True:
            try:
                info = ancestor.stat()
                break
            except FileNotFoundError:
                parent = ancestor.parent
                if parent == ancestor:
                    raise GateError('target parent unavailable')
                ancestor = parent
        if ancestor == resolved:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise GateError('target is not a single-link regular file')
        elif not stat.S_ISDIR(info.st_mode):
            raise GateError('target parent is not a directory')
    except (OSError, RuntimeError, ValueError) as error:
        raise GateError('target resolution unavailable') from error
    if any(STATE_NAMES.search(str(path)) for path in (target, lexical, resolved)):
        raise GateError('protected state target')
    return lexical, resolved


_LITERAL_PART = r"(?:[A-Za-z0-9_./~:@%+=,\-]+|'[^'\x00]*'|\"(?:[^\"\\$`\x00]|\\[\"\\])*\")"
_LITERAL_WORD = re.compile(_LITERAL_PART + '+')
NATIVE_NOTE_EVENTS = {'intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result'}


def _native_note_data(command, payload):
    """One exact literal note invocation, with no shell expansion, wrapper or second command."""
    if len(command) > MAX_COMMAND_CHARS:
        return False
    words, raw_words, offset = [], [], 0
    while offset < len(command):
        if command[offset] in '\r\n':
            return False  # outside a quoted word, a newline starts another shell command
        if command[offset] in ' \t':
            offset += 1
            continue
        match = _LITERAL_WORD.match(command, offset)
        if not match or (match.end() < len(command) and not command[match.end()].isspace()):
            return False
        raw = match[0]
        try:
            decoded = shlex.split(raw)
        except ValueError:
            return False
        if len(decoded) != 1:
            return False
        words.append(decoded[0]); raw_words.append(raw); offset = match.end()
        if len(words) > 9:
            return False
    if len(words) != 9 or words[0] not in {'python3', 'python'} or words[2] != 'note':
        return False
    helper = Path.home() / '.codex' / 'agent-harness' / 'wal.py'
    if words[1] != str(helper) and raw_words[1] != '~/.codex/agent-harness/wal.py':
        return False
    values = {}
    for index in (3, 5, 7):
        key = words[index]
        if key not in {'--wal', '--event', '--note'} or key in values:
            return False
        values[key] = words[index + 1]
    if (values.get('--event') not in NATIVE_NOTE_EVENTS or not values.get('--note', '').strip()
            or values.get('--note', '').startswith('-') or len(values.get('--note', '')) > 4000):
        return False
    try:
        helper_lexical, helper_real = _effective_target(str(helper), payload)
        if helper_lexical != helper_real or not helper_real.is_file():
            return False
        lexical, resolved = _effective_target(values['--wal'], payload, home_form=True)
        root = Path.home() / '.agent-harness' / 'codex-wals'
        if lexical != resolved or lexical.parent.parent != root:
            return False
        session, filename = lexical.parent.name, lexical.name
        if (not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', session) or session in {'.', '..'}
                or not re.fullmatch(r'main\.jsonl|agent-[A-Za-z0-9._-]{1,120}\.jsonl', filename)):
            return False
    except (GateError, KeyError, OSError, ValueError):
        return False
    return True


def _shell_like(name):
    name = str(name or "").lower()
    return name in SHELL_TOOLS or name.startswith(("bash", "shell", "exec"))


def decide(payload, runner, state_dir, now=None):
    """(exit code, stderr text) for one PreToolUse payload."""
    state_dir = Path(state_dir)
    now = now if now is not None else time.time()
    tool = _edit_tool(payload)
    tool_input = payload.get("tool_input")
    subagent = bool(payload.get("agent_id"))
    if ('tool_name' in payload and not tool
            and _edit_tool({'toolName': payload.get('toolName')}) in WRITE_TOOLS):
        return 2, "merge-gate: malformed canonical edit-tool identity."
    if tool in WRITE_TOOLS:
        try:
            for path in _edit_paths(tool, tool_input):
                _effective_target(path, payload)
        except Exception:
            # A known edit always needs complete target proof. Do not let a
            # resolution fault reach the legacy command-hint fail-open path.
            return 2, "merge-gate: edit targets are protected, ambiguous or unavailable; supply complete ordinary-file targets."
        return 0, ""
    paths = touched_paths(tool_input)
    if any(STATE_NAMES.search(p) for p in paths):
        return 2, "merge-gate: the waiver, audit and approval files are written only by merge_gate.py itself."
    command = command_text(tool_input)
    if command is None:
        if _shell_like(tool):
            return 2, "merge-gate: the shell command has a shape the gate cannot read; run it as one plain command string."
        return 0, ""
    if _native_note_data(command, payload):
        return 0, ""
    plain = re.sub(r"[\"'\\$]", "", command)  # w''aive, $M and escaped spellings
    if STATE_NAMES.search(command) or STATE_NAMES.search(plain):
        return 2, "merge-gate: the waiver, audit and approval files are written only by merge_gate.py itself."
    if subagent and PEER_REVIEW_AUTH.search(plain):
        return 2, ("merge-gate: a subagent cannot run the PR review that mints a merge authorization (--github-repo/"
                   "--pr); run it without the GitHub binding, or ask the main agent.")
    # goodqa#15684: a missing agent_id is not proof of main (Codex hook payloads never carry one), so the waiver path
    # needs the positive proof the review stamp already needs.
    if (STATE_GLOB.search(plain) or _waiver_attempt(command)) and (subagent or not _may_record_waiver(payload)):
        return 2, "merge-gate: only the main agent may record a waiver; ask the main agent."
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    stamp = None
    if WAIVE_CMD.search(command) and not subagent and _plain_waive(command) and _may_record_waiver(payload):
        stamp = _stamp_waive(command, payload, state_dir)  # written only if this decision allows (red-team M1)
    if PEER_REVIEW_AUTH.search(plain):
        _stamp_review(command, payload, now)
    merges = find_merges(command, cwd=cwd)
    if not merges:
        return _allow(stamp, state_dir, now)
    command_hash = hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()
    client = Client(runner, time.monotonic() + _deadline_seconds() - 2, cwd)
    blocks = []
    for merge in merges:
        allowed, text, info = evaluate_merge(merge, client, state_dir, now, command_hash)
        outcome = "waived" if info.get("waiver") else ("allow" if allowed else "block")
        _audit(state_dir, {"ts": now, "outcome": outcome, "repo": info.get("repo"), "pr": info.get("pr"),
                           "head": info.get("head"), "kind": merge.kind, "command_sha256": command_hash,
                           "waiver": info.get("waiver"), "no_ci": info.get("no_ci"), "session": clean(payload.get("session_id") or "", 40)})
        if not allowed:
            blocks.append(text)
    if blocks:
        return 2, "\n".join(blocks)
    return _allow(stamp, state_dir, now)


def _allow(stamp, state_dir, now):
    """Allow the command, writing the pending waive stamp only now that the hook has chosen to allow it, so a command
    this hook blocks leaves no stamp. A write failure means no stamp (the CLI then asks for --approved-by)."""
    if stamp:
        try:
            put_stamp(state_dir, stamp[0], stamp[1], now)
        except OSError:
            pass
    return 0, ""


def _may_record_waiver(payload):
    """Positive proof of who is calling: the main agent (caller_identity.is_main), or the current user-driven Codex
    Desktop root session (native_main.is_desktop_review_root: its own metadata row, nearest verified runtime and signed
    GUI parent; a spawned child, a standalone CLI and a missing or unqualified row are not roots). Any failure to
    decide is not proof."""
    try:
        import caller_identity  # noqa: PLC0415
        if caller_identity.is_main(payload):
            return True
        from native_main import is_desktop_review_root  # noqa: PLC0415
        return is_desktop_review_root(payload) is True
    except Exception:  # noqa: BLE001 - fail closed
        return False


def _plain_waive(command):
    """Only ONE plain `python3 [-I] .../merge_gate.py waive ...` command mints the stamp: no newline, `;`, `&`, `|`,
    backtick, `<`, `>` or `$(` anywhere (so no echo, printf, pipe, redirect, wrapper or quoted separator), the same
    rule `_plain_peer_review` applies to the review stamp."""
    if _SHELL_SYNTAX.search(command):
        return False
    try:
        argv = shlex.split(command, comments=False)
    except ValueError:
        return False
    if not argv or not _PYTHON.fullmatch(os.path.basename(argv[0])):
        return False
    rest = argv[1:]
    while rest and rest[0] in ("-I", "-u", "-B", "-E", "-s"):
        rest = rest[1:]
    return len(rest) >= 2 and os.path.basename(rest[0]) == "merge_gate.py" and rest[1] == "waive"


_HEAD = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


# Anywhere in the raw text, quoted or not: `$` (variables, `$'...'` ANSI-C quoting, `$(`), a backtick, and any control
# character (CR, tab, NUL, DEL, C1). shlex and the shell can split or expand these differently.
_STAMP_UNSAFE_ANYWHERE = re.compile(r"[$`\x00-\x1f\x7f-\x9f]")
# Outside quotes only: comment, brace, glob, zsh glob qualifier, history and tilde characters. Inside single or double
# quotes they are literal to bash, zsh and shlex alike (the ticket is always the quoted 'GoodQA #N').
_STAMP_UNSAFE_UNQUOTED = set("#{}*?[]()!^~")


def _stamp_lexically_safe(command):
    """True when bash, zsh and shlex.split read `command` as the same words: none of _STAMP_UNSAFE_ANYWHERE, none of
    _STAMP_UNSAFE_UNQUOTED outside quotes (a leading `~/`, which both shells expand to $HOME, is the one exception), no
    `=` starting an unquoted word (zsh `=cmd` expansion), and balanced quotes (red-team PR 207 M1)."""
    if _STAMP_UNSAFE_ANYWHERE.search(command):
        return False
    quote, word_start, i = None, True, 0
    while i < len(command):
        char = command[i]
        if quote == "'":
            quote = None if char == "'" else quote
        elif quote == '"':
            if char == "\\":
                i += 1
            elif char == '"':
                quote = None
            elif char == "!":
                return False
        elif char == " ":
            word_start = True
            i += 1
            continue
        elif char in "'\"":
            quote = char
        elif char == "\\":
            i += 1
        elif char == "~" and word_start and command[i + 1:i + 2] == "/":
            pass
        elif char in _STAMP_UNSAFE_UNQUOTED or (char == "=" and word_start):
            return False
        word_start = False
        i += 1
    return quote is None


def _stamp_interpreter_ok(word):
    """`python3` or `python3.N` that this host can actually find on PATH, or an absolute path to an executable file
    with that name. `python3.99` (not installed) and a missing path would make the shell fail after the stamp."""
    if not re.fullmatch(r"python3(?:\.\d+)?", os.path.basename(word)):
        return False
    if "/" not in word:
        return bool(shutil.which(word))
    return os.path.isabs(word) and os.path.isfile(word) and os.access(word, os.X_OK)


def _stamp_gate_paths():
    """The gate copies a stamped command may name: this running file and the two install targets (install.py puts it
    in ~/.claude/hooks, install_codex.py in ~/.codex/agent-harness). Resolved at call time from the current HOME."""
    home = Path(os.path.expanduser("~"))
    return {Path(__file__).resolve(), (home / ".claude" / "hooks" / "merge_gate.py").resolve(),
            (home / ".codex" / "agent-harness" / "merge_gate.py").resolve()}


def _stamp_script_ok(word):
    """The script word must be absolute (or `~/...`) and resolve to an installed gate; a relative path, another
    directory or a missing file elsewhere is not the gate the CLI lookup belongs to."""
    if word.startswith("~/"):
        word = os.path.expanduser(word)
    return os.path.isabs(word) and Path(word).resolve() in _stamp_gate_paths()


def _stamp_waive(command, payload, state_dir):
    """The pending (key, approved_by) stamp for a plain waive command, or None. decide() writes it only when it
    allows the command. A stamp is offered only when:
    - bash, zsh and shlex read the text as the same words (_stamp_lexically_safe),
    - the interpreter is a findable python3 and the script resolves to an installed gate,
    - the strict CLI parser accepts the arguments and reads them unambiguously: no repeated or abbreviated option, no
      `--state-dir` other than the hook's own, no help flag, and values `add_waiver` would accept.
    Anything else leaves no stamp, and the command is still judged normally (red-team m-1, F1, F2, PR 207 M1/L1).
    Stamp-before-run limit: a stamp offered here can still go unconsumed if the user denies the permission prompt or a
    later PreToolUse hook blocks the command; STAMP_TTL_SECONDS (120 s) bounds that."""
    try:
        if not _stamp_lexically_safe(command):
            return None
        argv = shlex.split(command, comments=False)
        if not _stamp_interpreter_ok(argv[0]):
            return None
        rest = argv[1:]
        while rest and rest[0] in ("-I", "-u", "-B", "-E", "-s"):
            rest = rest[1:]
        if not _stamp_script_ok(rest[0]):
            return None
        rest = rest[2:]  # skip merge_gate.py and the subcommand
        names = [t.split("=", 1)[0] for t in rest if t.startswith("--")]
        if len(names) != len(set(names)):
            return None
        args = _build_parser(strict=True).parse_args(["waive"] + rest)
        raw_pr = next((rest[i + 1] for i, t in enumerate(rest[:-1]) if t == "--pr"), None)
        raw_pr = raw_pr if raw_pr is not None else next((t[5:] for t in rest if t.startswith("--pr=")), "")
        if not (raw_pr.isascii() and raw_pr.isdigit()):  # int() also takes spaces, signs, underscores, other scripts
            return None
        if args.state_dir is not None and Path(args.state_dir).resolve() != Path(state_dir).resolve():
            return None
        if not (isinstance(args.pr, int) and args.pr > 0 and _HEAD.fullmatch(args.head or "")):
            return None
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", args.repo) or \
                not re.match(r"^GoodQA (?:[\w-]+)?#\d+$", args.ticket) or not (10 <= len(args.reason) <= 500) or \
                CTRL.search(args.reason):
            return None
    except (_ParseRefused, ValueError, OSError, IndexError, SystemExit):
        # SystemExit: any argparse exit path (red-team L1, `-h`/`--help`) means no stamp, never the end of the hook.
        return None
    session = clean(payload.get("session_id") or "unknown", 40)
    return (stamp_key(args.repo, args.pr, args.head, args.ticket),
            "main:session-" + re.sub(r"[^A-Za-z0-9_.-]", "", session) + "(hook)")


def _stamp_review(command, payload, now):
    """B2: the peer_review run that may mint a merge authorization gets a one-shot stamp, only from proven main."""
    import caller_identity  # noqa: PLC0415
    if not _plain_peer_review(command):
        return
    if not caller_identity.is_main(payload):
        # A Codex Desktop root is accepted here for the review receipt and, by the user's decision (answer
        # b6714826, goodqa#15565), for recording merge waivers (_may_record_waiver). Generic main authority still
        # controls protected Stop and owner handoffs.
        try:
            from native_main import is_desktop_review_root  # noqa: PLC0415
            if is_desktop_review_root(payload) is not True:
                return
        except Exception:
            return
    tokens, _ = tokenize(command)
    values = {}
    for index, token in enumerate(tokens):
        for name in ("--github-repo", "--pr"):
            if token == name and index + 1 < len(tokens):
                values[name] = tokens[index + 1]
            elif token.startswith(name + "="):
                values[name] = token.split("=", 1)[1]
    if values.get("--github-repo") and str(values.get("--pr", "")).isdigit():
        caller_identity.put_stamp("review-auth", [values["--github-repo"], int(values["--pr"])],
                                  session=str(payload.get("session_id") or ""), now=now)


_SHELL_SYNTAX = re.compile(r"[\n;&|`<>]|\$\(")
_PYTHON = re.compile(r"python3?(?:\.\d+)?")


def _plain_peer_review(command):
    """Delta red-team D-F6: only a single plain `python3 [-I] .../peer_review.py ...` command mints the stamp, not an
    echo, a heredoc, a comment or a compound command that merely mentions its options."""
    if _SHELL_SYNTAX.search(command):
        return False
    try:
        argv = shlex.split(command, comments=False)
    except ValueError:
        return False
    if not argv or not _PYTHON.fullmatch(os.path.basename(argv[0])):
        return False
    rest = argv[1:]
    while rest and rest[0] in ("-I", "-u", "-B", "-E", "-s"):
        rest = rest[1:]
    return bool(rest) and os.path.basename(rest[0]) == "peer_review.py"


def _deadline_seconds():
    try:
        value = float(os.environ.get("MERGE_GATE_DEADLINE", DEADLINE_SECONDS))
    except ValueError:
        value = DEADLINE_SECONDS
    return max(1.0, min(value, DEADLINE_SECONDS))


def default_state_dir():
    return Path(os.path.expanduser("~")) / ".agent-harness" / "state"


def hook_main(state_dir, runner, stdin, stdout, stderr):
    real = stdin is None
    if real and hasattr(signal, "SIGALRM"):
        def expired(signum, frame):
            os.write(2, b"merge-gate: the hook ran out of time; blocking.\n")
            os._exit(2)

        signal.signal(signal.SIGALRM, expired)
        signal.alarm(int(_deadline_seconds()) + 1)
    text, payload = "", None
    try:
        stream = stdin if stdin is not None else sys.stdin.buffer
        raw = stream.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            stderr.write("merge-gate: hook input is larger than the cap; blocking.\n")
            return 2
        parsed = safe_input.safe_json_loads(raw, max_depth=60, max_bytes=MAX_STDIN_BYTES)
        if not isinstance(parsed, dict):
            raise ValueError("payload is not an object")
        payload = parsed
        text = json.dumps(payload.get("tool_input"), ensure_ascii=False)[:MAX_COMMAND_CHARS]
        code, message = decide(payload, runner or SubprocessGh(), state_dir)
    except (ValueError, OSError) as error:
        if payload is None:
            stderr.write("merge-gate: hook input is not usable JSON (" + type(error).__name__ + "); blocking.\n")
            return 2
        return _fault(error, text, stderr)
    except BaseException as error:  # noqa: BLE001 - every fault ends in a block or a warning, never a traceback
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _fault(error, text, stderr)
    if code:
        stderr.write(message.rstrip() + "\n")
    return code


def _fault(error, text, stderr):
    """A bug in the gate must not let a merge through, and must not block unrelated commands."""
    if GH_HINT.search(text) or STATE_NAMES.search(text):
        stderr.write(f"merge-gate: the gate failed ({type(error).__name__}) on a command that may merge; blocking. "
                     "Run the merge as a plain `gh pr merge <n> -R owner/repo --match-head-commit <sha>`.\n")
        return 2
    stderr.write(f"merge-gate: warning, the gate failed ({type(error).__name__}); command not blocked.\n")
    return 0


# ---------------------------------------------------------------------------------------------------- cli

class _ParseRefused(Exception):
    """A strict parse refused the arguments (the hook minting a stamp must refuse what the CLI would)."""


class _Parser(argparse.ArgumentParser):
    strict = False

    def error(self, message):
        if self.strict:
            raise _ParseRefused(message)
        super().error(message)


def _build_parser(strict=False):
    """The CLI's own parser. The hook parses a candidate command with the same one (strict, no abbreviations) so a
    stamp is minted only for arguments the CLI reads identically (red-team F1)."""
    parser = _Parser(description="PR merge gate: hook, check, waive, report.", allow_abbrev=not strict,
                     add_help=not strict)  # strict: `-h` is a refused argument, not a print-and-exit
    parser.strict = strict
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for name in ("hook", "report", "check", "waive"):
        p = sub.add_parser(name, allow_abbrev=not strict, add_help=not strict)
        p.strict = strict
        p.add_argument("--state-dir", default=None)
        if name in ("check", "waive"):
            p.add_argument("--repo", required=True)
            p.add_argument("--pr", type=int, required=True)
        if name == "waive":
            p.add_argument("--head", required=True)
            p.add_argument("--ticket", required=True)
            p.add_argument("--reason", required=True)
            p.add_argument("--approved-by", default=None)
    return parser


def main(argv=None, runner=None, stdin=None, stdout=None, stderr=None):
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 3 if error.code else 0
    state_dir = Path(args.state_dir) if args.state_dir else default_state_dir()
    if args.command == "hook":
        return hook_main(state_dir, runner, stdin, stdout, stderr)
    if args.command == "report":
        stdout.write(report_text(state_dir) + "\n")
        return 0
    if args.command == "check":
        client = Client(runner or SubprocessGh(), time.monotonic() + _deadline_seconds() - 2)
        allowed, text, info = evaluate_merge(Merge("check", slug=args.repo, number=str(args.pr)), client, state_dir,
                                             time.time(), "check")
        stdout.write(("merge-gate: all checks green on " + str(info.get("head")) + "\n") if allowed else text + "\n")
        return 0 if allowed else 2
    approved, source = args.approved_by, "asserted"
    if _HEAD.fullmatch(args.head or ""):
        stamped = take_stamp(state_dir, stamp_key(args.repo, args.pr, args.head, args.ticket))
        if stamped:
            approved, source = stamped, "hook"
    if not approved:
        stderr.write("merge-gate: a waiver needs main-agent approval: run it through the main agent so the hook stamps "
                     "it, or pass --approved-by main:<agent-id>. The hook stamps only ONE plain command: a ; & | < > "
                     "backtick, $ or control character anywhere in it, including inside --reason, or an unquoted # "
                     "glob, brace or ~user, means no stamp; a stamp lives 120 s.\n")
        return 3
    try:
        record = add_waiver(state_dir, args.repo, args.pr, args.head, args.ticket, args.reason, approved, source)
    except (ValueError, Corrupt, OSError) as error:
        stderr.write(f"merge-gate: waiver refused: {error}\n")
        return 3
    stdout.write(f"merge-gate: waiver {record['id']} recorded for {record['repo']}#{record['pr']} head "
                 f"{record['head'][:12]} ({source}); single use, expires in 24h.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
