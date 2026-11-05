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
import signal
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
STAMP_TTL_SECONDS = 600
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
STATE_NAMES = re.compile(r"merge-gate[-/](?:waivers|audit|approvals)", re.I)
STATE_GLOB = re.compile(r"merge-gate-[wa*?\[]", re.I)  # subagents: globs and split spellings of the state files
WAIVE_CMD = re.compile(r"merge_gate(?:\.py)?['\"]?\s+(?:--\S+\s+\S+\s+)*waive\b")
WAIVE_ANY = re.compile(r"waive|add_waiver|consume_waiver|put_stamp|take_stamp", re.I)
GRAPHQL_MERGE = re.compile(r"mergePullRequest|enablePullRequestAutoMerge|enqueuePullRequest", re.I)
REST_MERGE = re.compile(r"(?:repos/([^/\s'\"]+)/([^/\s'\"]+)/)?pulls/(\d+)/merge\b")
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
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
            if name in ("gh", "gh.exe"):
                found.extend(_gh_merge(tokens[i + 1:b], seen_xargs, ctx, cwd))
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
        first = next((t for t in seg if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t)
                      and os.path.basename(t) not in WRAPPER_WORDS and not t.startswith("-")), "")
        full_command = " ".join(tokens)
        if MERGE_HINT.search(full_command) and (DYNAMIC_WORD.match(first) or (
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
                    # `tags:` with no value (null) or an empty list is not a tag filter
                    empty = value in ("", "[]", "null", "~", "{}")
                    found[current].add(m.group(1) if not empty else m.group(1) + ":empty")
                    pending = None if not empty else (current, m.group(1))
                elif body.startswith("- "):
                    found[current].add("-")  # a list directly under the trigger
                else:
                    return None
            elif indent < sub:
                return None
            elif pending:  # a nested value under `key:` makes that key non-empty
                found[pending[0]].discard(pending[1] + ":empty")
                found[pending[0]].add(pending[1])
                pending = None
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


INACTIVE_STATES = {"disabled_manually", "disabled_inactivity", "disabled_fork", "deleted"}


def _get_file(client, slug, path, ref):
    """Text of a workflow file at a ref; None when the file does not exist there (404); GateError otherwise."""
    rc, out, err = client.raw(["api", f"repos/{slug}/contents/{path}?ref={urllib.parse.quote(ref, safe='')}"])
    if rc != 0:
        if "404" in (err + out):
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
        if "404" in (err + out):
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
    paths, inactive = [], set()
    for item in listed:
        if not isinstance(item, dict) or item.get("state") not in INACTIVE_STATES | {"active"}:
            raise GateError("the workflow list holds an entry with an unknown state")
        path = str(item.get("path") or "")
        if item["state"] in INACTIVE_STATES:
            inactive.add(path)
        else:
            paths.append(path)
    for path in _workflow_dir(client, slug, head):  # added by the PR, or a listed path (already counted above)
        if path not in inactive and path not in paths:
            paths.append(path)
    reasons = []
    for path in paths:
        if not re.match(r"^\.github/workflows/[\w./-]+$", path) or ".." in path:
            reasons.append("a workflow has an unreadable path")
            continue
        texts = [(label, _get_file(client, slug, path, ref)) for ref, label in ((base, "base"), (head, "head"))]
        if all(t is None for _, t in texts):
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
    if not SHA.match(head):
        raise GateError("the pull request head SHA is missing")
    m = re.match(r"^https://[^/]+/([\w.-]+)/([\w.-]+)/pull/(\d+)", str(pr.get("url") or ""))
    if not m:
        raise GateError("the pull request URL is unreadable")
    real_slug, real_number = m.group(1) + "/" + m.group(2), int(m.group(3))
    if slug and slug.lower() != real_slug.lower():
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
        elif name in apps and not any(e["src"] == "api" and e["app"] in apps[name] and e["v"] == "ok" for e in mine):
            reasons.append(f"required check '{clean(name)}' has no success from the required app")
    if not entries and known and not required:
        # Zero reports: fine only when no ACTIVE workflow could have run on this head (GitHub CI switched off).
        try:
            reasons.extend(_ci_capable_workflows(client, slug, head, base))
        except (GateError, ValueError, TypeError, AttributeError):
            reasons.append("no checks reported and the workflow list could not be read")
    again = client.json(["pr", "view", str(number), "-R", slug, "--json", "headRefOid"], "the pull request head")
    if str((again or {}).get("headRefOid") or "").lower() != head:
        raise GateError("the pull request head moved while the checks were read")
    return {"slug": slug, "number": number, "head": head}, reasons


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
        info.update(repo=details["slug"], pr=details["number"], head=details["head"])
        if merge.kind != "check":
            if merge.head_unknown or not merge.head_vals:
                hard.append(f"the merge must carry the verified head: add {merge.binding.replace('<full head sha>', details['head'])}")
            elif any(h != details["head"] for h in merge.head_vals):
                hard.append("the head SHA in the merge command is not the verified head " + details["head"][:12])
    except GateError as error:
        hard.append(str(error))
    if not hard and not soft:
        return True, "", info
    if not hard and info["head"]:
        wid = consume_waiver(state_dir, info["repo"], info["pr"], info["head"], command_hash, now=now)
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


def _active(records, repo, pr, head, now):
    used = {r.get("waiver") for r in records if r.get("event") == "consume"}
    for r in records:
        if (r.get("event") == "waive" and r.get("id") not in used and str(r.get("repo", "")).lower() == repo.lower()
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
    if not re.match(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", str(head)):
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


def consume_waiver(state_dir, repo, pr, head, command_hash, now=None):
    state_dir = Path(state_dir)
    try:
        lock = _lock(state_dir)
    except (Corrupt, OSError):
        return None
    try:
        records = _read_waivers(state_dir)
        waiver = _active(records, repo, pr, head, now or time.time())
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


def _shell_like(name):
    name = str(name or "").lower()
    return name in SHELL_TOOLS or name.startswith(("bash", "shell", "exec"))


def decide(payload, runner, state_dir, now=None):
    """(exit code, stderr text) for one PreToolUse payload."""
    state_dir = Path(state_dir)
    now = now if now is not None else time.time()
    tool = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    subagent = bool(payload.get("agent_id"))
    paths = touched_paths(tool_input)
    if any(STATE_NAMES.search(p) for p in paths):
        return 2, "merge-gate: the waiver, audit and approval files are written only by merge_gate.py itself."
    command = command_text(tool_input)
    if command is None:
        if _shell_like(tool):
            return 2, "merge-gate: the shell command has a shape the gate cannot read; run it as one plain command string."
        return 0, ""
    if not _shell_like(tool) and tool.lower() in WRITE_TOOLS:
        return 0, ""
    plain = re.sub(r"[\"'\\$]", "", command)  # w''aive, $M and escaped spellings
    if STATE_NAMES.search(command) or STATE_NAMES.search(plain):
        return 2, "merge-gate: the waiver, audit and approval files are written only by merge_gate.py itself."
    if subagent and (STATE_GLOB.search(plain) or ("merge_gate" in plain.lower() and WAIVE_ANY.search(plain))):
        return 2, "merge-gate: only the main agent may record a waiver; ask the main agent."
    if WAIVE_CMD.search(command):
        if subagent:
            return 2, "merge-gate: only the main agent may record a waiver; ask the main agent."
        _stamp_waive(command, payload, state_dir, now)
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    merges = find_merges(command, cwd=cwd)
    if not merges:
        return 0, ""
    command_hash = hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()
    client = Client(runner, time.monotonic() + _deadline_seconds() - 2, cwd)
    blocks = []
    for merge in merges:
        allowed, text, info = evaluate_merge(merge, client, state_dir, now, command_hash)
        outcome = "waived" if info.get("waiver") else ("allow" if allowed else "block")
        _audit(state_dir, {"ts": now, "outcome": outcome, "repo": info.get("repo"), "pr": info.get("pr"),
                           "head": info.get("head"), "kind": merge.kind, "command_sha256": command_hash,
                           "waiver": info.get("waiver"), "session": clean(payload.get("session_id") or "", 40)})
        if not allowed:
            blocks.append(text)
    if blocks:
        return 2, "\n".join(blocks)
    return 0, ""


def _stamp_waive(command, payload, state_dir, now):
    tokens, _ = tokenize(command)
    values = {}
    for name in ("--repo", "--pr", "--head", "--ticket"):
        if name in tokens and tokens.index(name) + 1 < len(tokens):
            values[name] = tokens[tokens.index(name) + 1]
    if len(values) == 4 and values["--pr"].isdigit():
        session = clean(payload.get("session_id") or "unknown", 40)
        put_stamp(state_dir, stamp_key(values["--repo"], int(values["--pr"]), values["--head"], values["--ticket"]),
                  "main:session-" + re.sub(r"[^A-Za-z0-9_.-]", "", session) + "(hook)", now)


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

def main(argv=None, runner=None, stdin=None, stdout=None, stderr=None):
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    parser = argparse.ArgumentParser(description="PR merge gate: hook, check, waive, report.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("hook", "report", "check", "waive"):
        p = sub.add_parser(name)
        p.add_argument("--state-dir", default=None)
        if name in ("check", "waive"):
            p.add_argument("--repo", required=True)
            p.add_argument("--pr", type=int, required=True)
        if name == "waive":
            p.add_argument("--head", required=True)
            p.add_argument("--ticket", required=True)
            p.add_argument("--reason", required=True)
            p.add_argument("--approved-by", default=None)
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
    if re.match(r"^[0-9a-f]{40}", args.head or ""):
        stamped = take_stamp(state_dir, stamp_key(args.repo, args.pr, args.head, args.ticket))
        if stamped:
            approved, source = stamped, "hook"
    if not approved:
        stderr.write("merge-gate: a waiver needs main-agent approval: run it through the main agent so the hook stamps "
                     "it, or pass --approved-by main:<agent-id>.\n")
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
