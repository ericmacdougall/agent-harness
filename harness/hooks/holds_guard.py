#!/usr/bin/env python3
"""PreToolUse guard for two rule families (rules S03, S08, S09, S11-adjacent; GoodQA rules batch B1, #14543).

0. PUSH SAFETY (rule S17): force pushes (any flag cluster containing f, a `+` refspec) and changing an existing git
   remote (`git remote set-url|rename|remove`, `git config remote.<name>.url|pushurl` or `url.<x>.insteadOf` writes,
   `git -c` overrides of those keys) are denied.
1. HOLDS: the user put yates, Petfiliate and OptinRouter on hold ("do not touch"). While a hold is active this hook
   denies any tool call that reaches a held path or host: every Bash command whose path-like or URL-like operand or
   redirect target names it (ls, rm, find, grep -r, tee, > file, python3 x.py /srv/yates ...), host verbs (ssh, ping,
   docker, psql ...) that name it anywhere, any Read/Write/Edit/Grep/Glob of it, and GoodQA calls whose project,
   ticket or ref fields (or a `name#N` ref value) name a held project. Naming a held project as a plain word (a grep
   filter, an echo, a commit message, a PR body, a `--note`, `-k`, `--grep` or `-d` value, a branch name, an agent
   brief) is allowed: the rule is about access, and a sweep must be able to skip them.
   A hold is lifted only by the USER. `holds.py lift` requires an interactive terminal (agent Bash has none) and a
   transcript-verified human message that is exactly `lift hold <id>`; the guard also denies any agent call of the
   installed holds.py other than `status`, code that calls `holds.lift`, and writes to session transcripts, and it
   re-verifies every lift state entry against the transcript on every call.
2. PROTECTED PATHS: credentials (member.key, *.secret, SSH keys, ~/.aws, rclone config, Keychain files) can not be
   read, copied or searched by an agent, and recursive readers (grep -r, rg, Grep, Glob `**`, tar, cp -r ...) can not
   sweep the home directory or its parents. The installed hooks directory, the settings files that wire it and the
   session transcripts can not be changed by an agent: not through a file tool, and not through Bash (redirect,
   cp/mv/rm/ln/rsync/tar/unzip/git into the directory OR INTO ANY ANCESTOR OF IT such as ~/.claude or ~, in-place
   sed/perl/awk, dd of=, sed `w`, awk `print >`, find -delete, xargs and $(...) pipelines, any mutating verb run with
   the working directory inside it, interpreter code that holds a path into it ...). Changes reach the installed
   hooks through a reviewed branch and install.py, which runs as its own process.

Bash analysis is a bounded best effort, not a shell: it expands braces (lists and ranges, up to MAX_BRACE words),
NAME=value assignments and HOME/TMPDIR/USER, globs (relative to a simulated cd/pushd/popd stack), sh -c / eval
strings and $(...) / `...` / <(...) bodies (as mutating), reads heredoc bodies fed to interpreters, normalizes
Unicode (NFKC, zero-width characters) and resolves symlinks. GoodQA calls are matched by project name, slug or ref
and by the ids listed in holds.json "projects"; those ids must come from the user (nobody lists or opens a held
project to find them), so a call that names a held project only by an unlisted uuid is not recognised.

ACCEPTED LIMITS (by design; this stops realistic single-command bypasses and accidents, not a determined adversary
running as the same user): a script file the agent wrote (`python3 /tmp/x.py`, `bash x.sh`), strings computed at run
time (concatenation inside -c code, `echo cmd | sh`, variables from the session environment), `git -c alias.x='!...'`,
ssh aliases that holds.json does not list, and `gh api` force operations are not visible to a static check. The lift
authority does not depend on this guard: it is the transcript-verified `lift hold <id>` human message.

FAILS CLOSED: unparseable input, a non-object payload, a wrongly typed field on a checked tool, an oversized command,
a too-large brace expansion, nesting deeper than MAX_DEPTH, a check that runs past its deadline, or any crash of this
script produces a deny with a clear message. A missing or invalid holds.json falls back to the built-in minimum
policy, and the file can only add to the built-in holds.
"""
from __future__ import annotations

import fnmatch
import glob
import itertools
import json
import os
import re
import shlex
import signal
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "holds.json"
STATE = HERE / "holds.state.json"
MAX_INPUT = 4_000_000
MAX_COMMAND = 64_000
MAX_GLOB = 200
MAX_BRACE = 4096
MAX_DEPTH = 3
DEADLINE_S = 4.0

BUILTIN = {
    "holds": [
        {"id": "yates", "patterns": [r"yates", r"apex_app_pos"], "projects": [], "note": "user hold 2026-11-05"},
        {"id": "petfiliate", "patterns": [r"petfiliate"], "projects": [], "note": "user hold 2026-11-05"},
        {"id": "optinrouter", "patterns": [r"optinrouter", r"optin-router"], "projects": [], "note": "user hold 2026-11-05"},
    ],
    "protected_paths": ["*/member.key", "member.key", "*.secret", "*/Library/Keychains/*", "*/.ssh", "*/.ssh/*",
                        "*/.aws", "*/.aws/*", "*/.config/rclone", "*/.config/rclone/*", "*native-api-key*",
                        "*solve*owner*phrase*", "*/goodqa-hive*/*key*"],
    "policy_files": ["holds.json", "holds.state.json", "holds_guard.py", "holds.py"],
}
# verbs whose bare (non-path) operands name a remote host or resource: every operand is scanned for hold names
HOST_VERBS = {"ssh", "scp", "sftp", "mosh", "ping", "nc", "ncat", "telnet", "ftp", "dig", "nslookup", "traceroute",
              "host", "whois", "docker", "kubectl", "psql", "mysql", "aws", "gcloud", "rsync"}
# verbs whose operands are paths on another machine: the local guarded-area checks do not apply to them
REMOTE_ONLY = {"ssh", "mosh", "ping", "nc", "ncat", "telnet", "ftp", "dig", "nslookup", "traceroute", "host", "whois"}
# option values that are text, not paths or hosts: never scanned for hold names
TEXT_FLAGS = {"-m", "--message", "--title", "--body", "--note", "--notes", "--subject", "--description", "--reason",
              "--comment", "--label", "--grep", "--prompt", "--text", "--summary", "--author", "--keyword", "--match"}
VERB_TEXT_FLAGS = {"git": {"-S", "-G", "--pickaxe-regex", "--format", "--pretty"},
                   "curl": {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "-F",
                            "--form", "-H", "--header"},
                   "pytest": {"-k"}, "python3": {"-k"}, "python": {"-k"}, "npm": set(), "gh": {"-b", "-t"}}
READ_VERBS = {"cat", "less", "more", "head", "tail", "cp", "mv", "base64", "xxd", "od", "strings", "grep", "rg",
              "sed", "awk", "openssl", "scp", "rsync", "tar", "zip", "gzip", "curl", "wget", "cut", "tr", "diff",
              "source", ".", "bat", "nl", "tac", "sort", "uniq", "python3", "python", "node", "ruby", "perl",
              "xargs", "ln", "dd", "pbcopy", "open", "code", "vim", "nano", "view", "emacs", "jq", "yq", "file",
              "hexdump", "wc", "cmp", "rev", "ssh-keygen", "find", "tee", "ag", "ack"}
RECURSIVE_READERS = {"tar", "zip", "cp", "rsync", "grep", "rg", "find", "ag", "ack", "du"}
# verbs that write a named file by nature (a transcript operand of any other verb, e.g. a script reading it, is fine)
TRANSCRIPT_WRITERS = {"cp", "mv", "tee", "dd", "ln", "rm", "truncate", "touch", "install", "rsync", "ditto", "tar",
                      "unzip", "sed", "gsed", "perl", "awk", "gawk", "chmod", "chown", "shred", "split", "patch"}
DEFAULT_CWD_SEARCHERS = {"rg", "ag", "ack"}  # search the working directory recursively when no path is given
TEXT_ONLY = {"echo", "printf", ":", "true", "false"}  # their plain-word arguments name nothing
READONLY = {"cat", "less", "more", "head", "tail", "grep", "rg", "ls", "wc", "diff", "jq", "stat", "file", "echo",
            "printf", "true", "false", ":", "test", "[", "pwd", "which", "type", "du", "df", "sort", "uniq", "cut",
            "tr", "nl", "tac", "bat", "xxd", "od", "strings", "cmp", "base64", "hexdump", "realpath", "dirname",
            "basename", "readlink", "ag", "ack", "date", "whoami", "id", "uname", "env", "printenv", "column"}
READONLY_GIT = {"status", "log", "diff", "show", "branch", "rev-parse", "ls-files", "blame", "grep", "describe",
                "remote", "config", "ls-remote", "fetch", "cat-file", "shortlog", "reflog", "tag", "worktree",
                "rev-list", "name-rev", "for-each-ref", "merge-base", "var", "version", "help"}
GIT_TREE_WRITERS = {"reset", "checkout", "restore", "switch", "merge", "pull", "rebase", "cherry-pick", "revert",
                    "stash", "apply", "am", "clean", "rm", "mv", "read-tree", "checkout-index", "sparse-checkout",
                    "filter-branch", "submodule"}
INTERPRETERS = {"python3", "python", "node", "perl", "ruby", "php", "osascript"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "env", "nohup", "time", "command", "exec", "timeout", "builtin", "nice", "stdbuf", "caffeinate"}
SECURITY_VERBS = re.compile(r"^(find|dump|export|delete|import)-")
FILE_TOOLS = {"Read": ("file_path", "notebook_path"), "Write": ("file_path",), "Edit": ("file_path",),
              "MultiEdit": ("file_path",), "NotebookEdit": ("notebook_path",), "Grep": ("path", "glob"),
              "Glob": ("path", "pattern"), "LS": ("path",)}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GOODQA_KEY_WORDS = {"project", "projects", "ticket", "tickets", "ref", "refs", "slug"}
LIFT_CODE_RE = re.compile(r"\bholds\s*\.\s*(lift|_interactive)\b|\bfrom\s+holds\s+import\b[^\n]*\b(lift|_interactive)\b")
WRITE_CALL_RE = re.compile(
    r"open\s*\([^)]*['\"][^'\"]*[wax+][^'\"]*['\"]|write_text|write_bytes|\.unlink|os\.remove|os\.rename|os\.replace"
    r"|shutil\.|rmtree|symlink|os\.link|chmod|chown|subprocess|os\.system|popen|extractall|mkdir|makedirs|copyfile"
    r"|writeFile|appendFile|fs\.(write|rename|unlink|rm|cp|copy|symlink|mkdir)|File\.write|IO\.write|unlink\s*\(|rename\s*\("
    r"|system\s*\(|>>?\s*['\"$]")
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"))
OPERATORS = {";", "&&", "||", "|", "&", "(", ")", ";;", "|&"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", ">|", "&>"}
HEREDOC_RE = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
DURATION_RE = re.compile(r"^\d+(\.\d+)?[smhd]?$")


class Bad(Exception):
    """Input that can not be judged safely: the caller denies."""


def clean(text: str) -> str:
    if "\x00" in text:
        raise Bad("a path or command contains a NUL byte")
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def valid_policy(data) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("holds"), list) or not data["holds"]:
        return False
    for h in data["holds"]:
        if not (isinstance(h, dict) and isinstance(h.get("id"), str) and h["id"]
                and isinstance(h.get("patterns"), list) and h["patterns"]
                and all(isinstance(p, str) and p for p in h["patterns"])):
            return False
        try:
            for p in h["patterns"]:
                re.compile(p)
        except re.error:
            return False
        if not isinstance(h.get("projects", []), list):
            return False
    for key in ("protected_paths", "policy_files"):
        if key in data and not (isinstance(data[key], list) and all(isinstance(x, str) for x in data[key])):
            return False
    return True


def load_policy(path: Path | None = None) -> tuple[dict, str]:
    """BUILTIN plus whatever holds.json adds; a damaged or empty file never turns protection off."""
    try:
        data = json.loads((path or POLICY).read_text())
        if not valid_policy(data):
            raise ValueError("shape")
    except (OSError, ValueError):
        return BUILTIN, "holds.json missing or invalid: using the built-in minimum policy"
    ids = {h["id"] for h in data["holds"]}
    holds = list(data["holds"]) + [h for h in BUILTIN["holds"] if h["id"] not in ids]
    merged = {"holds": holds}
    for key in ("protected_paths", "policy_files"):
        merged[key] = list(dict.fromkeys(list(data.get(key, [])) + BUILTIN[key]))
    return merged, ""


def lifted_ids(finder=None) -> set[str]:
    """Hold ids lifted through holds.py. Each state entry is re-verified against the user's transcript on every call
    (holds.verify_user_source: a human message that is exactly `lift hold <id>`), so a hand-written state file or an
    unrelated human message lifts nothing. Any failure to verify counts as not lifted."""
    try:
        lifted = json.loads(STATE.read_text()).get("lifted", {})
        if not isinstance(lifted, dict) or not lifted:
            return set()
    except (OSError, ValueError, AttributeError):
        return set()
    out = set()
    try:
        sys.path.insert(0, str(HERE))
        import holds
    except Exception:  # noqa: BLE001 - no verifier available: nothing is lifted
        return set()
    for hold_id, entry in lifted.items():
        try:
            excerpt = str(entry["excerpt"]).replace("\\", "\\\\").replace('"', '\\"')
            holds.verify_user_source(f'user:{entry["session"]}/{entry["source_uuid"]} "{excerpt}"', finder, hold_id)
            out.add(hold_id)
        except Exception:  # noqa: BLE001
            continue
    return out


def claude_home() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured) if configured else Path(os.path.expanduser("~")) / ".claude"


def settings_files() -> list[Path]:
    return [HERE.parent / "settings.json", HERE.parent / "settings.local.json"]


_ROOTS_CACHE: dict = {}


def guarded_roots(policy: dict | None = None) -> list[str]:
    """Real paths an agent may not change: the hooks directory this guard lives in, the installed hooks directory of
    the Claude home, and the settings files of both."""
    key = (str(HERE), os.environ.get("HOME", ""), os.environ.get("CLAUDE_CONFIG_DIR", ""))
    if key not in _ROOTS_CACHE:
        home = claude_home()
        paths = [HERE, home / "hooks"] + settings_files() + [home / "settings.json", home / "settings.local.json"]
        _ROOTS_CACHE[key] = list(dict.fromkeys(os.path.realpath(p) for p in paths))
    return _ROOTS_CACHE[key]


def transcripts_dir() -> str:
    return os.path.realpath(claude_home() / "projects")


def holds_cli_paths() -> set[str]:
    return {os.path.realpath(HERE / "holds.py"), os.path.realpath(claude_home() / "hooks" / "holds.py")}


def inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def forms(path: str, cwd: str) -> set[str]:
    """The text of a path as written, normalized, and with symlinks resolved (relative to cwd when not absolute)."""
    text = clean(path)
    expanded = os.path.expanduser(text)
    if not os.path.isabs(expanded) and cwd:
        expanded = os.path.join(cwd, expanded)
    return {text, os.path.normpath(expanded), os.path.realpath(expanded)}


def resolve(path: str, cwd: str) -> str:
    expanded = os.path.expanduser(clean(path))
    return os.path.realpath(expanded if os.path.isabs(expanded) or not cwd else os.path.join(cwd, expanded))


def protected(path_forms: set[str], globs: list[str]) -> str | None:
    for p in path_forms:
        base = os.path.basename(p)
        if base.endswith(".pub") or (base in ("known_hosts", "config") and "/.ssh/" in p):
            continue
        for g in globs:
            if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(base, g):
                return g
    return None


POLICY_MSG = ("the installed hooks directory and the settings files are changed only through a reviewed branch and "
              "install.py, not by an agent")
TRANSCRIPT_MSG = "session transcripts are written only by Claude Code, not by an agent (they are the lift authority)"
ANCESTOR_MSG = POLICY_MSG + " (the target is a directory that contains them; name a destination below it)"


def guard_hit(path_forms, transcripts: bool = True) -> str | None:
    """Why a path is agent-immutable (inside the hooks dir or settings, or a session transcript), else None."""
    roots = guarded_roots()
    if any(inside(p, r) for p in path_forms for r in roots):
        return POLICY_MSG
    if not transcripts:
        return None
    proj = transcripts_dir()
    if any(inside(p, proj) and p != proj and p.endswith(".jsonl") for p in path_forms):
        return TRANSCRIPT_MSG
    return None


def in_guarded_area(path_forms: set[str], policy: dict | None = None) -> bool:
    return guard_hit(path_forms) is not None


def ancestor_of_guarded(real: str) -> bool:
    """A strict ancestor of a guarded root (~/.claude, ~, /Users, /): writing into it can replace the root."""
    return any(inside(r, real) and r != real for r in guarded_roots())


def ancestor_of_secrets(real: str) -> bool:
    """A strict ancestor of the user's home secrets (home itself, its parent): recursive readers must name a subdirectory."""
    home = os.path.realpath(os.path.expanduser("~"))
    return real in (home, os.path.dirname(home), "/") or real == "/Users"


def held(texts, policy: dict, lifted: set[str]) -> dict | None:
    for h in policy["holds"]:
        if h["id"] in lifted:
            continue
        for pat in h["patterns"]:
            for text in texts:
                if re.search(pat, text, re.I):
                    return h
    return None


def url_like(word: str) -> bool:
    return bool(re.match(r"^[A-Za-z][\w+.-]*://", word) or re.match(r"^[\w.+-]+@[\w.-]+", word))


def pathlike(word: str, sim: str = "") -> bool:
    if "/" in word or word.startswith(("~", ".")) or url_like(word) or re.match(r"^[\w.+-]+:", word):
        return True
    return bool(sim and word and not word.startswith("-") and os.path.lexists(os.path.join(sim, os.path.expanduser(word))))


def strict_pathlike(word: str, sim: str = "") -> bool:
    """For git, whose operands are mostly refs (feat/x): only explicit paths, URLs, host:path and existing names."""
    if word.startswith(("/", "~", "./", "../")) or word in (".", "..") or url_like(word) \
            or re.match(r"^[\w.+-]+:(?!$)", word):
        return True
    return bool(sim and word and not word.startswith("-") and os.path.lexists(os.path.join(sim, os.path.expanduser(word))))


def expansions(word: str, cwd: str) -> list[str]:
    if not re.search(r"[*?\[]", word):
        return []
    expanded = os.path.expanduser(word)
    if not os.path.isabs(expanded) and cwd:
        expanded = os.path.join(cwd, expanded)
    try:
        return list(itertools.islice(glob.iglob(expanded), MAX_GLOB))
    except Exception:  # noqa: BLE001
        return []


def _brace_alternatives(inner: str):
    if "," in inner:
        return inner.split(",")
    m = re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?", inner)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        step = abs(int(m.group(3) or 1)) or 1
        if abs(b - a) // step + 1 > MAX_BRACE:
            raise Bad("brace expansion is too large to check")
        pad = max(len(m.group(1)), len(m.group(2))) if re.match(r"^-?0\d", m.group(1) + " ") or \
            re.match(r"^-?0\d", m.group(2) + " ") else 0
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [str(n).zfill(pad) if pad else str(n) for n in rng]
    m = re.fullmatch(r"([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?", inner)
    if m:
        a, b = ord(m.group(1)), ord(m.group(2))
        step = abs(int(m.group(3) or 1)) or 1
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [chr(n) for n in rng]
    return None


def brace_expand(word: str) -> list[str]:
    """Bash-style {a,b} and {1..5}/{a..e} expansion (nested), capped at MAX_BRACE words; `${v}`, `{}` and `{x}` stay
    literal; a word without braces is returned unchanged."""
    out = [word]
    for _ in range(32):
        nxt, changed = [], False
        for w in out:
            for m in re.finditer(r"\{([^{}]*)\}", w):
                if m.start() > 0 and w[m.start() - 1] == "$":
                    continue
                alts = _brace_alternatives(m.group(1))
                if alts is None:
                    continue
                changed = True
                for part in alts:
                    nxt.append(w[:m.start()] + part + w[m.end():])
                    if len(nxt) > MAX_BRACE:
                        raise Bad("brace expansion is too large to check")
                break
            else:
                nxt.append(w)
        out = nxt
        if not changed:
            break
    return out


def split_heredocs(command: str):
    """(command without heredoc bodies, [(line prefix, body)]); bodies are checked only when they feed an interpreter."""
    lines, kept, bodies, i = command.split("\n"), [], [], 0
    while i < len(lines):
        line = lines[i]
        kept.append(line)
        i += 1
        for m in HEREDOC_RE.finditer(line):
            tag, body = m.group(2), []
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append((line[:m.start()], "\n".join(body)))
    return "\n".join(kept), bodies


def substitutions(command: str) -> list[str]:
    """Bodies of $(...), `...`, <(...) and >(...) outside single quotes (also inside double quotes)."""
    out, i, n, quote = [], 0, len(command), None
    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "'" and quote is None:
            quote = "'"
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "`":
            j = command.find("`", i + 1)
            j = n if j < 0 else j
            out.append(command[i + 1:j])
            i = j + 1
            continue
        elif c in "$<>" and command.startswith("(", i + 1) and not command.startswith("((", i + 1):
            depth, j, q = 1, i + 2, None
            while j < n and depth:
                d = command[j]
                if q:
                    if d == q:
                        q = None
                elif d in "'\"":
                    q = d
                elif d == "\\":
                    j += 1
                elif d == "(":
                    depth += 1
                elif d == ")":
                    depth -= 1
                j += 1
            out.append(command[i + 2:j - 1] if depth == 0 else command[i + 2:])
            i = j
            continue
        i += 1
    return out


def tokens(command: str) -> list[str]:
    command = command.replace("\\\n", "").replace("\r", " ").replace("\n", " ; ")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()


def segments(toks: list[str]) -> list[tuple[list[str], list[str], list[str], list[str]]]:
    """[(words, output redirect targets, input redirect files, here-strings)] with operators removed; heredoc tags
    are none of them."""
    out, words, targets, inputs, here, i = [], [], [], [], [], 0
    while i < len(toks):
        t = toks[i]
        if t in OPERATORS or (t and set(t) <= set(";&|()") and t not in REDIRECTS):
            if words or targets or inputs or here:
                out.append((words, targets, inputs, here))
            words, targets, inputs, here = [], [], [], []
        elif t in REDIRECTS or (t and set(t) <= set("<>&|") and t.endswith((">", "<"))):
            if i + 1 < len(toks) and (t == "<<<" or not toks[i + 1].isdigit()):
                if t in ("<", "<&"):
                    inputs.append(toks[i + 1])
                elif t == "<<<":
                    here.append(toks[i + 1])
                elif t not in ("<<", "<<-"):
                    targets.append(toks[i + 1])
            i += 1
        else:
            m = re.match(r"^\d*(>>?|<)(.+)$", t)
            if m and not t.startswith("<<"):
                (inputs if m.group(1) == "<" else targets).append(m.group(2))
            else:
                words.append(t)
        i += 1
    if words or targets or inputs or here:
        out.append((words, targets, inputs, here))
    return out


XARGS_VALUE_FLAGS = {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "-J", "-R", "-S"}


def verb_of(words: list[str]) -> tuple[str, list[str]]:
    wrapped = False
    i = 0
    while i < len(words):
        t = words[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in WRAPPERS:
            wrapped = wrapped or t in WRAPPERS
            i += 1
            continue
        if wrapped and (t.startswith("-") or DURATION_RE.match(t)):
            i += 1
            continue
        if os.path.basename(t) == "xargs":  # the command xargs runs is the verb that matters
            j = i + 1
            while j < len(words) and words[j].startswith("-"):
                j += 2 if words[j] in XARGS_VALUE_FLAGS else 1
            if j < len(words):
                verb, args = verb_of(words[j:])
                return verb, args
            return "xargs", words[i + 1:]
        return os.path.basename(t), words[i + 1:]
    return "", []


def git_subcommand(args: list[str]) -> tuple[str, list[str]]:
    """First git subcommand after global options (-C path, -c k=v, --git-dir=..), and the arguments after it."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return a, args[i + 1:]
    return "", []


def git_globals(args: list[str]) -> list[str]:
    """Values of `git -c key=value` before the subcommand."""
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "-c" and i + 1 < len(args):
            out.append(args[i + 1])
            i += 2
        elif a in ("-C", "--git-dir", "--work-tree", "--namespace"):
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            break
    return out


REMOTE_KEY_RE = re.compile(r"(?i)^(remote\.[^=]+\.(url|pushurl)|url\..+\.(insteadof|pushinsteadof))$")


def git_remote_change(args: list[str]) -> bool:
    for value in git_globals(args):
        if REMOTE_KEY_RE.match(value.split("=", 1)[0]):
            return True
    sub, rest = git_subcommand(args)
    if sub == "remote":
        return bool(rest[:1]) and rest[0] in ("set-url", "rename", "remove", "rm", "set-head", "set-branches")
    if sub != "config":
        return False
    flags = [a for a in rest if a.startswith("-")]
    if any(f in ("--edit", "-e") for f in flags):
        return True
    for i, a in enumerate(rest):
        if a in ("--rename-section", "--remove-section") and i + 1 < len(rest) and \
                re.match(r"(?i)^(remote|url)\b", rest[i + 1]):
            return True
    positional = [a for a in rest if not a.startswith("-")]
    for i, a in enumerate(positional):
        if REMOTE_KEY_RE.match(a):
            writes = i + 1 < len(positional) or any(
                f.split("=", 1)[0] in ("--unset", "--unset-all", "--replace-all", "--add") for f in flags)
            if writes:
                return True
    return False


def force_push(args: list[str]) -> bool:
    sub, rest = git_subcommand(args)
    if sub != "push":
        return False
    return any(a in ("--force", "--mirror") or a.startswith("--force") or re.match(r"^-[A-Za-z]*f[A-Za-z]*$", a)
               or (len(a) > 1 and a.startswith("+")) or ":+" in a for a in rest)


def implicit_cwd_write(verb: str, args: list[str]) -> bool:
    """Mutating commands that write into the working directory without naming it."""
    if verb == "git":
        sub, _rest = git_subcommand(args)
        return sub in GIT_TREE_WRITERS and "-C" not in args
    if verb in ("tar", "bsdtar", "gtar"):
        first = args[0] if args else ""
        extract = bool(re.match(r"^-?[A-Za-z]*x", first)) or "--extract" in args or "--get" in args
        return extract and not any(a in ("-C", "--directory") or a.startswith("--directory=") for a in args)
    if verb == "unzip":
        return not any(a == "-d" or a.startswith("-d") and len(a) > 2 for a in args) and "-l" not in args
    if verb == "patch":
        return not any(a in ("-d", "--directory") or a.startswith("--directory=") for a in args)
    if verb == "cpio":
        return any(re.match(r"^-[A-Za-z]*i", a) for a in args)
    return False


def inplace_edit(verb: str, args: list[str]) -> bool:
    for a in args:
        if a.startswith("--in-place"):
            return True
        if verb == "perl" and re.match(r"^-(?![IM])[A-Za-z]*i", a):
            return True
        if verb in ("sed", "gsed") and re.match(r"^-[nEersuzl]*i", a):
            return True
        if verb in ("awk", "gawk") and (a == "-i" or a.startswith("-iinplace")):
            return True
    return False


SED_WRITE_RE = re.compile(r"(?:^|[;\n{}]|\d|\$|/)\s*[wW]\s+\S")
AWK_WRITE_RE = re.compile(r"\bprintf?\b[^;}\n]*>|\bsystem\s*\(|\|\s*\"|\|&")


def script_writes(verb: str, args: list[str]) -> list[str]:
    """sed/awk program texts that write files (`w file`, `s///w file`, `print > "file"`, `system()`)."""
    programs, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "--expression") and i + 1 < len(args):
            programs.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--expression="):
            programs.append(a.split("=", 1)[1])
        elif not a.startswith("-") and not programs:
            programs.append(a)
            break
        elif a in ("-f", "-F", "-v", "--file") and i + 1 < len(args):
            i += 1
        i += 1
    rx = SED_WRITE_RE if verb in ("sed", "gsed") else AWK_WRITE_RE
    return [p for p in programs if rx.search(p)]


def program_targets(verb: str, program: str) -> list[str]:
    """Files a sed (`w file`, `s///w file`) or awk (`print > "file"`) program writes."""
    if verb in ("sed", "gsed"):
        return re.findall(r"(?:^|[;\n{}]|\d|\$|/)\s*[wW]\s+([^\n;}]+)", program)
    return re.findall(r">>?\s*\"([^\"]+)\"", program)


def deny(kind: str, reason: str) -> tuple[str, str]:
    return kind, reason


def check_path(value: str, cwd: str, policy: dict, lifted: set[str], what: str, write: bool, read_check: bool = True):
    pf = forms(value, cwd)
    if read_check:
        hit = protected(pf, policy["protected_paths"])
        if hit:
            return deny("protected-path", f"{what} of a protected credential path ({hit}) is not allowed for agents")
    if write:
        msg = guard_hit(pf)
        if msg:
            return deny("policy-file", msg)
    h = held(pf, policy, lifted)
    if h:
        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): {what} of a held path is not allowed")
    return None


def goodqa_strings(obj, keyed: bool = False):
    """(is this value under a project/ticket/ref key, string) for every string in a tool input, recursively."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            words = {w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", str(k))}
            yield from goodqa_strings(v, keyed or bool(words & GOODQA_KEY_WORDS))
    elif isinstance(obj, list):
        for v in obj:
            yield from goodqa_strings(v, keyed)
    elif isinstance(obj, str):
        yield keyed, obj


def decide_goodqa(tin: dict, policy: dict, lifted: set[str]):
    text = json.dumps(tin)
    for h in policy["holds"]:
        if h["id"] in lifted:
            continue
        for proj in h.get("projects", []):
            if proj and proj in text:
                return deny("hold", f"hold '{h['id']}' is active: GoodQA calls on its project are not allowed")
    for keyed, value in goodqa_strings(tin):
        value = clean(value)
        h = held([value], policy, lifted) if keyed else None
        if not h and re.fullmatch(r"\s*(?:goodqa\s+)?[\w.-]+\s*#\s*\d+\s*", value, re.I):
            h = held([value.split("#", 1)[0]], policy, lifted)
        if h:
            return deny("hold", f"hold '{h['id']}' is active: GoodQA calls on its project are not allowed")
    return None


def decide(payload: dict, policy: dict, lifted: set[str], hooks_dir: Path | None = None, depth: int = 0):
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise Bad("tool_name is missing or not a string")
    tin = payload.get("tool_input")
    raw_cwd = payload.get("cwd", "")
    if not isinstance(raw_cwd, str):
        raise Bad("cwd is not a string")
    cwd = os.path.realpath(raw_cwd) if raw_cwd else ""
    checked = tool in FILE_TOOLS or tool == "Bash" or tool.startswith("mcp__")
    if checked and not isinstance(tin, dict):
        raise Bad(f"tool_input of {tool} is not an object")
    if not checked:
        return None
    # --- file tools
    if tool in FILE_TOOLS:
        for key in FILE_TOOLS[tool]:
            value = tin.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                raise Bad(f"{tool}.{key} is not a string")
            if key == "pattern" and tool == "Grep":
                continue
            for candidate in [value] + expansions(value, cwd):
                r = check_path(candidate, cwd, policy, lifted, tool, tool in WRITE_TOOLS)
                if r:
                    return r
        if tool in ("Grep", "Glob", "LS"):
            base = tin.get("path") or cwd
            if tool == "Glob" and os.path.isabs(os.path.expanduser(tin.get("pattern") or "")):
                pattern = os.path.expanduser(tin["pattern"])
                static = re.split(r"[*?\[{]", pattern, maxsplit=1)[0]
                base, rel = os.path.dirname(static) or "/", pattern[len(os.path.dirname(static)):].lstrip("/")
            else:
                rel = tin.get("pattern") or ""
            if base:
                real = resolve(base, cwd)
                if not tin.get("path") and cwd:
                    r = check_path(cwd, "", policy, lifted, tool, False)
                    if r:
                        return r
                sweeping = tool != "Glob" or bool(re.match(r"^[*?\[{]", rel) and "/" in rel) or rel.startswith("**")
                if sweeping and ancestor_of_secrets(real):
                    return deny("protected-path", f"{tool} over the home directory (or above it) would sweep "
                                "credentials; pass a narrower path")
        return None
    # --- GoodQA calls in held projects
    if tool.startswith("mcp__"):
        if "oodqa" not in tool.lower():
            return None
        return decide_goodqa(tin, policy, lifted)
    command = tin.get("command")
    if not isinstance(command, str):
        raise Bad("Bash command is not a string")
    if len(command) > MAX_COMMAND:
        raise Bad(f"the command is longer than {MAX_COMMAND} characters and can not be checked in time")
    return decide_bash(clean(command), cwd, policy, lifted, depth)


def code_paths(code: str) -> list[str]:
    found = [m.group(2) for m in re.finditer(r"(['\"])((?:(?!\1).){1,1024}?)\1", code, re.S)]
    found += re.findall(r"(?<![\w$])(~[\w.-]*(?:/[^\s'\"`;,()]*)?|/[^\s'\"`;,()]+)", code)
    return [f for f in dict.fromkeys(found) if f and "\n" not in f]


def code_check(code: str, sim: str):
    """Inline interpreter code (-c/-e, heredoc). Denied when it calls holds.lift, holds a path into a guarded root
    (absolute, ~, or relative to the simulated cwd), or writes while naming an ancestor of one or `.claude` + hooks."""
    if LIFT_CODE_RE.search(code):
        return deny("lift-by-agent", "a hold is lifted only by the user in their own terminal; code that calls "
                    "holds.lift is not allowed")
    writes = bool(WRITE_CALL_RE.search(code))
    if writes and re.search(r"\.claude\W{0,6}(hooks|settings)", code):
        return deny("policy-file", POLICY_MSG + " (inline code writes and names the Claude config directory)")
    for cand in code_paths(code):
        absolute = os.path.isabs(os.path.expanduser(cand))
        if not absolute and not sim:
            continue
        pf = forms(cand, sim)
        msg = guard_hit(pf, transcripts=writes)
        if msg:
            return deny("policy-file", msg + " (inline code holds a path into it)")
        if writes and ancestor_of_guarded(resolve(cand, sim)) and (absolute or cand in (".", "..")):
            return deny("policy-file", ANCESTOR_MSG + " (inline code writes and names it)")
    return None


def inline_codes(verb: str, args: list[str]) -> tuple[list[str], str]:
    """(inline code strings, script path) of an interpreter call."""
    codes, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "-e", "-E", "--eval", "-p", "--print", "-r") or re.match(r"^-[A-Za-z]*[ceE]$", a):
            if i + 1 < len(args):
                codes.append(args[i + 1])
            return codes, ""
        if a.startswith("--eval="):
            return [a.split("=", 1)[1]], ""
        if a in ("-m", "-W", "-X", "-I", "-M", "-r", "--require"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return codes, a
    return codes, ""


def holds_cli_check(words: list[str], sim: str, sim_known: bool):
    """(deny or None, is an allowed `holds.py status` run). Any agent call of the installed holds.py other than
    status/help is refused, wherever it sits in the command (python3 -u, script -q /dev/null, env ...)."""
    targets = holds_cli_paths()
    for i, w in enumerate(words):
        if os.path.basename(w) != "holds.py":
            continue
        rel = not os.path.isabs(os.path.expanduser(w))
        if (rel and not sim_known) or resolve(w, sim) in targets:
            if words[i + 1:] in ([], ["status"], ["-h"], ["--help"]):
                return None, True
            return deny("lift-by-agent", "a hold is lifted only by the user: the user sends the message "
                        "`lift hold <id>` and runs `python3 ~/.claude/hooks/holds.py lift <id> --source ...` in their "
                        "own terminal; agents may only run `holds.py status`"), False
    return None, False


def decide_bash(command: str, cwd: str, policy: dict, lifted: set[str], depth: int, force_mut: bool = False):
    command, heredocs = split_heredocs(command)
    subs = substitutions(command)
    if subs and depth >= MAX_DEPTH:
        raise Bad("command substitution is nested too deeply to check")
    for body in subs:  # the body runs, and its output feeds the outer command: check it as mutating
        r = decide_bash(clean(body), cwd, policy, lifted, depth + 1, True)
        if r:
            return r
    env: dict[str, str] = {k: v for k, v in (("HOME", os.path.expanduser("~")), ("TMPDIR", os.environ.get("TMPDIR", "")),
                                             ("USER", os.environ.get("USER", "")),
                                             ("CLAUDE_CONFIG_DIR", os.environ.get("CLAUDE_CONFIG_DIR", ""))) if v}
    # sim_strict: the cwd is unknown because of popd / `cd -` (relative mutating operands are refused); a cd to a
    # $variable makes it unknown too, but only refuses when the cd text names .claude (sim_guard)
    sim, sim_known, sim_guard, sim_strict, stack = cwd, True, False, False, []
    cwd_hold = held([clean(cwd)], policy, lifted) if cwd else None
    all_segments = segments(tokens(command))
    force_mut = force_mut or bool(subs) or any(
        "xargs" in (os.path.basename(x) for x in w) for w, _t, _i, _h in all_segments)
    for words, targets, inputs, here in all_segments:
        for m in (re.match(r"^(?:export\s+)?([A-Za-z_]\w*)=(.*)$", w) for w in words):
            if m:
                env[m.group(1)] = m.group(2)
        env["PWD"] = sim

        def sub(w: str) -> str:
            return re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: env.get(m.group(1) or m.group(2), m.group(0)), w)

        words = [sub(w) for w in words]
        targets = [sub(t) for t in targets]
        inputs = [sub(t) for t in inputs]
        verb, args = verb_of(words)
        r, holds_status = holds_cli_check(words, sim, sim_known) if verb not in READONLY else (None, False)
        if r:
            return r
        holds_status = holds_status and verb in INTERPRETERS
        if cwd_hold and verb != "cd":
            return deny("hold", f"hold '{cwd_hold['id']}' is active: the working directory is inside a held path; "
                        "start the session in another directory")
        codes, script_arg = inline_codes(verb, args) if verb in INTERPRETERS else ([], "")
        script = resolve(script_arg, sim) if script_arg and sim_known else ""
        runs_installed = holds_status or (bool(script) and script.endswith(".py")
                                          and any(inside(script, r) for r in guarded_roots()))
        joined = " ".join(args)
        if verb in SHELLS or verb == "eval":
            payloads = [joined] if verb == "eval" else [args[i + 1] for i, a in enumerate(args[:-1])
                                                        if re.match(r"^-[a-z]*c[a-z]*$", a)]
            if payloads and depth >= MAX_DEPTH:
                raise Bad("shell strings are nested too deeply to check")
            for text in payloads:
                r = decide_bash(clean(text), sim if sim_known else "", policy, lifted, depth + 1, force_mut)
                if r:
                    return r
        if here and verb in SHELLS and not any(re.match(r"^-[a-z]*c[a-z]*$", a) for a in args):
            if depth >= MAX_DEPTH:
                raise Bad("here-strings are nested too deeply to check")
            for text in here:
                r = decide_bash(clean(sub(text)), sim if sim_known else "", policy, lifted, depth + 1, force_mut)
                if r:
                    return r
        if verb in INTERPRETERS and not runs_installed and here and not codes and script_arg in ("", "-"):
            codes = codes + [sub(text) for text in here]
        if verb in INTERPRETERS and not runs_installed:
            for code in codes:
                r = code_check(code, sim if sim_known else "")
                if r:
                    return r
            if sim_known and guard_hit(forms(sim, "")) and (codes or not script_arg):
                return deny("policy-file", POLICY_MSG + " (inline code runs inside the hooks directory)")
        if verb == "security" and args and SECURITY_VERBS.match(args[0]):
            return deny("protected-path", "the macOS security CLI keychain verbs are not allowed for agents")
        if verb == "git":
            if force_push(args):
                return deny("force-push", "force pushes are never allowed (rule: never force-push)")
            if git_remote_change(args):
                return deny("remote-switch", "changing an existing remote (set-url, rename, remove, remote.*.url, "
                            "url.*.insteadOf) is not allowed; declare the remote in the brief")
        # cd / pushd / popd move the simulated working directory (with a pushd stack)
        if verb == "popd":
            if stack:
                sim, sim_known, sim_guard, sim_strict = stack.pop()
            else:
                sim_known, sim_strict = False, True
            continue
        if verb in ("cd", "pushd"):
            target = next((a for a in args if not a.startswith("-") or a == "-"), "" if verb == "pushd" else "~")
            if verb == "pushd":
                stack.append((sim, sim_known, sim_guard, sim_strict))
            if not target:  # pushd with no argument swaps the top two entries
                sim_known, sim_strict = False, True
                continue
            for hit in brace_expand(target):
                for cand in [hit] + expansions(hit, sim):
                    h = held(forms(cand, sim), policy, lifted)
                    if h:
                        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `cd` into a held path is not allowed")
            if target == "-":
                sim_known, sim_strict = False, True
            elif "$" in target or "`" in target:
                sim_known, sim_guard, sim_strict = False, ".claude" in target, False
            elif os.path.isabs(os.path.expanduser(target)) or (sim and sim_known):
                sim, sim_known, sim_guard, sim_strict = resolve(brace_expand(target)[0], sim), True, False, False
            continue
        # operands: every argument, option value, key=value value and redirect target is checked against the
        # guarded areas; text option values (messages, filters, request bodies) are not scanned for hold names
        text_flags = TEXT_FLAGS | VERB_TEXT_FLAGS.get(verb, set())
        git_sub = git_subcommand(args)[0] if verb == "git" else ""
        guard_ops = [(t, True) for t in targets] + [(t, False) for t in inputs]
        hold_ops = [(t, True) for t in targets + inputs]
        text_next, force_next, positional = False, False, 0
        positionals = [a for a in args if not a.startswith("-")]
        dest = positionals[-1] if verb in ("cp", "rsync", "ditto", "scp") and len(positionals) > 1 else None
        for a in args:
            if text_next:
                text_next = False
                if a.startswith("@"):  # curl -d @file reads that file
                    guard_ops.append((a[1:], False))
                continue
            if force_next:
                force_next = False
                guard_ops.append((a, False))
                hold_ops.append((a, True))
                continue
            if a in text_flags:
                text_next = True
                continue
            if a.startswith("--") and "=" in a:
                k, v = a.split("=", 1)
                if k not in text_flags:
                    guard_ops.append((v, False))
                    hold_ops.append((v, None))
                continue
            if verb == "git" and a in ("-C", "--git-dir", "--work-tree"):
                force_next = True
                continue
            if verb == "git" and a == "-c":
                text_next = True
                continue
            if a.startswith("-"):
                m = re.match(r"^-[A-Za-z]([/~.].*)$", a)
                if m:
                    guard_ops.append((m.group(1), False))
                    hold_ops.append((m.group(1), True))
                continue
            positional += 1
            if (script_arg and a == script_arg and runs_installed) or (verb == "git" and positional == 1 and a == git_sub):
                continue
            m = re.match(r"^[A-Za-z_][\w.-]*=(.+)$", a)
            value = m.group(1) if m else a
            if m:
                guard_ops.append((a, False))
            guard_ops.append((value.lstrip("@"), False))
            # git push/fetch/pull: the first operand is the remote, the rest are refspecs (text)
            if verb == "git" and git_sub in ("push", "fetch", "pull") and positional > 2:
                continue
            hold_ops.append((value.lstrip("@"), None))
        mutating = force_mut or not (verb in READONLY or (verb == "git" and git_sub in READONLY_GIT) or runs_installed)
        if verb == "find" and not force_mut and not any(
                a in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls") for a in args):
            mutating = False
        writing_programs = script_writes(verb, args) if verb in ("sed", "gsed", "awk", "gawk") else []
        if verb in ("sed", "gsed", "perl", "awk", "gawk") and not force_mut:  # these write files only in place
            mutating = inplace_edit(verb, args) or bool(writing_programs)
        for program in writing_programs:
            r = code_check(program, sim if sim_known else "")
            if r:
                return r
            guard_ops += [(t.strip(), True) for t in program_targets(verb, program)]
        remote_only = verb in REMOTE_ONLY
        # the working directory: a mutating verb run inside a guarded root, or one that writes into the cwd at an
        # ancestor of it (git reset, tar x, unzip, patch), is denied even with no operand
        if mutating and not runs_installed and not remote_only:
            if sim_known and guard_hit(forms(sim, "")):
                return deny("policy-file", POLICY_MSG + " (the working directory is inside it)")
            if not sim_known and sim_guard:
                return deny("policy-file", POLICY_MSG + " (the working directory may be inside it)")
            if sim_known and sim and implicit_cwd_write(verb, args) and ancestor_of_guarded(sim):
                return deny("policy-file", ANCESTOR_MSG + " (the command writes into the working directory)")
        for raw, is_target in guard_ops:
            if not raw:
                continue
            for value in brace_expand(raw):
                if not sim_known and sim_strict and (mutating or is_target) \
                        and not os.path.isabs(os.path.expanduser(value)) and not value.startswith("-") and not remote_only:
                    return deny("policy-file", "a relative path after an unresolved cd/popd can not be resolved; "
                                "use absolute paths")
                if (mutating or is_target) and "$" in value and ".claude" in value:
                    return deny("policy-file", POLICY_MSG + " (an unresolved variable in a path under .claude)")
                if verb in TEXT_ONLY and not is_target and not force_mut:
                    continue
                candidates = [value] + expansions(value, sim)
                is_path = pathlike(value, sim if sim_known else "")
                if verb in RECURSIVE_READERS and is_path and not is_target and raw != dest:
                    for cand in candidates:
                        if ancestor_of_secrets(resolve(cand, sim)):
                            return deny("protected-path", f"`{verb}` over the home directory would sweep credentials; "
                                        "name a narrower directory")
                if (mutating or is_target) and not remote_only:
                    for cand in candidates:
                        msg = guard_hit(forms(cand, sim), transcripts=is_target or verb in TRANSCRIPT_WRITERS)
                        if msg:
                            return deny("policy-file", msg)
                        if not runs_installed and ancestor_of_guarded(resolve(cand, sim)):
                            return deny("policy-file", ANCESTOR_MSG)
                elif runs_installed:
                    for cand in candidates:
                        msg = guard_hit(forms(cand, sim), transcripts=False)
                        if msg:
                            return deny("policy-file", msg + " (an installed script pointed at it)")
                if verb in READ_VERBS or is_target or force_mut:
                    for cand in candidates:
                        hit = protected(forms(cand, sim), policy["protected_paths"])
                        if hit:
                            return deny("protected-path", f"`{verb or 'redirect'}` of a protected credential path ({hit}) is not allowed")
        # searchers with no path operand sweep the working directory
        if sim_known and (verb in DEFAULT_CWD_SEARCHERS or (verb == "grep" and any(
                re.match(r"^-[A-Za-z]*[rR]", a) or a in ("--recursive", "--dereference-recursive") for a in args))):
            explicit = [v for v, _t in guard_ops if v and not v.startswith("-")]
            if not any(a in ("-e", "-f", "--regexp", "--file") or a.startswith(("--regexp=", "-e")) for a in args):
                explicit = explicit[1:]  # the first operand is the pattern
            if not explicit and ancestor_of_secrets(sim):
                return deny("protected-path", f"`{verb}` with no path searches the working directory, which is the "
                            "home directory (or above it) and would sweep credentials; name a narrower directory")
        # holds: path-like and URL-like operands, and every operand of a host verb
        hold_texts = []
        for raw, forced in hold_ops:
            if not raw:
                continue
            for value in brace_expand(raw):
                if verb in TEXT_ONLY and not forced and not force_mut:
                    continue
                if forced is not None:
                    is_path = forced
                elif verb == "git":
                    is_path = strict_pathlike(value, sim if sim_known else "")
                else:
                    is_path = pathlike(value, sim if sim_known else "")
                hold_texts.append(value)
                if is_path or verb in HOST_VERBS or url_like(value):
                    for cand in [value] + expansions(value, sim):
                        h = held(forms(cand, sim), policy, lifted)
                        if h:
                            return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb or 'redirect'}` naming it is not allowed")
        if verb in HOST_VERBS:
            h = held([clean(" ".join(hold_texts))], policy, lifted)
            if h:
                return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb}` naming it is not allowed")
        for proj in (p for hh in policy["holds"] if hh["id"] not in lifted for p in hh.get("projects", [])):
            if proj and proj in joined:
                return deny("hold", "a held GoodQA project id is named in a command")
    # heredoc bodies that feed an interpreter or a shell
    for prefix, body in heredocs:
        segs = segments(tokens(prefix)) or [([], [], [], [])]
        verb, args = verb_of(segs[-1][0])
        if verb in INTERPRETERS:
            codes, script_arg = inline_codes(verb, args)
            if not codes and (not script_arg or script_arg == "-"):
                r = code_check(body, sim if sim_known else "")
                if r:
                    return r
        elif verb in SHELLS:
            if depth >= MAX_DEPTH:
                raise Bad("shell heredocs are nested too deeply to check")
            r = decide_bash(clean(body), sim if sim_known else "", policy, lifted, depth + 1, force_mut)
            if r:
                return r
    return None


def emit_deny(kind: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": f"holds_guard [{kind}]: {reason}"}}))


def _on_alarm(_signum, _frame):
    raise Bad(f"checking this call took longer than {DEADLINE_S:g} s")


def main() -> int:
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise Bad("hook input is larger than 4 MB")
        try:
            payload = json.loads(raw)
        except ValueError:
            raise Bad("hook input is not valid JSON") from None
        if not isinstance(payload, dict):
            raise Bad("hook input is not a JSON object")
        try:
            signal.signal(signal.SIGALRM, _on_alarm)
            signal.setitimer(signal.ITIMER_REAL, DEADLINE_S)
        except (ValueError, OSError, AttributeError):
            pass  # no alarm available (not the main thread, or a platform without it): the size cap still applies
        policy, warning = load_policy()
        result = decide(payload, policy, lifted_ids())
        if warning:
            print(warning, file=sys.stderr)
        if result:
            emit_deny(*result)
    except Bad as exc:
        emit_deny("input", f"{exc}; failing closed")
    except Exception as exc:  # noqa: BLE001 - fail closed, never silently allow
        emit_deny("guard-error", f"{type(exc).__name__} while checking this call; failing closed")
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except (ValueError, OSError, AttributeError):
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
