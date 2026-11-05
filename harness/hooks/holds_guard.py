#!/usr/bin/env python3
"""PreToolUse guard: holds, credential paths, protected harness files, force pushes (GoodQA rules batch B1, #14543).

THREAT MODEL (docs/holds-guard.md is the long form). This guard stops ACCIDENTAL damage by a cooperating agent:
touching a held project, editing the installed hooks or the settings that wire them by mistake, reading a credential
by mistake, force pushing or switching a remote, and a hold lifted without a real user instruction. It is NOT a
defense against a deliberately malicious agent or user: such an agent can run a script file, compute strings at run
time, plant a pty, or edit anything the same Unix user can edit. Tampering is covered by DETECTION, not prevention:
integrity.py records hashes of the hooks, holds.json, holds.state.json and the settings hook entries off-host and
alerts on a mismatch. Bypasses that need deliberate intent are documented as RESIDUAL, not chased here.

0. PUSH SAFETY (rule S17): force pushes (a flag cluster containing f, --force*, --mirror, a `+` refspec) and changing
   an existing remote (`git remote set-url|rename|remove`, remote.*.url / url.*.insteadOf writes, `git -c` overrides
   of those keys) are denied.
1. HOLDS (S08/S09): while a hold is active, any tool call that reaches a held path or host is denied: a Bash path-like
   or URL-like operand or redirect target naming it, every operand of a host verb (ssh, ping, docker, psql ...), any
   Read/Write/Edit/Grep/Glob of it, a working directory inside it, and GoodQA calls whose project, ticket or ref fields
   (or a `name#N` value) name a held project. Naming a held project as a plain word (a filter, an echo, a commit
   message, a --note, a branch name, an agent brief) is allowed. Lifts: holds.py (a user message verified in the local
   transcript and in the off-host transcript backup); every state entry is re-verified against the local transcript.
2. CREDENTIALS (S03): reading verbs (cat, cp, base64, grep, python3 ...) and file tools on member.key, *.secret, SSH
   private keys, ~/.aws, the rclone config or Keychain files are denied; recursive readers can not sweep the home
   directory or its parents.
3. PROTECTED HARNESS FILES: the installed hooks directory (this guard, holds.py, integrity.py, holds.json,
   holds.state.json and every other hook), ~/.claude/settings.json and settings.local.json, and every project-level
   `.claude/settings.json` / `.claude/settings.local.json`. File tools can not write them. A Bash command whose operand,
   redirect target, option value (`-o`, `--output=`, `of=`, `-C`, `-t` ...), $(...) body or xargs input resolves into
   that set is allowed only when its verb is a PURE READER (cat, head, grep, ls, diff, jq, find without
   -delete/-exec of a writer, git read-only subcommands without --output, sort without -o, python3 running an installed
   hook script by path ...). Everything else touching the set is denied with the path and the safe alternative. A
   destructive verb on a directory that contains the set (~/.claude, ~, a `.claude` directory) is denied too.
   Commands that do not touch the set are not analysed for writes at all, so ordinary work is unaffected.

Bash analysis is a bounded best effort, not a shell: braces (MAX_BRACE words), NAME=value assignments and HOME/TMPDIR,
globs (relative to a simulated cd/pushd/popd), sh -c / eval strings, $(...) bodies and heredocs fed to interpreters or
shells, NFKC + zero-width normalization, symlinks. FAILS CLOSED: unparseable input, a wrongly typed field, an oversized
command, nesting deeper than MAX_DEPTH, the internal DEADLINE_S deadline (a BaseException, so no broad handler can
swallow it) or any crash produce a deny. install.py runs this hook as `python3 -I -S` with onFailure "block", so a
timeout or a crash of the interpreter blocks the call too. A missing or invalid holds.json falls back to the built-in
minimum policy; the file can only add holds.
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
if str(HERE) not in sys.path:  # -I -S: no script dir, no site; siblings (holds, provenance) are found explicitly
    sys.path.insert(0, str(HERE))
POLICY = HERE / "holds.json"
STATE = HERE / "holds.state.json"
MODE_FILE = HERE / "holds_guard_policy.json"
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
    "policy_files": ["holds.json", "holds.state.json", "holds_guard.py", "holds.py", "integrity.py", "holds_guard_policy.json"],
}
SETTINGS_SUFFIXES = ("/.claude/settings.json", "/.claude/settings.local.json")
# verbs whose bare (non-path) operands name a remote host or resource: every operand is scanned for hold names
HOST_VERBS = {"ssh", "scp", "sftp", "mosh", "ping", "nc", "ncat", "telnet", "ftp", "dig", "nslookup", "traceroute",
              "host", "whois", "docker", "kubectl", "psql", "mysql", "aws", "gcloud", "rsync"}
# verbs whose operands are on another machine: local protected-path checks do not apply
REMOTE_ONLY = {"ssh", "mosh", "ping", "nc", "ncat", "telnet", "ftp", "dig", "nslookup", "traceroute", "host", "whois"}
# option values that are text, not paths or hosts
TEXT_FLAGS = {"--source", "-m", "--message", "--title", "--body", "--note", "--notes", "--subject", "--description", "--reason",
              "--comment", "--label", "--grep", "--prompt", "--text", "--summary", "--author", "--keyword", "--match"}
VERB_TEXT_FLAGS = {"git": {"-S", "-G", "--pickaxe-regex", "--format", "--pretty"},
                   "curl": {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "-F",
                            "--form", "-H", "--header"},
                   "pytest": {"-k"}, "python3": {"-k"}, "python": {"-k"}, "gh": {"-b", "-t"}}
# verbs that read a credential when it is an operand
READ_VERBS = {"cat", "less", "more", "head", "tail", "cp", "mv", "base64", "xxd", "od", "strings", "grep", "rg",
              "sed", "awk", "openssl", "scp", "rsync", "tar", "zip", "gzip", "curl", "wget", "cut", "tr", "diff",
              "source", ".", "bat", "nl", "tac", "sort", "uniq", "python3", "python", "node", "ruby", "perl",
              "xargs", "ln", "dd", "pbcopy", "open", "code", "vim", "nano", "view", "emacs", "jq", "yq", "file",
              "hexdump", "wc", "cmp", "rev", "ssh-keygen", "find", "tee", "ag", "ack"}
RECURSIVE_READERS = {"tar", "zip", "cp", "rsync", "grep", "rg", "ag", "ack"}  # find: only with -exec (it lists names)
# commands whose output is a list of paths named by their operands ($(...) bodies and xargs producers)
EMITTERS = {"find", "ls", "echo", "printf", "realpath", "readlink", "dirname", "basename", "fd", "locate", "grep",
            "rg", "ag", "git", "stat", "du", "head", "tail", "sort", "uniq", "cat"}
SHELL_OUT_RE = re.compile(r"system\s*\(|subprocess|popen|spawn|execSync|exec\s*\(|`[^`]+`|%x\{")
SHELL_KEYWORDS = {"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}", "time"}
TEXT_VERBS = {"for", "case", "select", "function", "done", "fi", "esac", "in"}  # operands are words, not paths
DEFAULT_CWD_SEARCHERS = {"rg", "ag", "ack"}
TEXT_ONLY = {"echo", "printf", ":", "true", "false"}
# PURE READERS: they never write a file named by an operand (conditional ones are checked in reader_verb)
READERS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack", "ls", "wc",
           "stat", "file", "diff", "cmp", "comm", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "sha512sum",
           "cksum", "b2sum", "readlink", "realpath", "basename", "dirname", "test", "[", "du", "df", "tree", "bat",
           "nl", "od", "hexdump", "strings", "column", "cut", "tr", "tac", "rev", "fold", "fmt", "paste", "join",
           "expand", "jq", "echo", "printf", "true", "false", ":", "pwd", "which", "type", "whereis", "date",
           "whoami", "id", "uname", "env", "printenv", "zcat", "gzcat", "bzcat", "xzcat", "lsof", "otool", "nm",
           "codesign", "mdls", "sleep", "wait", "hostname", "uptime", "ps", "pgrep", "tput", "seq",
           "exit", "return", "set", "unset", "export", "local", "declare", "read", "shift", "trap", "source", "."}
CONDITIONAL_READERS = {"sort", "uniq", "xxd", "base64", "find", "git", "tar", "unzip", "sed", "gsed", "awk", "gawk",
                       "yq", "plutil"}
READONLY_GIT = {"status", "log", "diff", "show", "blame", "ls-files", "ls-tree", "rev-parse", "grep", "cat-file",
                "describe", "shortlog", "rev-list", "for-each-ref", "merge-base", "name-rev", "reflog", "branch",
                "tag", "remote", "ls-remote", "fetch", "add", "commit", "var", "version", "help", "diff-tree",
                "diff-index", "diff-files", "check-ignore", "check-attr", "count-objects", "verify-commit"}
GIT_TREE_WRITERS = {"reset", "checkout", "restore", "switch", "merge", "pull", "rebase", "cherry-pick", "revert",
                    "stash", "apply", "am", "clean", "rm", "mv", "read-tree", "checkout-index", "sparse-checkout",
                    "filter-branch", "submodule"}
COPY_VERBS = {"cp", "rsync", "scp", "ditto", "install", "gcp"}  # sources are read, the destination is written
# (ln is not a copy verb: a link to a protected file is an alias that later writes go through)
RCLONE_READERS = {"ls", "lsl", "lsd", "lsf", "lsjson", "cat", "size", "about", "listremotes", "version", "md5sum",
                  "sha1sum", "hashsum", "tree", "check", "cryptcheck", "ncdu", "help"}
FIND_WRITERS = {"-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
OUTPUT_FLAGS = {"-o", "--output", "--out", "--outfile", "--output-file"}
INTERPRETERS = {"python3", "python", "node", "perl", "ruby", "php", "osascript"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "env", "nohup", "time", "command", "exec", "timeout", "builtin", "nice", "stdbuf", "caffeinate"}
SECURITY_VERBS = re.compile(r"^(find|dump|export|delete|import)-")
FILE_TOOLS = {"Read": ("file_path", "notebook_path"), "Write": ("file_path",), "Edit": ("file_path",),
              "MultiEdit": ("file_path",), "NotebookEdit": ("notebook_path",), "Grep": ("path", "glob"),
              "Glob": ("path", "pattern"), "LS": ("path",)}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GOODQA_KEY_WORDS = {"project", "projects", "ticket", "tickets", "ref", "refs", "slug"}
WRITE_CALL_RE = re.compile(
    r"open\s*\([^\n]{0,300}?,\s*(?:mode\s*=\s*)?['\"][rbt+]*[wax][rwxabt+]*['\"]|mode\s*=\s*['\"][rbt+]*[wax]"
    r"|write_text|write_bytes|\.unlink|os\.remove|os\.rename|os\.replace"
    r"|shutil\.|rmtree|symlink|os\.link|chmod|chown|extractall|mkdir|makedirs|copyfile"
    r"|writeFile|appendFile|fs\.(write|rename|unlink|rm|cp|copy|symlink|mkdir)|File\.write|IO\.write|unlink\s*\(|rename\s*\("
    r"|system\s*\(|>>?\s*['\"$]")
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"))
OPERATORS = {";", "&&", "||", "|", "&", "(", ")", ";;", "|&"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", ">|", "&>"}
HEREDOC_RE = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
DURATION_RE = re.compile(r"^\d+(\.\d+)?[smhd]?$")
SUB_MARK = "\x01SUB{}\x01"
SUB_RE = re.compile("\x01SUB(\\d+)\x01")


class Bad(Exception):
    """Input that can not be judged safely: the caller denies."""


class Deadline(BaseException):
    """The internal deadline. A BaseException, so `except Exception` anywhere in the checks can not swallow it."""


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
    """Hold ids lifted through holds.py. Each state entry is re-verified against the LOCAL transcript on every call
    (holds.verify_user_source: a human message that is exactly `lift hold <id>`), so a hand-written state file or an
    unrelated human message lifts nothing. The off-host backup check runs once, in `holds.py lift`; a state entry that
    integrity.py has not recorded still counts here (lifted-but-unrecorded) and `integrity.py verify` reports it.
    Any failure to verify counts as not lifted."""
    try:
        lifted = json.loads(STATE.read_text()).get("lifted", {})
        if not isinstance(lifted, dict) or not lifted:
            return set()
    except (OSError, ValueError, AttributeError):
        return set()
    try:
        import holds
    except Exception:  # noqa: BLE001 - no verifier available: nothing is lifted (a Deadline still propagates)
        return set()
    out = set()
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


_ROOTS_CACHE: dict = {}


def protected_roots() -> tuple[list[str], list[str]]:
    """(directories, files) that make up the protected set, as real paths: the hooks directory this guard lives in and
    the installed one of the Claude home, and the settings files next to both."""
    key = (str(HERE), os.environ.get("HOME", ""), os.environ.get("CLAUDE_CONFIG_DIR", ""))
    if key not in _ROOTS_CACHE:
        home = claude_home()
        dirs = list(dict.fromkeys(os.path.realpath(p) for p in (HERE, home / "hooks")))
        files = list(dict.fromkeys(os.path.realpath(p) for p in (
            HERE.parent / "settings.json", HERE.parent / "settings.local.json",
            home / "settings.json", home / "settings.local.json")))
        _ROOTS_CACHE[key] = (dirs, files)
    return _ROOTS_CACHE[key]


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
    """Credential glob a path matches, else None."""
    for p in path_forms:
        base = os.path.basename(p)
        if base.endswith(".pub") or (base in ("known_hosts", "config") and "/.ssh/" in p):
            continue
        for g in globs:
            if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(base, g):
                return g
    return None


SAFE_ALT = ("edit the file in a branch worktree and run install.py (it installs and records integrity); "
            "project settings are changed by the user")


def protected_hit(path_forms) -> str | None:
    """The protected path a set of path forms falls in, else None."""
    dirs, files = protected_roots()
    for p in path_forms:
        if not os.path.isabs(p):
            continue
        for r in dirs:
            if inside(p, r):
                return r
        if p in files or p.endswith(SETTINGS_SUFFIXES):
            return p
    return None


def ancestor_hit(real: str) -> str | None:
    """A strict ancestor of the protected set inside the home directory (~/.claude, ~) or a `.claude` directory: a
    destructive verb on it can delete or replace protected files. / and /Users are left to the command guard."""
    dirs, files = protected_roots()
    if os.path.basename(real.rstrip("/")) == ".claude":
        return real
    home = os.path.realpath(os.path.expanduser("~"))
    if not inside(real, home):
        return None
    for r in dirs + files:
        if inside(r, real) and r != real:
            return real
    return None


def ancestor_of_secrets(real: str) -> bool:
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
        return sorted(itertools.islice(glob.iglob(expanded), MAX_GLOB))
    except Exception:  # noqa: BLE001 - a broken glob expands to nothing (a Deadline still propagates)
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


def mask_substitutions(command: str) -> tuple[str, list[str]]:
    """(command with each $(...), `...`, <(...) and >(...) outside single quotes replaced by a marker, [bodies]).
    The outer command then tokenizes cleanly and a word that holds a marker maps back to its body."""
    out, bodies, i, n, quote = [], [], 0, len(command), None
    while i < n:
        c = command[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\":
            out.append(command[i:i + 2])
            i += 2
            continue
        if c == "'" and quote is None:
            quote = "'"
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "`":
            j = command.find("`", i + 1)
            j = n if j < 0 else j
            out.append(SUB_MARK.format(len(bodies)))
            bodies.append(command[i + 1:j])
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
            out.append(SUB_MARK.format(len(bodies)))
            bodies.append(command[i + 2:j - 1] if depth == 0 else command[i + 2:])
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out), bodies


def tokens(command: str) -> list[str]:
    command = command.replace("\\\n", "").replace("\r", " ").replace("\n", " ; ")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()


def segments(toks: list[str]) -> list[tuple[list[str], list[str], list[str], list[str], str]]:
    """[(words, output redirect targets, input redirect files, here-strings, operator before it)]."""
    out, words, targets, inputs, here, before, i = [], [], [], [], [], "", 0

    def flush(op):
        nonlocal words, targets, inputs, here, before
        if words or targets or inputs or here:
            out.append((words, targets, inputs, here, before))
        words, targets, inputs, here, before = [], [], [], [], op

    while i < len(toks):
        t = toks[i]
        if t in OPERATORS or (t and set(t) <= set(";&|()") and t not in REDIRECTS):
            flush(t)
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
    flush("")
    return out


WRAPPER_VALUE_FLAGS = {"-u", "--unset", "-g", "-n", "-s", "--signal", "-k", "--kill-after", "-C", "--chdir", "-p"}
XARGS_VALUE_FLAGS = {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "-J", "-R", "-S"}


def verb_of(words: list[str]) -> tuple[str, list[str]]:
    wrapped = False
    i = 0
    while i < len(words):
        t = words[i]
        if t in SHELL_KEYWORDS and not wrapped:
            i += 1
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in WRAPPERS:
            wrapped = wrapped or t in WRAPPERS
            i += 1
            continue
        if wrapped and t in WRAPPER_VALUE_FLAGS and i + 1 < len(words):
            i += 2
            continue
        if wrapped and (t.startswith("-") or DURATION_RE.match(t)):
            i += 1
            continue
        if os.path.basename(t) == "xargs":  # the command xargs runs is the verb that matters
            j = i + 1
            while j < len(words) and words[j].startswith("-"):
                j += 2 if words[j] in XARGS_VALUE_FLAGS else 1
            if j < len(words):
                return verb_of(words[j:])
            return "echo", []
        return re.sub(r"^(python3?)\.\d+$", r"\1", os.path.basename(t)), words[i + 1:]
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


def tar_mode(args: list[str]) -> tuple[str, str]:
    """('c'|'x'|'t'|'', archive file) of a tar call."""
    mode, archive, take_file = "", "", False
    for i, a in enumerate(args):
        if take_file:
            archive, take_file = a, False
            continue
        if a in ("--create", "--append", "--update"):
            mode = mode or "c"
        elif a in ("--extract", "--get"):
            mode = mode or "x"
        elif a == "--list":
            mode = mode or "t"
        elif a.startswith("--file="):
            archive = a.split("=", 1)[1]
        elif a == "--file":
            take_file = True
        elif re.match(r"^-?[A-Za-z]+$", a) and (a.startswith("-") or i == 0):
            letters = a.lstrip("-")
            for ch in letters:
                if ch in "crux" and not mode:
                    mode = "x" if ch == "x" else "c"
                elif ch == "t" and not mode:
                    mode = "t"
            if "f" in letters:
                rest = letters.split("f", 1)[1]
                if rest and a.startswith("-"):
                    archive = rest
                else:
                    take_file = True
    return mode, archive


def implicit_cwd_write(verb: str, args: list[str]) -> bool:
    """Mutating commands that write into the working directory without naming it."""
    if verb == "git":
        sub, _rest = git_subcommand(args)
        return sub in GIT_TREE_WRITERS and "-C" not in args
    if verb in ("tar", "bsdtar", "gtar"):
        return tar_mode(args)[0] == "x" and not any(
            a in ("-C", "--directory") or a.startswith("--directory=") for a in args)
    if verb == "unzip":
        return not any(a == "-d" or a.startswith("-d") and len(a) > 2 for a in args) and \
            not any(a in ("-l", "-p", "-t", "-v", "-Z") for a in args)
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
    if verb in ("sed", "gsed"):
        return re.findall(r"(?:^|[;\n{}]|\d|\$|/)\s*[wW]\s+([^\n;}]+)", program)
    return re.findall(r">>?\s*\"([^\"]+)\"", program)


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
        if a == "-m":
            return codes, ""
        if a in ("-W", "-X", "-I", "-M", "--require"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return codes, a
    return codes, ""


def positionals(args: list[str]) -> list[str]:
    return [a for a in args if not a.startswith("-")]


def reader_verb(verb: str, args: list[str], runs_hook: bool, codes: list[str]) -> bool:
    """True when this command never writes a file named by one of its operands (the allowlist)."""
    if runs_hook:
        return True
    if verb in INTERPRETERS:
        return bool(codes) and not inplace_edit(verb, args) and not any(WRITE_CALL_RE.search(c) for c in codes)
    if verb == "less" and any(f.startswith(("-o", "-O", "--log-file", "--LOG-FILE")) for f in args):
        return False
    if verb == "file" and any(re.match(r"^-[A-Za-z]*C", f) for f in args):
        return False
    if verb in READERS or verb in TEXT_VERBS:
        return True
    if verb not in CONDITIONAL_READERS:
        return False
    flags = [a for a in args if a.startswith("-")]
    if verb == "sort":
        return not any(f in ("-o", "--output") or f.startswith(("--output=", "-o")) for f in flags)
    if verb == "uniq":
        return len(positionals(args)) <= 1
    if verb == "xxd":
        return not any(re.match(r"^-[a-z]*r", f) or f == "-revert" for f in flags) and len(positionals(args)) <= 1
    if verb == "base64":
        return not any(f in ("-o", "--output") or f.startswith(("--output=", "-o")) for f in flags)
    if verb in ("yq", "plutil"):
        return not any(f in ("-i", "--inplace", "-convert", "-insert", "-replace", "-remove", "-o") for f in flags)
    if verb in ("sed", "gsed", "awk", "gawk"):
        return not inplace_edit(verb, args) and not script_writes(verb, args)
    if verb == "unzip":
        return any(a in ("-l", "-p", "-t", "-v", "-Z") for a in args)
    if verb == "tar":
        return tar_mode(args)[0] == "t"
    if verb == "find":
        if any(a in FIND_WRITERS for a in args):
            return False
        for i, a in enumerate(args):
            if a in FIND_EXEC:
                inner = []
                for b in args[i + 1:]:
                    if b in (";", "+", "\\;"):
                        break
                    inner.append(b)
                ivert, iargs = verb_of(inner)
                if not ivert or ivert == "find" or not reader_verb(ivert, iargs, False, []):
                    return False
        return True
    if verb == "git":
        sub, rest = git_subcommand(args)
        if any(a == "--output" or a.startswith("--output=") or a == "-o" for a in rest):
            return False
        if sub == "worktree":
            return rest[:1] == ["list"]
        if sub in ("branch", "tag", "remote", "stash"):
            return True  # refs and config inside .git, never an operand file
        return sub in READONLY_GIT
    return False


def write_targets(verb: str, args: list[str], ops: list[str], runs_hook: bool, codes: list[str]) -> list[str]:
    """The operands this command may write (all of them unless the verb is a reader or a copy verb)."""
    if reader_verb(verb, args, runs_hook, codes):
        return []
    if verb in COPY_VERBS and "--remove-source-files" not in args:
        pos = positionals(args)
        dest = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-t", "--target-directory")]
        dest += [a.split("=", 1)[1] for a in args if a.startswith("--target-directory=")]
        if not dest and pos:
            dest = [pos[-1]]
        return dest + [o for o in ops if o not in pos and o not in dest and not o.startswith("-")
                       and o not in [args[i + 1] for i, a in enumerate(args[:-1]) if a.startswith("-")]]
    if verb in ("tar", "bsdtar", "gtar"):
        mode, archive = tar_mode(args)
        if mode == "c":
            return [archive] if archive else []
        return [o for o in ops if o != archive]
    if verb == "dd":
        return [a[3:] for a in args if a.startswith("of=")]
    if verb == "rclone":
        pos = positionals(args)
        sub = pos[0] if pos else ""
        if sub in RCLONE_READERS:
            return []
        if sub in ("copy", "copyto", "sync", "bisync", "check", "cryptcheck", "copyurl") and len(pos) > 2:
            return [pos[-1]]
        return ops
    return ops


def deny(kind: str, reason: str) -> tuple[str, str]:
    return kind, reason


def check_path(value: str, cwd: str, policy: dict, lifted: set[str], what: str, write: bool, read_check: bool = True):
    pf = forms(value, cwd)
    if read_check:
        hit = protected(pf, policy["protected_paths"])
        if hit:
            return deny("protected-path", f"{what} of a protected credential path ({hit}) is not allowed for agents")
    if write:
        hit = protected_hit(pf)
        if hit:
            return deny("policy-file", f"{what} of {hit} is not allowed: {SAFE_ALT}")
    h = held(pf, policy, lifted)
    if h:
        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): {what} of a held path is not allowed")
    return None


def goodqa_strings(obj, keyed: bool = False):
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
    if tool in FILE_TOOLS:
        for key in FILE_TOOLS[tool]:
            value = tin.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                raise Bad(f"{tool}.{key} is not a string")
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
    """Whole quoted strings that look like one path (no whitespace): what code passes to open()/shutil/os. A path
    that only appears inside prose (a docstring, a replacement text) is data, not a target."""
    found = [m.group(2) for m in re.finditer(r"(['\"])((?:(?!\1).){1,1024}?)\1", code, re.S)]
    return [f for f in dict.fromkeys(found) if f and not re.search(r"\s", f)]


def code_check(code: str, sim: str):
    """Inline interpreter code (-c/-e, heredoc, here-string). Reading anything is fine; code that WRITES (open 'w',
    shutil, os.remove, subprocess ...) is denied when it names a protected path, a directory that contains one, or
    `.claude` + hooks/settings, or when the working directory is inside the protected set."""
    if not WRITE_CALL_RE.search(code):
        return None
    if re.search(r"""['"]\.claude['"]\s*[,/+]\s*['"](hooks|settings[\w.]*)['"]|\.claude['"]\s*\+\s*['"]/(hooks|settings)"""
                 r"""|['"][^'"\s]*/\.claude/(hooks\b|settings(\.local)?\.json)[^'"\s]*['"]""", code):
        return deny("policy-file", f"inline code writes and names the Claude hooks or settings: {SAFE_ALT}")
    if sim and protected_hit({sim}):
        return deny("policy-file", f"inline code that writes runs inside the protected hooks directory: {SAFE_ALT}")
    for cand in code_paths(code):
        absolute = os.path.isabs(os.path.expanduser(cand))
        if not absolute and not sim:
            continue
        pf = forms(cand, sim)
        hit = protected_hit(pf)
        if hit:
            return deny("policy-file", f"inline code writes and names {hit}: {SAFE_ALT}")
        if absolute and resolve(cand, sim) == os.path.realpath(claude_home()):
            return deny("policy-file", f"inline code writes and names {resolve(cand, sim)}, which contains "
                        f"protected files: {SAFE_ALT}")
    return None


def protected_named(words: list[str], targets: list[str], sim: str) -> list[str]:
    """Protected paths (or protected-set ancestors) that the words or redirect targets of a segment name."""
    out = []
    for raw in [w.split("=", 1)[1] if w.startswith("--") and "=" in w else w for w in words] + targets:
        if not raw or raw.startswith("-"):
            continue
        for value in brace_expand(raw):
            for cand in [value] + expansions(value, sim):
                pf = forms(cand, sim)
                if protected_hit(pf) or ancestor_hit(resolve(cand, sim)):
                    out.append(cand)
    return out


def body_protected(body: str, sim: str, env: dict) -> list[str]:
    """Paths into the protected set that a $(...) body or a pipeline producer names: its output may be those paths."""
    masked, _ = mask_substitutions(split_heredocs(body)[0])
    out = []
    for words, targets, _inputs, _here, _op in segments(tokens(masked)):
        words = [_subst(w, env) for w in words]
        verb, args = verb_of(words)
        if verb in EMITTERS:
            out += [p for p in protected_named(args, [], sim) if protected_hit(forms(p, sim))]
    return out


def unmask(text: str, subs: list[str]) -> str:
    """Put $(...) bodies back into a string that is itself a command (sh -c, eval, a here-string)."""
    return SUB_RE.sub(lambda m: "$(" + subs[int(m.group(1))] + ")" if int(m.group(1)) < len(subs) else "", text)


def _subst(w: str, env: dict) -> str:
    return re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: env.get(m.group(1) or m.group(2), m.group(0)), w)


def text_word(raw: str, sim: str) -> bool:
    """An operand with whitespace that is not an existing file is text (a JSON body, a sed program, a sentence).
    Only short path-shaped words are looked up, so a long remote script never touches the filesystem."""
    if not re.search(r"\s", raw):
        return False
    if len(raw) > 1024 or "\n" in raw or not re.match(r"^[~./\w]", raw):
        return True
    return not os.path.lexists(os.path.join(sim, os.path.expanduser(raw)) if sim else os.path.expanduser(raw))


def write_deny(verb: str, path: str) -> tuple[str, str]:
    return deny("policy-file", f"`{verb or 'redirect'}` would write {path}, which is protected; only pure readers "
                f"(cat, grep, ls, diff, git log ...) may touch it: {SAFE_ALT}")


def decide_bash(command: str, cwd: str, policy: dict, lifted: set[str], depth: int):
    command, heredocs = split_heredocs(command)
    command, subs = mask_substitutions(command)
    if subs and depth >= MAX_DEPTH:
        raise Bad("command substitution is nested too deeply to check")
    env: dict[str, str] = {k: v for k, v in (("HOME", os.path.expanduser("~")), ("TMPDIR", os.environ.get("TMPDIR", "")),
                                             ("USER", os.environ.get("USER", "")),
                                             ("CLAUDE_CONFIG_DIR", os.environ.get("CLAUDE_CONFIG_DIR", ""))) if v}
    sub_paths: list = [[] for _ in subs]  # filled when the segment holding the body is reached (its cwd)
    checked_subs: set = set()
    # simulated working directory: known unless a cd names an unresolved $variable (sim_guard: its text names .claude)
    sim, sim_known, sim_guard, stack, oldpwd = cwd, True, False, [], cwd
    cwd_hold = held([clean(cwd)], policy, lifted) if cwd else None
    pipe_paths: list[str] = []   # protected-set paths named by earlier segments of this pipeline
    pipe_creds: list[str] = []   # credential paths named by earlier segments of this pipeline
    pipe_words: list[str] = []   # path-like words of earlier segments (a held path fed to xargs)
    for words, targets, inputs, here, before in segments(tokens(command)):
        if before not in ("|", "|&"):
            pipe_paths, pipe_creds, pipe_words = [], [], []
        for m in (re.match(r"^(?:export\s+)?([A-Za-z_]\w*)=(.*)$", w) for w in words):
            if m:
                env[m.group(1)] = m.group(2)
        env["PWD"] = sim
        words = [_subst(w, env) for w in words]
        targets = [_subst(t, env) for t in targets]
        inputs = [_subst(t, env) for t in inputs]
        uses_xargs = any(os.path.basename(w) == "xargs" for w in words[:3])
        verb, args = verb_of(words)
        fed = list(pipe_paths) if uses_xargs else []
        for w in words + targets + inputs:  # $(...) bodies run in the simulated cwd of their segment
            for m in SUB_RE.finditer(w):
                k = int(m.group(1))
                if k < len(subs) and k not in checked_subs:
                    checked_subs.add(k)
                    r = decide_bash(clean(subs[k]), sim if sim_known else "", policy, lifted, depth + 1)
                    if r:
                        return r
                    sub_paths[k] = body_protected(subs[k], sim if sim_known else "", env)
        for w in words + targets:
            for m in SUB_RE.finditer(w):
                if int(m.group(1)) < len(sub_paths):
                    fed += sub_paths[int(m.group(1))]
        if cwd_hold and verb != "cd":
            return deny("hold", f"hold '{cwd_hold['id']}' is active: the working directory is inside a held path; "
                        "start the session in another directory")
        codes, script_arg = inline_codes(verb, args) if verb in INTERPRETERS else ([], "")
        codes = [unmask(c, subs) for c in codes]
        script = resolve(script_arg, sim) if script_arg and sim_known else ""
        runs_hook = bool(script) and script.endswith((".py", ".js")) and protected_hit({script}) is not None \
            and not codes
        joined = " ".join(args)
        if verb in SHELLS or verb == "eval":
            payloads = [joined] if verb == "eval" else [args[i + 1] for i, a in enumerate(args[:-1])
                                                        if re.match(r"^-[a-z]*c[a-z]*$", a)]
            if payloads and depth >= MAX_DEPTH:
                raise Bad("shell strings are nested too deeply to check")
            for text in payloads:
                r = decide_bash(clean(unmask(text, subs)), sim if sim_known else "", policy, lifted, depth + 1)
                if r:
                    return r
        if here and verb in SHELLS and not any(re.match(r"^-[a-z]*c[a-z]*$", a) for a in args):
            if depth >= MAX_DEPTH:
                raise Bad("here-strings are nested too deeply to check")
            for text in here:
                r = decide_bash(clean(unmask(_subst(text, env), subs)), sim if sim_known else "", policy, lifted, depth + 1)
                if r:
                    return r
        if verb in INTERPRETERS and here and not codes and script_arg in ("", "-"):
            codes = codes + [unmask(_subst(text, env), subs) for text in here]
        if verb in INTERPRETERS and not runs_hook:
            for code in codes:
                r = code_check(code, sim if sim_known else "")
                if r:
                    return r
                if SHELL_OUT_RE.search(code) and depth < MAX_DEPTH:  # os.system('rm -rf ...'): check the strings
                    strings = [m.group(2) for m in re.finditer(r"(['\"])((?:(?!\1).){1,2048}?)\1", code, re.S)]
                    for lst in re.finditer(r"\[([^\[\]]{1,4096})\]", code):  # ['rm', '-rf', path]
                        words_in = [m.group(2) for m in re.finditer(r"(['\"])((?:(?!\1).)*?)\1", lst.group(1))]
                        if len(words_in) > 1:
                            strings.append(" ".join(shlex.quote(w) for w in words_in))
                    for text in strings:
                        r = decide_bash(clean(text), sim if sim_known else "", policy, lifted, depth + 1)
                        if r:
                            return r
        if verb == "security" and args and SECURITY_VERBS.match(args[0]):
            return deny("protected-path", "the macOS security CLI keychain verbs are not allowed for agents")
        if verb == "git":
            if force_push(args):
                return deny("force-push", "force pushes are never allowed (rule: never force-push)")
            if git_remote_change(args):
                return deny("remote-switch", "changing an existing remote (set-url, rename, remove, remote.*.url, "
                            "url.*.insteadOf) is not allowed; declare the remote in the brief")
        # cd / pushd / popd move the simulated working directory
        if verb == "popd":
            if stack:
                oldpwd = sim
                sim, sim_known, sim_guard = stack.pop()
            continue  # popd on an empty stack fails and leaves the directory unchanged
        if verb in ("cd", "pushd"):
            target = next((a for a in args if not a.startswith("-") or a == "-"), "" if verb == "pushd" else "~")
            if verb == "pushd" and not target:  # swap the top two entries
                if stack:
                    top = stack.pop()
                    stack.append((sim, sim_known, sim_guard))
                    oldpwd = sim
                    sim, sim_known, sim_guard = top
                continue
            cands = [c for hit in brace_expand(target) for c in [hit] + expansions(hit, sim)]
            for cand in cands:
                h = held(forms(cand, sim), policy, lifted)
                if h:
                    return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `cd` into a held path is not allowed")
            if verb == "pushd":
                stack.append((sim, sim_known, sim_guard))
            if target == "-":
                sim, oldpwd = oldpwd, sim
                continue
            if "$" in target or "`" in target or SUB_RE.search(target):
                oldpwd = sim
                sim_known, sim_guard = False, ".claude" in target or "hooks" in target or SUB_RE.search(target) and \
                    any(sub_paths[int(m.group(1))] for m in SUB_RE.finditer(target))
                continue
            globbed = [c for c in cands if c != target and os.path.isdir(c)]
            dest = globbed[0] if globbed else brace_expand(target)[0]
            if os.path.isabs(os.path.expanduser(dest)) or (sim and sim_known):
                oldpwd = sim
                sim, sim_known, sim_guard = resolve(dest, sim), True, False
            continue
        # operands: positionals, option values, key=value values and redirects
        text_flags = TEXT_FLAGS | VERB_TEXT_FLAGS.get(verb, set())
        git_sub = git_subcommand(args)[0] if verb == "git" else ""
        ops: list[str] = []          # every operand (for the protected-set write check)
        cred_ops = list(inputs)      # read operands checked against credential globs
        hold_ops = [(t, True) for t in targets + inputs]
        text_next, force_next, positional = False, False, 0
        for a in args:
            if text_next:
                text_next = False
                if a.startswith("@"):  # curl -d @file reads that file
                    cred_ops.append(a[1:])
                continue
            if force_next:
                force_next = False
                ops.append(a)
                cred_ops.append(a)
                hold_ops.append((a, True))
                continue
            if a in text_flags:
                text_next = True
                continue
            if a.startswith("--") and "=" in a:
                k, v = a.split("=", 1)
                if k not in text_flags:
                    ops.append(v)
                    cred_ops.append(v)
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
                    ops.append(m.group(1))
                    cred_ops.append(m.group(1))
                    hold_ops.append((m.group(1), True))
                continue
            positional += 1
            if (script_arg and a == script_arg and runs_hook) or (verb == "git" and positional == 1 and a == git_sub):
                continue
            m = re.match(r"^[A-Za-z_][\w.-]*=(.+)$", a)
            value = m.group(1) if m else a
            ops.append(value.lstrip("@") if verb != "dd" else a)
            cred_ops.append(value.lstrip("@"))
            if verb == "git" and git_sub in ("push", "fetch", "pull") and positional > 2:
                continue
            hold_ops.append((value.lstrip("@"), None))
        remote_only = verb in REMOTE_ONLY
        # --- protected harness files: writes only (the allowlist inversion)
        if not remote_only and not verb:  # a bare redirect (`> f`, `exec 3> f`) still writes
            for raw in targets:
                for cand in [raw] + expansions(raw, sim):
                    if protected_hit(forms(cand, sim if sim_known else "")) or "/.claude/hooks/" in cand:
                        return write_deny("redirect", cand)
        if not remote_only and verb:
            reader = reader_verb(verb, args, runs_hook, codes)
            if sim_known and sim and not reader and protected_hit({sim}):
                return deny("policy-file", f"`{verb}` runs with the working directory inside the protected hooks "
                            f"directory; only pure readers may run there: {SAFE_ALT}")
            if not sim_known and sim_guard and not reader:
                return deny("policy-file", f"`{verb}` runs after a cd into an unresolved path under .claude; use an "
                            "absolute path")
            if sim_known and sim and implicit_cwd_write(verb, args):
                hit = protected_hit({sim}) or ancestor_hit(sim)
                if hit:
                    return write_deny(verb, f"{sim} (the working directory, which contains protected files)")
            wops = write_targets(verb, args, ops, runs_hook, codes)
            for program in (script_writes(verb, args) if verb in ("sed", "gsed", "awk", "gawk") else []):
                wops += [t.strip() for t in program_targets(verb, program)]
                if re.search(r"/\.claude/(hooks\b|settings(\.local)?\.json)", program):
                    return write_deny(verb, "a path under .claude/hooks or a settings file (named in its program)")
            if not reader and fed:
                return write_deny(verb, f"{fed[0]} (named by the $(...) or pipeline that feeds it)")
            for raw in wops + targets:
                if not raw:
                    continue
                if "$" in raw or SUB_RE.search(raw):
                    known = re.split(r"\$|\x01", raw, maxsplit=1)[0]
                    base = resolve(known.rsplit("/", 1)[0] or "/", sim if sim_known else "") if "/" in known else ""
                    if (base and (protected_hit({base}) or ancestor_hit(base))) or raw.endswith(SETTINGS_SUFFIXES) \
                            or "/.claude/hooks" in raw:
                        return deny("policy-file", f"`{verb}` writes {raw}, an unresolved path that can name protected "
                                    f"files: {SAFE_ALT}")
                    continue
                if "\n" in raw or text_word(raw, sim):
                    continue  # text (a JSON body, a sentence), not a path
                for value in brace_expand(raw):
                    for cand in [value] + expansions(value, sim):
                        pf = forms(cand, sim if sim_known else "")
                        if not sim_known and not os.path.isabs(os.path.expanduser(cand)):
                            continue
                        hit = protected_hit(pf)
                        if hit:
                            return write_deny(verb, cand)
                        real = resolve(cand, sim)
                        if ancestor_hit(real) and raw not in targets:
                            return write_deny(verb, f"{real} (a directory that contains protected files)")
        # --- credentials
        is_read = verb in READ_VERBS
        dest = positionals(args)[-1] if verb in ("cp", "rsync", "ditto", "scp") and len(positionals(args)) > 1 else None
        recursive_grep = any(re.match(r"^-[A-Za-z]*[rR]", a) or a in ("--recursive", "--dereference-recursive") for a in args)
        pattern_arg = next((a for a in args if not a.startswith("-")), None) if verb in ("grep", "egrep", "rg", "ag", "ack") \
            and not any(a in ("-e", "-f", "--regexp", "--file") or a.startswith(("--regexp=", "-e")) for a in args) else None
        for raw in cred_ops + targets:
            if not raw or "\n" in raw or text_word(raw, sim):
                continue  # text (a sed program, a sentence), not a path
            for value in brace_expand(raw):
                candidates = [value] + expansions(value, sim)
                is_path = pathlike(value, sim if sim_known else "")
                sweeper = (verb in RECURSIVE_READERS and (verb != "grep" or recursive_grep)) or \
                    (verb == "find" and any(a in FIND_EXEC for a in args))
                if sweeper and is_path and raw not in targets and raw != dest and raw != pattern_arg:
                    for cand in candidates:
                        if ancestor_of_secrets(resolve(cand, sim)):
                            return deny("protected-path", f"`{verb}` over the home directory would sweep credentials; "
                                        "name a narrower directory")
                if is_read or raw in targets or fed:
                    for cand in candidates:
                        hit = protected(forms(cand, sim), policy["protected_paths"])
                        if hit:
                            return deny("protected-path", f"`{verb or 'redirect'}` of a protected credential path ({hit}) is not allowed")
        if uses_xargs and verb in READ_VERBS:
            for raw in pipe_creds:
                hit = protected(forms(raw, sim), policy["protected_paths"])
                if hit:
                    return deny("protected-path", f"`{verb}` fed a protected credential path ({hit}) through xargs")
        # searchers with no path operand sweep the working directory
        if sim_known and (verb in DEFAULT_CWD_SEARCHERS or (verb == "grep" and any(
                re.match(r"^-[A-Za-z]*[rR]", a) or a in ("--recursive", "--dereference-recursive") for a in args))):
            explicit = [v for v in cred_ops if v and not v.startswith("-")]
            if not any(a in ("-e", "-f", "--regexp", "--file") or a.startswith(("--regexp=", "-e")) for a in args):
                explicit = explicit[1:]
            if not explicit and ancestor_of_secrets(sim):
                return deny("protected-path", f"`{verb}` with no path searches the working directory, which is the "
                            "home directory (or above it) and would sweep credentials; name a narrower directory")
        # --- holds: path-like and URL-like operands, and every operand of a host verb
        hold_texts = []
        for raw, forced in hold_ops:
            if not raw:
                continue
            if verb in REMOTE_ONLY and re.search(r"\s", raw):  # a remote command string: matched as text below
                hold_texts.append(raw)
                continue
            for value in brace_expand(raw):
                if verb in TEXT_ONLY and not forced:
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
        if uses_xargs:
            for value in pipe_words:
                h = held(forms(value, sim), policy, lifted)
                if h:
                    return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): a held path is fed to `{verb}` through xargs")
        if verb in HOST_VERBS:
            h = held([clean(" ".join(hold_texts))], policy, lifted)
            if h:
                return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb}` naming it is not allowed")
        for proj in (p for hh in policy["holds"] if hh["id"] not in lifted for p in hh.get("projects", [])):
            if proj and proj in joined:
                return deny("hold", "a held GoodQA project id is named in a command")
        # what this segment hands to the next one in a pipeline (xargs): paths it names
        pipe_words = pipe_words + [v for a in args if not a.startswith("-") and not re.search(r"\s", a)
                                   for v in brace_expand(a) if pathlike(v)]
        if verb in EMITTERS:
            pipe_paths = pipe_paths + [p for p in protected_named(args, [], sim if sim_known else "")
                                       if protected_hit(forms(p, sim))]
        pipe_creds = pipe_creds + [v for v in args if not v.startswith("-") and not re.search(r"\s", v)
                                   for v in brace_expand(v) if protected(forms(v, sim), policy["protected_paths"])]
    for k, body in enumerate(subs):
        if k not in checked_subs:
            r = decide_bash(clean(body), cwd, policy, lifted, depth + 1)
            if r:
                return r
    for prefix, body in heredocs:
        segs = segments(tokens(mask_substitutions(prefix)[0])) or [([], [], [], [], "")]
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
            r = decide_bash(clean(body), sim if sim_known else "", policy, lifted, depth + 1)
            if r:
                return r
    return None


def load_mode(path: Path = None) -> str:
    """"warn" only when the shipped policy file says so; a missing or invalid file means enforce, so removing or
    damaging it can never switch the guard down."""
    try:
        data = json.loads((path or MODE_FILE).read_text())
    except (OSError, ValueError):
        return "enforce"
    return "warn" if isinstance(data, dict) and data.get("mode") == "warn" else "enforce"


def emit_deny(kind: str, reason: str) -> None:
    if load_mode() == "warn":  # rollout mode: say what would be denied, let the call proceed
        print(json.dumps({"systemMessage": f"holds_guard (warn mode, not blocking) would deny [{kind}]: {reason}"}))
        return
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": f"holds_guard [{kind}]: {reason}"}}))


def _on_alarm(_signum, _frame):
    raise Deadline()


def main() -> int:
    try:
        try:
            signal.signal(signal.SIGALRM, _on_alarm)
            signal.setitimer(signal.ITIMER_REAL, DEADLINE_S)
        except (ValueError, OSError, AttributeError):
            pass  # no alarm available: the size caps still apply, and the hook timeout blocks (onFailure)
        raw = sys.stdin.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise Bad("hook input is larger than 4 MB")
        try:
            payload = json.loads(raw)
        except ValueError:
            raise Bad("hook input is not valid JSON") from None
        if not isinstance(payload, dict):
            raise Bad("hook input is not a JSON object")
        policy, warning = load_policy()
        result = decide(payload, policy, lifted_ids())
        signal.setitimer(signal.ITIMER_REAL, 0)
        if warning:
            print(warning, file=sys.stderr)
        if result:
            emit_deny(*result)
    except Deadline:
        emit_deny("input", f"checking this call took longer than {DEADLINE_S:g} s; failing closed")
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
