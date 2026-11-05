#!/usr/bin/env python3
"""PreToolUse guard for two rule families (rules S03, S08, S09, S11-adjacent; GoodQA rules batch B1, #14543).

0. PUSH SAFETY (rule S17): force pushes (any flag cluster containing f) and changing an existing git remote are denied.
1. HOLDS: the user put yates, Petfiliate and OptinRouter on hold ("do not touch"). While a hold is active this hook
   denies any tool call that reaches a held path or host: every Bash command whose path-like argument or redirect
   target names it (ls, rm, find, grep -r, tee, > file ...), access verbs (ssh, curl ...) that name it, any
   Read/Write/Edit/Grep/Glob of it, and GoodQA calls naming a held project. Naming a held project as a plain word (a
   grep filter, an echo, a commit message, a PR body, an agent brief) is allowed: the rule is about access, and a
   sweep must be able to skip them. A hold is lifted only by the USER: `holds.py lift` is refused when an agent runs
   it, and the lift state is re-verified against the transcript (the message must name the hold and say lift).
2. PROTECTED PATHS: credentials (member.key, *.secret, SSH keys, ~/.aws, rclone config, Keychain files) can not be
   read, copied or searched by an agent, and neither can the installed hooks directory and the settings files that
   wire it be changed by one: through a file tool or through Bash (redirect, cp/mv/rm/ln into the directory, sed -i,
   find -delete, an interpreter with inline code that names it ...). Changes reach the installed hooks through a
   reviewed branch and install.py, which runs as its own process.

Bash analysis is a bounded best effort, not a shell: it expands braces, NAME=value assignments, globs (relative to a
simulated cd/pushd) and sh -c / eval strings, reads heredoc bodies fed to interpreters, normalizes Unicode (NFKC,
zero-width characters) and resolves symlinks. It can not see hosts hidden behind an ssh alias that holds.json does
not list, or data computed at run time; add such aliases to the hold's patterns. GoodQA calls are matched by project
name or slug and by the ids listed in holds.json "projects" (the user must supply those ids).

FAILS CLOSED: unparseable input, a non-object payload, a wrongly typed field on a checked tool, an oversized command,
a check that runs past its deadline, or any crash of this script produces a deny with a clear message. A missing or
invalid holds.json falls back to the built-in minimum policy, and the file can only add to the built-in holds.
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
MAX_BRACE = 64
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
ACCESS_VERBS = {"ssh", "scp", "sftp", "rsync", "git", "gh", "curl", "wget", "docker", "kubectl", "psql", "mysql",
                "cd", "pushd", "cat", "less", "more", "head", "tail", "cp", "mv", "open", "python3", "python", "node",
                "npm", "pnpm", "make", "bash", "sh", "zsh", "code", "vim", "nano", "ping", "nc", "ncat", "telnet",
                "mosh", "ftp", "dig", "nslookup", "traceroute", "aws", "gcloud"}
MESSAGE_VERBS = {"git", "gh"}  # their operands are mostly text (messages, titles, refs); only path-like ones count
MESSAGE_FLAGS = {"-m", "--message", "--title", "--body", "--grep", "-S", "-G", "--author", "--notes",
                 "--subject", "--description", "--reason", "--comment", "--label", "--pickaxe-regex"}
READ_VERBS = {"cat", "less", "more", "head", "tail", "cp", "mv", "base64", "xxd", "od", "strings", "grep", "rg",
              "sed", "awk", "openssl", "scp", "rsync", "tar", "zip", "gzip", "curl", "wget", "cut", "tr", "diff",
              "source", ".", "bat", "nl", "tac", "sort", "uniq", "python3", "python", "node", "ruby", "perl",
              "xargs", "ln", "dd", "pbcopy", "open", "code", "vim", "nano", "view", "emacs", "jq", "yq", "file",
              "hexdump", "wc", "cmp", "rev", "ssh-keygen", "find", "tee", "ag", "ack"}
RECURSIVE_READERS = {"tar", "zip", "cp", "rsync", "grep", "rg", "find", "ag", "ack", "du"}
TEXT_ONLY = {"echo", "printf", ":", "true", "false"}  # their plain-word arguments name nothing
READONLY = {"cat", "less", "more", "head", "tail", "grep", "rg", "ls", "wc", "diff", "jq", "stat", "file", "echo",
            "printf", "true", "false", ":", "test", "[", "pwd", "which", "type", "du", "df", "sort", "uniq", "cut",
            "tr", "nl", "tac", "bat", "xxd", "od", "strings", "cmp", "base64", "hexdump", "realpath", "dirname",
            "basename", "readlink", "ag", "ack"}
READONLY_GIT = {"status", "log", "diff", "show", "branch", "rev-parse", "ls-files", "blame", "grep", "describe",
                "remote", "config", "ls-remote", "fetch", "cat-file", "shortlog", "reflog", "tag", "worktree",
                "rev-list", "name-rev", "for-each-ref", "merge-base", "var", "version", "help"}
INTERPRETERS = {"python3", "python", "node", "perl", "ruby", "php", "osascript"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
SECURITY_VERBS = re.compile(r"^(find|dump|export|delete|import)-")
FILE_TOOLS = {"Read": ("file_path", "notebook_path"), "Write": ("file_path",), "Edit": ("file_path",),
              "MultiEdit": ("file_path",), "NotebookEdit": ("notebook_path",), "Grep": ("path", "glob"),
              "Glob": ("path", "pattern"), "LS": ("path",)}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GOODQA_PROJECT_KEYS = ("projectSlug", "projectName", "project", "slug")
INLINE_CODE_MARKERS = (".claude/hooks", "holds.json", "holds.state", "holds_guard", "holds.py", "settings.json",
                       "settings.local.json")
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"))
OPERATORS = {";", "&&", "||", "|", "&", "(", ")", ";;", "|&"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", ">|", "&>"}
HEREDOC_RE = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


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
    """Hold ids lifted through holds.py. Each state entry is re-verified against the user's transcript, and the
    message must name the hold and say lift, so a hand-written state file or an unrelated human message lifts nothing.
    Any failure to verify counts as not lifted."""
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


def settings_files() -> list[Path]:
    return [HERE.parent / "settings.json", HERE.parent / "settings.local.json"]


def guarded_roots(policy: dict) -> list[str]:
    """Real paths an agent may not change: the hooks directory this guard lives in, and the settings files."""
    return [os.path.realpath(HERE)] + [os.path.realpath(p) for p in settings_files()]


def inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def forms(path: str, cwd: str) -> set[str]:
    """The text of a path as written, normalized, and with symlinks resolved (relative to cwd when not absolute)."""
    text = clean(path)
    expanded = os.path.expanduser(text)
    if not os.path.isabs(expanded) and cwd:
        expanded = os.path.join(cwd, expanded)
    return {text, os.path.normpath(expanded), os.path.realpath(expanded)}


def protected(path_forms: set[str], globs: list[str]) -> str | None:
    for p in path_forms:
        base = os.path.basename(p)
        if base.endswith(".pub") or (base in ("known_hosts", "config") and "/.ssh/" in p):
            continue
        for g in globs:
            if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(base, g):
                return g
    return None


def in_guarded_area(path_forms: set[str], policy: dict) -> bool:
    roots = guarded_roots(policy)
    return any(inside(p, r) for p in path_forms for r in roots)


def ancestor_of_secrets(real: str) -> bool:
    """A strict ancestor of the user's home secrets (home itself, its parent): recursive readers must name a subdirectory."""
    home = os.path.realpath(os.path.expanduser("~"))
    return real in (home, os.path.dirname(home)) or real == "/Users"


def held(texts, policy: dict, lifted: set[str]) -> dict | None:
    for h in policy["holds"]:
        if h["id"] in lifted:
            continue
        for pat in h["patterns"]:
            for text in texts:
                if re.search(pat, text, re.I):
                    return h
    return None


def pathlike(word: str, sim: str = "") -> bool:
    if "/" in word or word.startswith(("~", ".")) or re.match(r"^[\w.+-]+@[\w.-]+", word) \
            or re.match(r"^[\w.+-]+:", word):
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


def brace_expand(word: str) -> list[str]:
    """Bash-style {a,b} expansion (comma lists, nested), capped; a word without braces is returned unchanged."""
    out = [word]
    for _ in range(8):
        nxt, changed = [], False
        for w in out:
            m = re.search(r"\{([^{}]*,[^{}]*)\}", w)
            if not m:
                nxt.append(w)
                continue
            changed = True
            for part in m.group(1).split(","):
                nxt.append(w[:m.start()] + part + w[m.end():])
                if len(nxt) > MAX_BRACE:
                    raise Bad("brace expansion is too large to check")
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


def tokens(command: str) -> list[str]:
    command = command.replace("\\\n", "").replace("\r", " ").replace("\n", " ; ")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()


def segments(toks: list[str]) -> list[tuple[list[str], list[str]]]:
    """[(words, redirect targets)] with operators removed."""
    out, words, targets, i = [], [], [], 0
    while i < len(toks):
        t = toks[i]
        if t in OPERATORS or (t and set(t) <= set(";&|()") and t not in REDIRECTS):
            if words or targets:
                out.append((words, targets))
            words, targets = [], []
        elif t in REDIRECTS or (t and set(t) <= set("<>&|") and t.endswith((">", "<"))):
            if i + 1 < len(toks) and not toks[i + 1].isdigit():
                targets.append(toks[i + 1])
            i += 1
        else:
            m = re.match(r"^\d*(>>?|<)(.+)$", t)
            if m:
                targets.append(m.group(2))
            else:
                words.append(t)
        i += 1
    if words or targets:
        out.append((words, targets))
    return out


def verb_of(words: list[str]) -> tuple[str, list[str]]:
    for i, t in enumerate(words):
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            continue
        if t in {"sudo", "env", "nohup", "time", "command", "exec", "timeout", "builtin", "nice"}:
            continue
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


def deny(kind: str, reason: str) -> tuple[str, str]:
    return kind, reason


POLICY_MSG = ("the installed hooks directory and the settings files are changed only through a reviewed branch and "
              "install.py, not by an agent")


def check_path(value: str, cwd: str, policy: dict, lifted: set[str], what: str, write: bool, read_check: bool = True):
    pf = forms(value, cwd)
    if read_check:
        hit = protected(pf, policy["protected_paths"])
        if hit:
            return deny("protected-path", f"{what} of a protected credential path ({hit}) is not allowed for agents")
    if write and in_guarded_area(pf, policy):
        return deny("policy-file", POLICY_MSG)
    h = held(pf, policy, lifted)
    if h:
        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): {what} of a held path is not allowed")
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
        if tool in ("Grep", "Glob", "LS") and not tin.get("path") and cwd:
            return check_path(cwd, "", policy, lifted, tool, False)
        return None
    # --- GoodQA writes in held projects
    if tool.startswith("mcp__"):
        if "oodqa" not in tool.lower():
            return None
        text = json.dumps(tin)
        for h in policy["holds"]:
            if h["id"] in lifted:
                continue
            for proj in h.get("projects", []):
                if proj and proj in text:
                    return deny("hold", f"hold '{h['id']}' is active: GoodQA calls on its project are not allowed")
        names = [clean(str(tin[k])) for k in GOODQA_PROJECT_KEYS if k in tin]
        h = held(names, policy, lifted)
        if h:
            return deny("hold", f"hold '{h['id']}' is active: GoodQA calls on its project are not allowed")
        return None
    command = tin.get("command")
    if not isinstance(command, str):
        raise Bad("Bash command is not a string")
    if len(command) > MAX_COMMAND:
        raise Bad(f"the command is longer than {MAX_COMMAND} characters and can not be checked in time")
    return decide_bash(clean(command), cwd, policy, lifted, depth)


def inline_code_hit(text: str) -> bool:
    low = text.replace("\\", "/")
    return any(m in low for m in INLINE_CODE_MARKERS) or str(HERE) in text


def decide_bash(command: str, cwd: str, policy: dict, lifted: set[str], depth: int):
    command, heredocs = split_heredocs(command)
    env: dict[str, str] = {}
    sim = cwd
    sim_known = True
    cwd_hold = held([clean(cwd)], policy, lifted) if cwd else None
    all_segments = segments(tokens(command))
    has_xargs = any(verb_of(w)[0] == "xargs" for w, _t in all_segments)
    roots = guarded_roots(policy)
    for words, targets in all_segments:
        for m in (re.match(r"^(?:export\s+)?([A-Za-z_]\w*)=(.*)$", w) for w in words):
            if m:
                env[m.group(1)] = m.group(2)

        def sub(w: str) -> str:
            return re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: env.get(m.group(1) or m.group(2), m.group(0)), w)

        words = [sub(w) for w in words]
        targets = [sub(t) for t in targets]
        verb, args = verb_of(words)
        script = ""
        if verb in INTERPRETERS and args and not args[0].startswith("-"):
            script = os.path.realpath(os.path.join(sim, os.path.expanduser(clean(args[0])))) if sim_known else ""
        holds_cli = script == os.path.realpath(HERE / "holds.py")
        runs_installed_script = bool(script) and inside(script, os.path.realpath(HERE)) and script.endswith(".py")
        if holds_cli:
            if "lift" in args:
                return deny("lift-by-agent", "a hold is lifted only by the user, in their own terminal "
                            "(python3 holds.py lift <id> --source ...); ask the user to lift it")
            args = []
        joined = " ".join(args)
        if cwd_hold and verb != "cd":
            return deny("hold", f"hold '{cwd_hold['id']}' is active: the working directory is inside a held path; "
                        "start the session in another directory")
        if verb in SHELLS or verb == "eval":
            if depth < MAX_DEPTH:
                payloads = [joined] if verb == "eval" else [args[i + 1] for i, a in enumerate(args[:-1])
                                                            if re.match(r"^-[a-z]*c[a-z]*$", a)]
                for text in payloads:
                    r = decide_bash(clean(text), sim, policy, lifted, depth + 1)
                    if r:
                        return r
        if verb in INTERPRETERS and not runs_installed_script:
            inline = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-c", "-e", "-E", "--eval")]
            if any(inline_code_hit(code) for code in inline) or (
                    sim_known and inside(os.path.realpath(sim or "/"), os.path.realpath(HERE))
                    and (inline or not script)):
                return deny("policy-file", POLICY_MSG + " (inline code names the hooks directory or runs inside it)")
        if verb == "security" and args and SECURITY_VERBS.match(args[0]):
            return deny("protected-path", "the macOS security CLI keychain verbs are not allowed for agents")
        if verb == "git":
            sub_cmd, rest = git_subcommand(args)
            if sub_cmd == "push" and any(a in ("--force", "--mirror") or a.startswith("--force")
                                         or re.match(r"^-[A-Za-z]*f[A-Za-z]*$", a)
                                         or (len(a) > 1 and a.startswith("+")) for a in rest):
                return deny("force-push", "force pushes are never allowed (rule: never force-push)")
            if sub_cmd == "remote" and rest[:1] and rest[0] in ("set-url", "rename"):
                return deny("remote-switch", "changing an existing remote is not allowed; declare the remote in the brief")
        # cd / pushd move the simulated working directory; popd makes it unknown
        if verb == "popd":
            sim_known = False
            continue
        if verb in ("cd", "pushd") and args:
            target = next((a for a in args if not a.startswith("-")), "")
            if target:
                for hit in itertools.chain.from_iterable(brace_expand(target) for _ in [0]):
                    for cand in [hit] + expansions(hit, sim):
                        h = held(forms(cand, sim), policy, lifted)
                        if h:
                            return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `cd` into a held path is not allowed")
                nxt = os.path.realpath(os.path.join(sim, os.path.expanduser(clean(brace_expand(target)[0])))) \
                    if sim or os.path.isabs(os.path.expanduser(target)) else ""
                sim, sim_known = nxt or sim, bool(nxt) or sim_known
            continue
        # operands: arguments (message-bearing options removed), redirect targets, git -C values
        operands = [(a, True) for a in targets]
        skip_next, force_next = False, False
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if force_next:
                force_next = False
                operands.append((a, True))
                continue
            if a in MESSAGE_FLAGS:
                skip_next = True
                continue
            if a.startswith("--") and "=" in a and a.split("=", 1)[0] in MESSAGE_FLAGS:
                continue
            if verb == "git" and a in ("-C", "--git-dir", "--work-tree"):
                force_next = True
                continue
            if a.startswith("-") and "=" not in a:
                continue
            value = a.split("=", 1)[-1] if a.startswith("-") else a
            operands.append((value.lstrip("@"), None))
        mutating = not (verb in READONLY or (verb == "git" and git_subcommand(args)[0] in READONLY_GIT)
                        or runs_installed_script or holds_cli)
        if verb == "find" and not any(a in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fls")
                                      for a in args):
            mutating = False
        if verb in ("sed", "perl", "awk", "gawk"):  # these write files only in place
            mutating = any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args)
        for raw, forced in operands:
            if not raw:
                continue
            for value in brace_expand(raw):
                is_path = forced if forced is not None else pathlike(value, sim if sim_known else "")
                if not sim_known and mutating and not os.path.isabs(os.path.expanduser(value)) and not value.startswith("-"):
                    return deny("policy-file", "a relative path after popd can not be resolved; use absolute paths")
                candidates = [value] + expansions(value, sim)
                if has_xargs or verb not in TEXT_ONLY or value in targets:
                    # guarded area: any operand of a mutating verb that lands in the hooks directory or settings
                    if mutating or value in targets:
                        for cand in candidates:
                            pf = forms(cand, sim)
                            if in_guarded_area(pf, policy):
                                return deny("policy-file", POLICY_MSG)
                            real = os.path.realpath(os.path.expanduser(cand) if os.path.isabs(os.path.expanduser(cand))
                                                    else os.path.join(sim, os.path.expanduser(cand)))
                            if verb in ("rm", "mv", "rmdir", "chmod", "chown", "truncate", "find") and any(
                                    inside(r, real) and r != real for r in roots):
                                return deny("policy-file", POLICY_MSG + " (the target contains it)")
                    if verb in RECURSIVE_READERS and is_path:
                        for cand in candidates:
                            real = os.path.realpath(os.path.expanduser(cand) if os.path.isabs(os.path.expanduser(cand))
                                                    else os.path.join(sim, os.path.expanduser(cand)))
                            if ancestor_of_secrets(real):
                                return deny("protected-path", f"`{verb}` over the home directory would sweep credentials; "
                                            "name a narrower directory")
                    if verb in READ_VERBS or is_path or value in targets or has_xargs:
                        for cand in candidates:
                            hit = protected(forms(cand, sim), policy["protected_paths"]) \
                                if (verb in READ_VERBS or value in targets or has_xargs) else None
                            if hit:
                                return deny("protected-path", f"`{verb or 'redirect'}` of a protected credential path ({hit}) is not allowed")
                if verb in TEXT_ONLY and value not in targets and not has_xargs:
                    continue
                if is_path or (verb in ACCESS_VERBS and verb not in MESSAGE_VERBS):
                    for cand in candidates:
                        h = held(forms(cand, sim), policy, lifted)
                        if h:
                            return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb or 'redirect'}` naming it is not allowed")
        if verb in ACCESS_VERBS and verb not in MESSAGE_VERBS and verb not in TEXT_ONLY:
            h = held([clean(joined)], policy, lifted)
            if h:
                return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb}` naming it is not allowed")
        for proj in (p for hh in policy["holds"] if hh["id"] not in lifted for p in hh.get("projects", [])):
            if proj and proj in joined:
                return deny("hold", "a held GoodQA project id is named in a command")
    # heredoc bodies that feed an interpreter or a shell
    for prefix, body in heredocs:
        segs = segments(tokens(prefix)) or [([], [])]
        verb, args = verb_of(segs[-1][0])
        if verb in INTERPRETERS and not (args and not args[0].startswith("-")) or verb in INTERPRETERS and args == ["-"]:
            if inline_code_hit(body):
                return deny("policy-file", POLICY_MSG + " (inline code names the hooks directory)")
        elif verb in SHELLS and depth < MAX_DEPTH:
            r = decide_bash(clean(body), sim, policy, lifted, depth + 1)
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
