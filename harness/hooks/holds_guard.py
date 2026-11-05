#!/usr/bin/env python3
"""PreToolUse guard for two rule families (rules S03, S08, S09, S11-adjacent; GoodQA rules batch B1, #14543).

0. PUSH SAFETY (rule S17): force pushes and changing an existing git remote are denied.
1. HOLDS: the user put yates, Petfiliate and OptinRouter on hold ("do not touch"). While a hold is active this hook
   denies any tool call that reaches a held path or host: every Bash command whose path-like argument or redirect
   target names it (ls, rm, find, grep -r, tee, > file ...), access verbs (ssh, git, curl ...) that merely name it,
   any Read/Write/Edit/Grep/Glob of it, and GoodQA calls naming a held project. Naming a held project as a plain
   word (a grep filter, an echo, an agent brief) is allowed: the rule is about access, and a sweep must be able to
   skip them. A hold is lifted only by `holds.py lift`; the guard re-verifies each lifted hold against the user's
   transcript on every call that has one, so a hand-written state file lifts nothing.
2. PROTECTED PATHS: credentials (member.key, *.secret, SSH keys, rclone config, Keychain files) can not be read,
   copied or searched by an agent, and the policy files that define holds (in this hooks directory) can not be
   changed by one, through a file tool or through Bash (redirect, sed -i, rm, cp, python -c ...).

Bash analysis is a bounded best effort, not a shell: it expands simple NAME=value assignments, globs (relative to a
simulated cd) and sh -c / eval strings, normalizes Unicode (NFKC, zero-width characters) and resolves symlinks.
It can not see hosts hidden behind an ssh alias that holds.json does not list, or data computed at run time; add
such aliases to the hold's patterns. It complements the command guard.

FAILS CLOSED: unparseable input, a non-object payload, a wrongly typed field on a checked tool, or any crash of
this script produces a deny with a clear message. A missing or invalid holds.json falls back to the built-in
minimum policy, and the file can only add to the built-in holds, never remove one.
"""
from __future__ import annotations

import fnmatch
import glob
import itertools
import json
import os
import re
import shlex
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "holds.json"
STATE = HERE / "holds.state.json"
MAX_INPUT = 4_000_000
MAX_GLOB = 200
MAX_DEPTH = 3

BUILTIN = {
    "holds": [
        {"id": "yates", "patterns": [r"yates", r"apex_app_pos"], "projects": [], "note": "user hold 2026-11-05"},
        {"id": "petfiliate", "patterns": [r"petfiliate"], "projects": [], "note": "user hold 2026-11-05"},
        {"id": "optinrouter", "patterns": [r"optinrouter", r"optin-router"], "projects": [], "note": "user hold 2026-11-05"},
    ],
    "protected_paths": ["*/member.key", "member.key", "*.secret", "*/Library/Keychains/*", "*/.ssh/id_*", "*/.ssh",
                        "*/.aws/credentials", "*/.config/rclone/rclone.conf", "*native-api-key*",
                        "*solve*owner*phrase*", "*/goodqa-hive*/*key*"],
    "policy_files": ["holds.json", "holds.state.json", "holds_guard.py", "holds.py"],
}
ACCESS_VERBS = {"ssh", "scp", "sftp", "rsync", "git", "gh", "curl", "wget", "docker", "kubectl", "psql", "mysql",
                "cd", "cat", "less", "more", "head", "tail", "cp", "mv", "open", "python3", "python", "node",
                "npm", "pnpm", "make", "bash", "sh", "zsh", "code", "vim", "nano", "ping", "nc", "ncat", "telnet",
                "mosh", "ftp", "dig", "nslookup", "traceroute", "aws", "gcloud"}
READ_VERBS = {"cat", "less", "more", "head", "tail", "cp", "mv", "base64", "xxd", "od", "strings", "grep", "rg",
              "sed", "awk", "openssl", "scp", "rsync", "tar", "zip", "gzip", "curl", "wget", "cut", "tr", "diff",
              "source", ".", "bat", "nl", "tac", "sort", "uniq", "python3", "python", "node", "ruby", "perl",
              "xargs", "ln", "dd", "pbcopy", "open", "code", "vim", "nano", "view", "emacs", "jq", "yq", "file",
              "hexdump", "wc", "cmp", "rev", "ssh-keygen", "find", "tee", "ag"}
TEXT_ONLY = {"echo", "printf", ":", "true", "false"}  # their plain-word arguments name nothing
READONLY_ON_POLICY = {"cat", "less", "more", "head", "tail", "grep", "rg", "ls", "wc", "diff", "jq", "stat", "file"}
INTERPRETERS = {"python3", "python", "node", "perl", "ruby"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
SECURITY_VERBS = re.compile(r"^(find|dump|export|delete|import)-")
FILE_TOOLS = {"Read": ("file_path", "notebook_path"), "Write": ("file_path",), "Edit": ("file_path",),
              "MultiEdit": ("file_path",), "NotebookEdit": ("notebook_path",), "Grep": ("path", "glob"),
              "Glob": ("path", "pattern"), "LS": ("path",)}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GOODQA_PROJECT_KEYS = ("projectSlug", "projectName", "project", "slug")
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"))
OPERATORS = {";", "&&", "||", "|", "&", "(", ")", ";;", "|&"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", ">|", "&>"}


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
    """Hold ids lifted through holds.py. Each state entry is re-verified against the user's transcript, so a
    hand-written or edited state file lifts nothing. Any failure to verify counts as not lifted."""
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
            holds.verify_user_source(f'user:{entry["session"]}/{entry["source_uuid"]} "{excerpt}"', finder)
            out.add(hold_id)
        except Exception:  # noqa: BLE001
            continue
    return out


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
        if base.endswith(".pub") or base in ("known_hosts", "config") and "/.ssh/" in p:
            continue
        for g in globs:
            if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(base, g):
                return g
    return None


def is_policy_file(path_forms: set[str], policy: dict) -> bool:
    targets = {str((HERE / n)) for n in policy["policy_files"]} | {os.path.realpath(HERE / n) for n in policy["policy_files"]}
    return any(p in targets for p in path_forms)


def held(texts, policy: dict, lifted: set[str]) -> dict | None:
    for h in policy["holds"]:
        if h["id"] in lifted:
            continue
        for pat in h["patterns"]:
            for text in texts:
                if re.search(pat, text, re.I):
                    return h
    return None


def pathlike(word: str) -> bool:
    return "/" in word or word.startswith(("~", ".")) or bool(re.match(r"^[\w.+-]+@[\w.-]+", word))


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


def tokens(command: str) -> list[str]:
    command = command.replace("\r", " ").replace("\n", " ; ")
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


def check_path(value: str, cwd: str, policy: dict, lifted: set[str], what: str, write: bool, read_check: bool = True):
    pf = forms(value, cwd)
    if read_check:
        hit = protected(pf, policy["protected_paths"])
        if hit:
            return deny("protected-path", f"{what} of a protected credential path ({hit}) is not allowed for agents")
    if write and is_policy_file(pf, policy):
        return deny("policy-file", "holds policy files are changed only by the user through holds.py")
    h = held(pf, policy, lifted)
    if h:
        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): {what} of a held path is not allowed")
    return None


def decide(payload: dict, policy: dict, lifted: set[str], hooks_dir: Path | None = None, depth: int = 0):
    tool = payload.get("tool_name", "")
    if not isinstance(tool, str):
        raise Bad("tool_name is not a string")
    tin = payload.get("tool_input")
    cwd = payload.get("cwd", "")
    cwd = os.path.realpath(cwd) if isinstance(cwd, str) and cwd else ""
    checked = tool in FILE_TOOLS or tool == "Bash" or tool.startswith("mcp__")
    if checked and not isinstance(tin, dict):
        raise Bad(f"tool_input of {tool} is not an object")
    if not checked:
        return None
    if cwd:
        h = held([clean(cwd)], policy, lifted)
        if h and tool != "Bash":
            return deny("hold", f"hold '{h['id']}' is active: the session working directory is inside a held path")
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
            r = check_path(value, cwd, policy, lifted, tool, tool in WRITE_TOOLS)
            if r:
                return r
            for hit in expansions(value, cwd):
                r = check_path(hit, cwd, policy, lifted, tool, tool in WRITE_TOOLS)
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
    return decide_bash(clean(command), cwd, policy, lifted, depth)


def decide_bash(command: str, cwd: str, policy: dict, lifted: set[str], depth: int):
    env: dict[str, str] = {}
    sim = cwd
    cwd_hold = held([clean(cwd)], policy, lifted) if cwd else None
    for words, targets in segments(tokens(command)):
        for m in (re.match(r"^(?:export\s+)?([A-Za-z_]\w*)=(.*)$", w) for w in words):
            if m:
                env[m.group(1)] = m.group(2)

        def sub(w: str) -> str:
            return re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: env.get(m.group(1) or m.group(2), m.group(0)), w)

        words = [sub(w) for w in words]
        targets = [sub(t) for t in targets]
        verb, args = verb_of(words)
        script = os.path.realpath(os.path.join(sim, os.path.expanduser(clean(args[0])))) \
            if verb in INTERPRETERS and args and not args[0].startswith("-") else ""
        holds_cli = script == os.path.realpath(HERE / "holds.py")
        joined = " ".join(args)
        if cwd_hold and verb != "cd":
            return deny("hold", f"hold '{cwd_hold['id']}' is active: the working directory is inside a held path; `cd` out of it first")
        # policy files: any verb that changes, moves or opens them for writing, or names them through a redirect
        mentions = []
        for w in list(words) + list(targets):
            base = w.split("=", 1)[-1]
            names = [n for n in policy["policy_files"] if n in base]
            if names:
                pf = forms(base, sim)
                inline = any(str(HERE / n) in base or f".claude/hooks/{n}" in base for n in names)
                if is_policy_file(pf, policy) or inline:
                    mentions.append(base)
        if mentions:
            is_holds_cli = holds_cli \
                and not any(os.path.basename(m) in ("holds.json", "holds.state.json") for m in mentions)
            changing = any(t in mentions or os.path.basename(t) in policy["policy_files"] for t in targets)
            if not is_holds_cli and (verb not in READONLY_ON_POLICY or changing
                                     or any(a in ("-i", "-w", "--in-place") for a in args)):
                return deny("policy-file", "holds policy files are changed only by the user through holds.py")
        if holds_cli:  # the verified lift/status CLI names hold ids as plain arguments
            args, joined = [], ""
        if verb in INTERPRETERS and "-c" in args and sim and os.path.realpath(sim) == os.path.realpath(HERE):
            return deny("policy-file", "inline code inside the hooks directory could rewrite the holds policy")
        # nested command strings
        if verb == "eval" and depth < MAX_DEPTH:
            r = decide_bash(clean(joined), sim, policy, lifted, depth + 1)
            if r:
                return r
        if verb in SHELLS and depth < MAX_DEPTH:
            for i, a in enumerate(args[:-1]):
                if re.match(r"^-[a-z]*c[a-z]*$", a):
                    r = decide_bash(clean(args[i + 1]), sim, policy, lifted, depth + 1)
                    if r:
                        return r
        if verb == "security" and args and SECURITY_VERBS.match(args[0]):
            return deny("protected-path", "the macOS security CLI keychain verbs are not allowed for agents")
        if verb == "git":
            sub_cmd, rest = git_subcommand(args)
            if sub_cmd == "push" and any(a in ("-f", "--force", "--mirror") or a.startswith("--force")
                                         or (len(a) > 1 and a.startswith("+")) for a in rest):
                return deny("force-push", "force pushes are never allowed (rule: never force-push)")
            if sub_cmd == "remote" and rest[:1] and rest[0] in ("set-url", "rename"):
                return deny("remote-switch", "changing an existing remote is not allowed; declare the remote in the brief")
        # cd moves the simulated working directory
        if verb == "cd" and args:
            target = next((a for a in args if not a.startswith("-")), "")
            if target:
                for hit in [target] + expansions(target, sim):
                    pf = forms(hit, sim)
                    h = held(pf, policy, lifted)
                    if h:
                        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `cd` into a held path is not allowed")
                nxt = os.path.realpath(os.path.join(sim, os.path.expanduser(clean(target)))) if sim or os.path.isabs(
                    os.path.expanduser(target)) else ""
                sim = nxt or sim
            continue
        # arguments and redirect targets
        operands = [(a, True) for a in targets]
        for a in args:
            value = a.split("=", 1)[-1] if a.startswith("-") and "=" in a else a
            if a.startswith("-") and "=" not in a:
                continue
            operands.append((value.lstrip("@"), pathlike(value.lstrip("@"))))
        for value, is_path in operands:
            if not value:
                continue
            if verb in READ_VERBS or is_path:
                for candidate in [value] + expansions(value, sim):
                    hit = protected(forms(candidate, sim), policy["protected_paths"]) \
                        if (verb in READ_VERBS or value in targets) else None
                    if hit:
                        return deny("protected-path", f"`{verb or 'redirect'}` of a protected credential path ({hit}) is not allowed")
            if verb in TEXT_ONLY and value not in targets:
                continue
            if is_path or verb in ACCESS_VERBS:
                for candidate in [value] + expansions(value, sim):
                    pf = forms(candidate, sim)
                    h = held(pf, policy, lifted)
                    if h:
                        return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb or 'redirect'}` naming it is not allowed")
        if verb in ACCESS_VERBS and verb not in TEXT_ONLY:
            h = held([clean(joined)], policy, lifted)
            if h:
                return deny("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb}` naming it is not allowed")
            for proj in (p for hh in policy["holds"] if hh["id"] not in lifted for p in hh.get("projects", [])):
                if proj and proj in joined:
                    return deny("hold", "a held GoodQA project id is named in an access command")
        for proj in (p for hh in policy["holds"] if hh["id"] not in lifted for p in hh.get("projects", [])):
            if proj and proj in joined:
                return deny("hold", "a held GoodQA project id is named in a command")
    return None


def emit_deny(kind: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": f"holds_guard [{kind}]: {reason}"}}))


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
    return 0


if __name__ == "__main__":
    sys.exit(main())
