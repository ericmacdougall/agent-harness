#!/usr/bin/env python3
"""PreToolUse guard for two rule families (rules S03, S08, S09, S11-adjacent; GoodQA rules batch B1).

0. PUSH SAFETY (rule S17): force pushes and changing an existing git remote are denied.
1. HOLDS: the user put yates, Petfiliate and OptinRouter on hold ("do not touch"). While a hold is active this
   hook denies access verbs (ssh, git, gh, curl, cd, cat ...) whose arguments name a held host, repo or path, any
   Read/Write/Edit/Grep/Glob of a held path, and GoodQA writes to a held project id. Merely naming a held project in
   a grep filter or an agent brief is allowed: the rule is about access, and a sweep must be able to skip them.
   A hold is lifted only by `holds.py lift`, which verifies a user: source against the transcript.
2. PROTECTED PATHS: credentials (member.key, *.secret, SSH keys, rclone config, Keychain files) can not be read,
   copied or searched by an agent, and the policy files that define holds can not be edited by one.

The Bash part is deliberately simple (token match, no shell parsing of wrappers). It complements, and does not
replace, the command guard; wrapper evasion (sh -c, eval, encoded strings) is that guard's job.
Fails open on its own crash (prints nothing, exit 0) but falls back to the built-in minimum policy when holds.json
is missing or corrupt, so a damaged file never silently turns protection off.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "holds.json"
STATE = HERE / "holds.state.json"

BUILTIN = {
    "holds": [
        {"id": "yates", "patterns": [r"yates", r"apex_app_pos"], "projects": [], "note": "user hold 2026-11-05"},
        {"id": "petfiliate", "patterns": [r"petfiliate"], "projects": [], "note": "user hold 2026-11-05"},
        {"id": "optinrouter", "patterns": [r"optinrouter", r"optin-router"], "projects": [], "note": "user hold 2026-11-05"},
    ],
    "protected_paths": ["*/member.key", "member.key", "*.secret", "*/Library/Keychains/*", "*/.ssh/id_*",
                        "*/.aws/credentials", "*/.config/rclone/rclone.conf", "*native-api-key*",
                        "*solve*owner*phrase*", "*/goodqa-hive*/*key*"],
    "policy_files": ["holds.json", "holds.state.json"],
}
ACCESS_VERBS = {"ssh", "scp", "sftp", "rsync", "git", "gh", "curl", "wget", "docker", "kubectl", "psql", "mysql",
                "cd", "cat", "less", "more", "head", "tail", "cp", "mv", "open", "python3", "python", "node",
                "npm", "pnpm", "make", "bash", "sh", "zsh", "code", "vim", "nano"}
READ_VERBS = {"cat", "less", "more", "head", "tail", "cp", "mv", "base64", "xxd", "od", "strings", "grep", "rg",
              "sed", "awk", "openssl", "scp", "rsync", "tar", "zip", "gzip", "curl", "wget", "cut", "tr", "diff",
              "source", ".", "bat", "nl", "tac", "sort", "uniq", "python3", "python", "node", "ruby", "perl",
              "xargs", "ln", "dd", "pbcopy", "open", "code", "vim", "nano", "view", "emacs"}
SECURITY_VERBS = re.compile(r"^(find|dump|export|delete|import)-")
FILE_TOOLS = {"Read": ("file_path",), "Write": ("file_path",), "Edit": ("file_path",), "MultiEdit": ("file_path",),
              "NotebookEdit": ("notebook_path",), "Grep": ("path", "glob"), "Glob": ("path", "pattern"),
              "LS": ("path",)}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def load_policy() -> tuple[dict, str]:
    try:
        data = json.loads(POLICY.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("holds"), list):
            raise ValueError("shape")
        merged = {**BUILTIN, **{k: v for k, v in data.items() if k in BUILTIN}}
        return merged, ""
    except (OSError, ValueError):
        return BUILTIN, "holds.json missing or corrupt: using the built-in minimum policy"


def lifted_ids() -> set[str]:
    """Hold ids lifted through holds.py (state file holds a verified user source for each)."""
    try:
        state = json.loads(STATE.read_text())
        return {k for k, v in state.get("lifted", {}).items() if isinstance(v, dict) and v.get("source_uuid")}
    except (OSError, ValueError, AttributeError):
        return set()


def norm_path(p: str) -> str:
    return os.path.normpath(os.path.expanduser(p)) if p else ""


def protected(path: str, globs: list[str]) -> str | None:
    p = norm_path(path)
    if not p:
        return None
    base = os.path.basename(p)
    if base.endswith(".pub"):
        return None
    for g in globs:
        if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(base, g):
            return g
    return None


def held(text: str, policy: dict, lifted: set[str]) -> dict | None:
    for h in policy["holds"]:
        if h["id"] in lifted:
            continue
        for pat in h.get("patterns", []):
            if re.search(pat, text, re.I):
                return h
    return None


def tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def segments(toks: list[str]) -> list[list[str]]:
    out, cur = [], []
    for t in toks:
        if t in {";", "&&", "||", "|", "&", "(", ")"} or t.endswith(";"):
            if t.endswith(";") and t not in {";"}:
                cur.append(t.rstrip(";"))
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def verb_of(seg: list[str]) -> str:
    for t in seg:
        if "=" in t and not t.startswith(("-", "/")) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            continue
        if t in {"sudo", "env", "nohup", "time", "command", "exec", "timeout"}:
            continue
        return os.path.basename(t)
    return ""


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


def decide(payload: dict, policy: dict, lifted: set[str], hooks_dir: Path | None = None) -> tuple[str, str] | None:
    tool = payload.get("tool_name", "")
    tin = payload.get("tool_input") or {}
    if not isinstance(tin, dict):
        return None
    globs = policy["protected_paths"]
    # --- file tools
    if tool in FILE_TOOLS:
        for key in FILE_TOOLS[tool]:
            value = tin.get(key)
            if not isinstance(value, str):
                continue
            hit = protected(value, globs)
            if hit:
                return ("protected-path", f"{tool} of a protected credential path ({hit}) is not allowed for agents")
            if tool in WRITE_TOOLS and os.path.basename(norm_path(value)) in policy["policy_files"]:
                return ("policy-file", "holds policy files are changed only by the user through holds.py")
            h = held(norm_path(value), policy, lifted)
            if h:
                return ("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): {tool} of a held path is not allowed")
        return None
    # --- GoodQA writes in held projects
    if tool.startswith("mcp__") and "oodqa" in tool.lower():
        text = json.dumps(tin)
        for h in policy["holds"]:
            if h["id"] in lifted:
                continue
            for proj in h.get("projects", []):
                if proj and proj in text:
                    return ("hold", f"hold '{h['id']}' is active: GoodQA calls on its project are not allowed")
        return None
    if tool != "Bash":
        return None
    command = tin.get("command")
    if not isinstance(command, str):
        return None
    for seg in segments(tokens(command)):
        verb = verb_of(seg)
        args = seg[1:] if seg and os.path.basename(seg[0]) == verb else seg
        joined = " ".join(args)
        if verb == "security" and args and SECURITY_VERBS.match(args[0]):
            return ("protected-path", "the macOS security CLI keychain verbs are not allowed for agents")
        if verb == "git":
            sub, rest = git_subcommand(args)
            if sub == "push" and any(a in ("-f", "--force", "--mirror") or a.startswith("--force")
                                     or (len(a) > 1 and a.startswith("+")) for a in rest):
                return ("force-push", "force pushes are never allowed (rule: never force-push)")
            if sub == "remote" and rest[:1] and rest[0] in ("set-url", "rename"):
                return ("remote-switch", "changing an existing remote is not allowed; declare the remote in the brief")
        if verb in READ_VERBS:
            for a in args:
                hit = protected(a.split("=", 1)[-1].lstrip("@"), globs)
                if hit:
                    return ("protected-path", f"`{verb}` of a protected credential path ({hit}) is not allowed")
        if verb in ACCESS_VERBS:
            h = held(joined, policy, lifted)
            if h:
                return ("hold", f"hold '{h['id']}' is active ({h.get('note', '')}): `{verb}` naming it is not allowed")
            for proj in (p for hh in policy["holds"] if hh["id"] not in lifted for p in hh.get("projects", [])):
                if proj and proj in joined:
                    return ("hold", "a held GoodQA project id is named in an access command")
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            return 0
        policy, warning = load_policy()
        result = decide(payload, policy, lifted_ids())
        if warning:
            print(warning, file=sys.stderr)
        if result:
            kind, reason = result
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                      "permissionDecisionReason": f"holds_guard [{kind}]: {reason}"}}))
    except Exception:  # noqa: BLE001 - never break a session on a guard bug
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
