#!/usr/bin/env python3
"""Agent Harness commit-message policy: validator, hooks, range and ticket checks.

Subcommands:
  hook            Claude Code / Codex PreToolUse hook (JSON payload on stdin)
  git-hook FILE   git commit-msg backstop (config-based hook, chains with repo hooks)
  check-message   validate a draft message (--file F or stdin)
  check-range     validate base..head, optionally verify referenced tickets
  waive           record a reasoned exception in the WAL and the waiver ledger
  notify          comment delivery evidence on referenced tickets

Rules live in commit_policy.json beside this file. There is no environment
bypass: the only exception path is `waive`, which records a reason in the WAL.
Runs on Python 3.9 with the standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "commit_policy.json"
LEDGER = Path.home() / ".agent-harness" / "commit-policy" / "waivers.jsonl"
SECTION_NAMES = ("Why", "What", "Testing", "Refs", "Risk", "Reason", "Authorized-by")
SECTION_LINE = re.compile(r"^(Why|What|Testing|Refs|Risk|Reason|Authorized-by)\s*:\s?(.*)$", re.I)
TRAILER_LINE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9]*-)+[Bb]y:\s+\S|^(?:Change-Id|Reviewed-on|Cc|Fixes|Closes|Co-authored-by):\s+\S", re.I)
SUBJECT = re.compile(r"^(?P<type>[A-Za-z]+)(?:\((?P<scope>[^()]*)\))?(?P<bang>!)?: (?P<summary>.*)$")
PR_REF = re.compile(r"\bPR\s*#[1-9]\d*\b|\b[\w.-]+/[\w.-]+#[1-9]\d*\b|https://github\.com/[\w.-]+/[\w.-]+/pull/\d+")
NONE_REF = re.compile(r"^none\s*\((?P<reason>.+)\)\s*\.?$", re.I | re.S)
COMMAND_HINT = re.compile(
    r"`[^`]{3,}`|^\s*(?:[-*]\s+)?\$?\s*(?:python3?|pytest|npm|pnpm|yarn|npx|node|go|cargo|make|git|bash|sh|uv|"
    r"tox|ruby|bundle|rake|mvn|gradle|dotnet|swift|xcodebuild|deno|bun|vitest|jest|playwright|curl|"
    r"ruff|mypy|eslint|tsc|terraform|kubectl|docker|\./)\b", re.M)
RESULT_HINT = re.compile(
    r"\b(?:pass(?:ed|es|ing)?|fail(?:ed|s|ures?)?|ok|exit(?:ed)?\s*(?:code\s*)?[=:]?\s*\d+|\d+\s+"
    r"(?:tests?|passed|failed|checks?|cases?|errors?)|errors?|clean|succeeded|success(?:ful)?|green|"
    r"no (?:issues|findings|errors|diff))\b|\d+/\d+", re.I)


class Unresolvable(Exception):
    """A git commit invocation whose message cannot be known statically."""


# --------------------------------------------------------------------------- policy

def load_policy(path: Path = POLICY_FILE) -> dict:
    with open(path, encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict) or policy.get("schema") != 1:
        raise ValueError(f"{path} is not a schema 1 commit policy")
    for key in ("subject", "body", "refs", "exempt", "ticket_systems", "waivers"):
        if not isinstance(policy.get(key), dict):
            raise ValueError(f"{path} lacks the {key!r} object")
    return policy


def normalize(message: str, *, strip_comments: bool = False) -> str:
    lines = message.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if strip_comments:
        kept = []
        for line in lines:
            if line.startswith("# ------------------------ >8 ------------------------"):
                break
            if not line.startswith("#"):
                kept.append(line)
        lines = kept
    text = "\n".join(line.rstrip() for line in lines).strip("\n")
    return re.sub(r"\n{3,}", "\n\n", text)


def digest(message: str) -> str:
    return hashlib.sha256(normalize(message).encode()).hexdigest()[:20]


def _clean(value: str) -> str:
    lines = [re.sub(r"^\s*(?:[-*+]|\d+[.)])\s+", "", line).strip() for line in value.split("\n")]
    return "\n".join(line for line in lines if line).strip()


def ticket_refs(text: str, policy: dict):
    found = []
    for system, config in policy["ticket_systems"].items():
        for match in re.finditer(config["ref_pattern"], text, re.I):
            project = (match.groupdict().get("project") or config.get("default_project") or "").lower()
            found.append((system, project, int(match.group("number"))))
    return list(dict.fromkeys(found))


def parse_message(message: str):
    """Split a normalized message into subject, sections, and trailer paragraph."""
    lines = message.split("\n")
    subject = lines[0] if lines else ""
    body = lines[1:]
    paragraphs, current = [], []
    for line in body:
        if line.strip():
            current.append(line)
        elif current:
            paragraphs.append(current)
            current = []
    if current:
        paragraphs.append(current)
    trailers = []
    if paragraphs and all(TRAILER_LINE.match(line) and not SECTION_LINE.match(line) for line in paragraphs[-1]):
        trailers = paragraphs.pop()
    sections, order, stray = {}, [], []
    name = None
    for paragraph in paragraphs:
        for line in paragraph:
            match = SECTION_LINE.match(line)
            if match:
                canonical = next(item for item in SECTION_NAMES if item.lower() == match.group(1).lower())
                name = canonical
                order.append(canonical)
                sections.setdefault(canonical, []).append(match.group(2))
            elif name is None:
                stray.append(line)
            else:
                sections[name].append(line)
    joined = {key: "\n".join(value).strip() for key, value in sections.items()}
    misplaced = [line for paragraph in paragraphs for line in paragraph
                 if TRAILER_LINE.match(line) and not SECTION_LINE.match(line)]
    return subject, (lines[1] if len(lines) > 1 else None), joined, order, stray, trailers, misplaced


def tickets_required_for(origin: str | None, policy: dict) -> bool:
    """The ticket rule applies only to repos a configured ticket system tracks."""
    if not origin:
        return False
    return any(re.search(pattern, origin) for config in policy["ticket_systems"].values()
               for pattern in config.get("repos", []))


def validate(message: str, *, policy: dict, previous: str | None = None, is_merge: bool = False,
             allow_autosquash: bool = False, strip_comments: bool = False,
             tickets_required: bool = True) -> list:
    """Return a list of human-readable violations (empty means compliant).

    tickets_required is False for repos no ticket system tracks: Refs must still
    be present and meaningful, but 'none (<reason>)' is accepted for any type.
    """
    text = normalize(message, strip_comments=strip_comments)
    if not text:
        return ["message: empty commit message"]
    subject_line = text.split("\n", 1)[0]
    exempt = policy["exempt"]
    # Only a real merge (MERGE_HEAD present, or more than one parent) is exempt. A subject
    # that merely starts with "Merge" proves nothing: squash commits must comply.
    if is_merge:
        return []
    if any(subject_line.startswith(prefix) for prefix in exempt["autosquash_prefixes"]):
        return [] if allow_autosquash else [
            "subject: fixup!/squash!/amend! commits are allowed only on an unpublished branch; "
            "squash them (git rebase -i --autosquash) before publication"]
    rules, body_rules, ref_rules = policy["subject"], policy["body"], policy["refs"]
    problems = []
    subject, separator, sections, order, stray, trailers, misplaced = parse_message(text)
    match = SUBJECT.match(subject)
    kind = None
    if not match:
        problems.append("subject: must be '<type>(<scope>): <imperative summary>', got "
                        + json.dumps(subject[:80]))
    else:
        kind = match.group("type")
        summary = match.group("summary").strip()
        if kind not in rules["types"]:
            problems.append(f"subject: type {kind!r} is not one of {', '.join(rules['types'])}")
        scope = match.group("scope")
        if scope is None or not re.match(rules["scope_pattern"], scope):
            problems.append("subject: needs a lowercase (scope), e.g. fix(deliver): ...")
        words = summary.split()
        if not words:
            problems.append("subject: summary is empty")
        else:
            first = words[0].lower()
            if first in rules["non_imperative_first_words"] or (
                    first not in rules.get("imperative_exceptions", [])
                    and any(first.endswith(suffix) and len(first) > len(suffix) + 2
                            for suffix in rules.get("non_imperative_suffixes", []))):
                problems.append(f"subject: use the imperative mood ('{words[0]}' -> e.g. 'add', 'fix')")
            if summary.lower().rstrip(".") in rules["boilerplate_summaries"] or len(words) < int(rules.get("min_summary_words", 2)):
                problems.append("subject: summary is boilerplate; say what changed and where")
        if summary.endswith("."):
            problems.append("subject: no trailing period")
    if len(subject) > int(rules["max_length"]):
        problems.append(f"subject: {len(subject)} chars, limit {rules['max_length']}")
    looks_revert = bool(re.search(body_rules.get("revert_detect", r"^This reverts commit [0-9a-f]{7,}"),
                                  text, re.M | re.I)) or bool(match and re.match(r"(?i)revert\b", match.group("summary")))
    if looks_revert and kind and kind != "revert":
        problems.append("subject: this is a revert; use type revert(<scope>) and give Reason: and Authorized-by:")
        kind = "revert"
    if separator is None:
        problems.append("body: missing; add a blank line then Why:/What:/Testing:/Refs: sections")
        return problems
    if separator.strip():
        problems.append("body: the second line must be blank")
    if stray:
        problems.append("body: text before the first section; start the body with 'Why:'")
    required = body_rules["required_sections"]
    for name in required:
        if name not in sections:
            problems.append(f"{name}: section missing")
    duplicated = sorted({name for name in order if order.count(name) > 1})
    for name in duplicated:
        problems.append(f"{name}: section appears more than once")
    seen = [name for name in order if name in required]
    if seen != sorted(seen, key=required.index):
        problems.append("body: sections must appear in the order " + ", ".join(required))
    placeholders = set(body_rules["placeholder_values"])
    for name in ("Why", "What"):
        if name in sections:
            value = _clean(sections[name])
            if not value or value.lower().rstrip(".") in placeholders:
                problems.append(f"{name}: empty or placeholder content")
            elif len(value) < int(body_rules["min_section_chars"]):
                problems.append(f"{name}: too short to explain anything; write a real sentence")
    if "Risk" in sections:
        value = _clean(sections["Risk"])
        if not value or value.lower().rstrip(".") in placeholders - {"none"}:
            problems.append("Risk: empty or placeholder content (omit the section if there is no risk)")
    if "Testing" in sections:
        value = _clean(sections["Testing"])
        prefix = body_rules["testing_not_run_prefix"]
        if value.lower().startswith(prefix):
            reason = value[len(prefix):].strip()
            if len(reason) < 8 or reason.lower().rstrip(".") in placeholders:
                problems.append("Testing: 'not run:' needs a concrete reason")
        elif not value or value.lower().rstrip(".!") in set(body_rules["testing_vague_values"]):
            problems.append("Testing: give the exact command(s) and results, or 'not run: <reason>'")
        elif not COMMAND_HINT.search(value):
            problems.append("Testing: name the exact command (in `backticks` or on its own line)")
        elif not RESULT_HINT.search(value):
            problems.append("Testing: state the result of each command (e.g. '12 passed', 'exit 0')")
    if "Refs" in sections:
        value = _clean(sections["Refs"])
        tickets = ticket_refs(value, policy)
        none = NONE_REF.match(value)
        unverifiable = any(re.search(p, value) for p in ref_rules["unverifiable_patterns"])
        if none:
            if len(none.group("reason").strip()) < 8:
                problems.append("Refs: 'none (<reason>)' needs a real reason")
            if tickets_required and kind and kind not in ref_rules["none_allowed_types"]:
                problems.append(f"Refs: {kind} commits must reference a ticket (e.g. 'GoodQA #1234'); "
                                f"'none' is allowed only for {', '.join(ref_rules['none_allowed_types'])}")
        elif not (tickets or PR_REF.search(value) or unverifiable):
            problems.append("Refs: name a ticket (GoodQA #N), PR, or 'none (<reason>)' for chore/docs")
        if tickets_required and kind in ref_rules["ticket_required_types"] and not tickets and not none:
            extra = " (R- coordinator records cannot be verified and do not count)" if unverifiable else ""
            problems.append(f"Refs: {kind} commits must reference a GoodQA ticket, e.g. 'GoodQA #1234'{extra}")
    if kind == "revert":
        fields = "\n".join([*(f"{k}: {v}" for k, v in sections.items()), *trailers])
        for field in body_rules["revert_required_fields"]:
            pattern = re.compile(rf"^\s*{re.escape(field)}\s*:\s*(.+)$", re.I | re.M)
            found = pattern.search(fields)
            content = _clean(found.group(1)) if found else ""
            if len(content) < 3 or content.lower() in placeholders:
                problems.append(f"revert: needs '{field}: ...' (why it is reverted and who authorized it)")
            elif field.lower() == "authorized-by" and tickets_required and not ticket_refs(content, policy):
                problems.append("revert: Authorized-by must cite the ticket where the authorization is recorded, "
                                "e.g. 'Authorized-by: Eric, GoodQA #14151'")
    if misplaced:
        problems.append("trailers: move Co-Authored-By/Signed-off-by lines to a final paragraph after a blank line")
    if previous is not None and normalize(previous) == text:
        problems.append("message: identical to the previous commit; describe this change specifically")
    return problems


def validate_pr(title: str, body: str, policy: dict, *, tickets_required: bool = True) -> list:
    """GitHub squash uses '<title> (#N)' plus the PR body; both must form a compliant message."""
    limit = int(policy["subject"]["max_length"]) - 8
    problems = []
    if len(title) > limit:
        problems.append(f"PR title: {len(title)} chars; keep it <= {limit} so the squash subject "
                        f"'<title> (#N)' fits {policy['subject']['max_length']}")
    message = title.strip() + "\n\n" + body
    problems += ["PR " + item for item in validate(message, policy=policy, tickets_required=tickets_required)
                 if not item.startswith("message:")]
    return problems


def template(message: str, policy: dict) -> str:
    subject = normalize(message).split("\n", 1)[0] if message.strip() else ""
    match = SUBJECT.match(subject)
    if match and match.group("type") in policy["subject"]["types"]:
        head = subject
    else:
        head = "fix(<scope>): <imperative summary, <=72 chars, no period>"
    return "\n".join([
        head, "",
        "Why: <the problem or motivation, not a restatement of the diff>",
        "What: <the key changes and their behaviour impact>",
        "Testing: `<exact command>` -> <result, e.g. 14 passed>  (or: not run: <reason>)",
        "Refs: GoodQA #<n>  (chore/docs only: none (<reason>))",
        "Risk: <optional: migrations, rollback>", "",
        "Co-Authored-By: <trailers last, after a blank line>"])


# --------------------------------------------------------------------------- git helpers

def git(repo, *args, timeout=10, check=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k in {
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=timeout, env=env)
    if check and result.returncode:
        raise OSError(f"git {args[0]} failed")
    return result.stdout.decode("utf-8", "replace")


def repo_facts(repo):
    """(previous message, head message, branch, merge in progress, published) or None outside a repo."""
    try:
        top = git(repo, "rev-parse", "--show-toplevel").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    head = git(top, "log", "-1", "--format=%B", check=False) or None
    parent = git(top, "log", "-1", "--skip=1", "--format=%B", check=False) or None
    branch = git(top, "symbolic-ref", "--quiet", "--short", "HEAD", check=False).strip()
    merging = bool(git(top, "rev-parse", "-q", "--verify", "MERGE_HEAD", check=False).strip())
    published = bool(branch) and bool(git(top, "for-each-ref", "--count=1", "--format=%(refname)",
                                          f"refs/remotes/*/{branch}", check=False).strip())
    origin = git(top, "remote", "get-url", "origin", check=False).strip() or None
    return {"top": top, "head": head, "parent": parent, "branch": branch, "merging": merging,
            "published": published, "origin": origin}


# --------------------------------------------------------------------------- shell analysis

OPERATORS = ("&&", "||", ";;", "|&", ";", "|", "&", "(", ")", "\n")
REDIRECTS = re.compile(r"^(?:\d*(?:>>|>|<|>&|<&|&>|&>>)|<<<)$")


def _heredocs(command: str):
    """Remove heredoc bodies; return text with <<__HDn__ markers and the bodies.

    Quote-aware: `<<` inside quotes (for example in an ssh remote command string)
    belongs to the inner shell and is left for the recursive analysis.
    """
    opener = re.compile(r"<<(-?)\s*(?:'([^'\n]+)'|\"([^\"\n]+)\"|\\?([A-Za-z_][A-Za-z0-9_]*))")
    # A stack of quote contexts: $( ... ) opens a fresh unquoted context even inside "...".
    out, bodies, lines, index, stack = [], [], command.split("\n"), 0, [None]
    while index < len(lines):
        line, index = lines[index], index + 1
        pending, rebuilt, i = [], [], 0
        while i < len(line):
            ch, quote = line[i], stack[-1]
            if quote == "'":
                if ch == "'":
                    stack[-1] = None
            elif quote == '"':
                if ch == "\\":
                    rebuilt.append(line[i:i + 2])
                    i += 2
                    continue
                if line.startswith("$(", i):
                    stack.append(None)
                    rebuilt.append("$(")
                    i += 2
                    continue
                if ch == '"':
                    stack[-1] = None
            elif ch == "\\":
                rebuilt.append(line[i:i + 2])
                i += 2
                continue
            elif ch in "'\"":
                stack[-1] = ch
            elif line.startswith("$(", i):
                stack.append(None)
                rebuilt.append("$(")
                i += 2
                continue
            elif ch == ")" and len(stack) > 1:
                stack.pop()
            elif ch == "#" and (i == 0 or line[i - 1] in " \t;&|("):
                rebuilt.append(line[i:])
                break
            elif line.startswith("<<<", i):
                rebuilt.append("<<<")
                i += 3
                continue
            elif line.startswith("<<", i):
                match = opener.match(line, i)
                if match:
                    delimiter = match.group(2) or match.group(3) or match.group(4)
                    pending.append((delimiter, bool(match.group(2) or match.group(3)), bool(match.group(1))))
                    rebuilt.append(f"<<__HD{len(bodies) + len(pending) - 1}__")
                    i = match.end()
                    continue
            rebuilt.append(ch)
            i += 1
        out.append("".join(rebuilt))
        for delimiter, quoted, strip_tabs in pending:
            body = []
            while True:
                if index >= len(lines):
                    raise Unresolvable("unterminated heredoc")
                current, index = lines[index], index + 1
                if (current.lstrip("\t") if strip_tabs else current) == delimiter:
                    break
                body.append(current.lstrip("\t") if strip_tabs else current)
            bodies.append(("\n".join(body) + "\n", quoted))
    return "\n".join(out), bodies


def tokenize(text: str):
    """POSIX-ish tokenizer: yields ('op', value) or ('word', value, dynamic)."""
    tokens, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t":
            i += 1
            continue
        if ch == "\\" and text[i:i + 2] == "\\\n":
            i += 2
            continue
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        op = next((item for item in OPERATORS if text.startswith(item, i)), None)
        if op:
            tokens.append(("op", op))
            i += len(op)
            continue
        word, dynamic, started = [], False, False
        while i < n:
            ch = text[i]
            if ch in " \t" or next((item for item in OPERATORS if text.startswith(item, i)), None):
                break
            started = True
            if ch == "\\":
                if i + 1 < n and text[i + 1] == "\n":
                    i += 2
                    continue
                if i + 1 < n:
                    word.append(text[i + 1])
                i += 2
            elif ch == "'":
                end = text.find("'", i + 1)
                if end < 0:
                    raise Unresolvable("unterminated single quote")
                word.append(text[i + 1:end])
                i = end + 1
            elif ch == '"':
                i += 1
                while True:
                    if i >= n:
                        raise Unresolvable("unterminated double quote")
                    ch = text[i]
                    if ch == '"':
                        i += 1
                        break
                    if ch == "\\" and i + 1 < n and text[i + 1] in '$`"\\\n':
                        if text[i + 1] != "\n":
                            word.append(text[i + 1])
                        i += 2
                        continue
                    if ch == "$" and text.startswith("$(", i):
                        depth, j = 0, i
                        while j < n:
                            if text[j] == "(":
                                depth += 1
                            elif text[j] == ")":
                                depth -= 1
                                if depth == 0:
                                    break
                            j += 1
                        inner = text[i:j + 1]
                        placeholder = re.fullmatch(r"\$\(\s*cat\s+<<__HD(\d+)__\s*\)", inner, re.S)
                        if placeholder:
                            word.append(f"\x00HD{placeholder.group(1)}\x00")
                        else:
                            dynamic = True
                            word.append(inner)
                        i = j + 1
                        continue
                    if ch in "$`" and not (ch == "$" and (i + 1 >= n or text[i + 1] in '" ')):
                        dynamic = True
                    word.append(ch)
                    i += 1
            elif ch == "$" and text.startswith("$(", i):
                depth, j = 0, i
                while j < n:
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                inner = text[i:j + 1]
                placeholder = re.fullmatch(r"\$\(\s*cat\s+<<__HD(\d+)__\s*\)", inner, re.S)
                word.append(f"\x00HD{placeholder.group(1)}\x00" if placeholder else inner)
                dynamic = dynamic or not placeholder
                i = j + 1
            elif ch == "`":
                # Backquoted command substitution is one word up to the closing backtick.
                end = text.find("`", i + 1)
                if end < 0:
                    raise Unresolvable("unterminated backtick")
                dynamic = True
                word.append(text[i:end + 1])
                i = end + 1
            elif ch == "$":
                dynamic = True
                word.append(ch)
                i += 1
            elif text.startswith("<<__HD", i):
                end = text.index("__", i + 6) + 2
                if word:
                    break
                tokens.append(("heredoc", int(text[i + 6:end - 2])))
                i = end
                started = False
                break
            else:
                word.append(ch)
                i += 1
        if started:
            tokens.append(("word", "".join(word), dynamic))
    return tokens


def simple_commands(tokens):
    commands, current = [], []
    for token in tokens:
        if token[0] == "op":
            if current:
                commands.append((current, token[1]))
            current = []
        else:
            current.append(token)
    if current:
        commands.append((current, ""))
    return commands


def expand(value: str, bodies) -> str:
    def replace(match):
        if int(match.group(1)) >= len(bodies):
            raise Unresolvable("heredoc nesting cannot be resolved; write the message to a file and use -F")
        body, quoted = bodies[int(match.group(1))]
        if not quoted and re.search(r"[$`\\]", body):
            raise Unresolvable("heredoc message is unquoted and contains $, ` or \\; use <<'EOF'")
        return body.rstrip("\n")
    return re.sub(r"\x00HD(\d+)\x00", replace, value)


COMMIT_ARG_LONG = {"message", "file", "reuse-message", "reedit-message", "template", "author", "date",
                   "cleanup", "trailer", "fixup", "squash", "pathspec-from-file", "gpg-sign", "untracked-files"}
COMMIT_OPTIONAL_LONG = {"gpg-sign", "untracked-files"}
COMMIT_FLAGS_LONG = {"all", "patch", "amend", "no-edit", "edit", "signoff", "no-signoff", "no-verify", "verify",
                     "allow-empty", "allow-empty-message", "dry-run", "short", "branch", "porcelain", "long",
                     "null", "include", "only", "quiet", "verbose", "status", "no-status", "reset-author",
                     "no-gpg-sign", "interactive", "help", "pathspec-file-nul", "no-post-rewrite"}


def _long(name: str):
    candidates = [item for item in COMMIT_ARG_LONG | COMMIT_FLAGS_LONG if item.startswith(name)]
    if name in COMMIT_ARG_LONG | COMMIT_FLAGS_LONG:
        return name
    if len(candidates) == 1:
        return candidates[0]
    raise Unresolvable(f"unknown or ambiguous git commit option --{name}")


def parse_commit_args(args):
    """Return option dict from git commit argument words (already static strings)."""
    opts = {"message": [], "file": None, "reuse": None, "amend": False, "no_edit": False, "fixup": None,
            "squash": None, "trailer": [], "template": None, "dry_run": False, "allow_empty_message": False,
            "help": False, "edit": False, "cleanup": None}
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            break
        if arg.startswith("--"):
            name, eq, value = arg[2:].partition("=")
            name = _long(name)
            if name in COMMIT_ARG_LONG and not eq and name not in COMMIT_OPTIONAL_LONG:
                if i >= len(args):
                    raise Unresolvable(f"--{name} needs a value")
                value = args[i]
                i += 1
            if name == "message":
                opts["message"].append(value)
            elif name == "file":
                opts["file"] = value
            elif name in ("reuse-message", "reedit-message"):
                opts["reuse"] = value
                opts["no_edit"] = opts["no_edit"] or name == "reuse-message"
            elif name in ("fixup", "squash"):
                opts[name] = value
            elif name == "trailer":
                opts["trailer"].append(value)
            elif name == "template":
                opts["template"] = value
            elif name == "amend":
                opts["amend"] = True
            elif name == "no-edit":
                opts["no_edit"] = True
            elif name == "edit":
                opts["edit"] = True
            elif name == "cleanup":
                opts["cleanup"] = value
            elif name in ("dry-run", "short", "porcelain", "long"):
                opts["dry_run"] = True
            elif name == "allow-empty-message":
                opts["allow_empty_message"] = True
            elif name == "help":
                opts["help"] = True
            continue
        if arg.startswith("-") and len(arg) > 1:
            j = 1
            while j < len(arg):
                flag = arg[j]
                j += 1
                if flag in "mFCct":
                    value = arg[j:]
                    if not value:
                        if i >= len(args):
                            raise Unresolvable(f"-{flag} needs a value")
                        value = args[i]
                        i += 1
                    if flag == "m":
                        opts["message"].append(value)
                    elif flag == "F":
                        opts["file"] = value
                    elif flag in "Cc":
                        opts["reuse"] = value
                        opts["no_edit"] = opts["no_edit"] or flag == "C"
                    else:
                        opts["template"] = value
                    break
                if flag in "Su":
                    break  # optional attached argument
                if flag == "h":
                    opts["help"] = True
                if flag == "e":
                    opts["edit"] = True
    return opts


def _apply_trailers(message: str, trailers) -> str:
    if not trailers:
        return message
    lines = [re.sub(r"\s*[=:]\s*", ": ", item, count=1) for item in trailers]
    paragraphs = message.split("\n\n")
    if len(paragraphs) > 1 and all(TRAILER_LINE.match(line) for line in paragraphs[-1].split("\n")):
        return message + "\n" + "\n".join(lines)
    return message + "\n\n" + "\n".join(lines)


def resolve_commit(args, cwd, stdin_body, facts):
    """Return (message or None if exempt-nothing-to-check, context dict)."""
    opts = parse_commit_args(args)
    context = {"amend": opts["amend"]}
    if opts["help"] or opts["dry_run"]:
        return None, context
    if opts["allow_empty_message"]:
        raise Unresolvable("--allow-empty-message is not allowed")
    if opts["edit"]:
        raise Unresolvable("-e/--edit lets an editor rewrite the message after it is checked; drop it")
    if opts["cleanup"] not in (None, "default", "whitespace", "verbatim"):
        raise Unresolvable(f"--cleanup={opts['cleanup']} changes the message after it is checked; omit it")
    context["file"] = opts["file"]
    if opts["fixup"] is not None or opts["squash"] is not None:
        target = opts["fixup"] if opts["fixup"] is not None else opts["squash"]
        prefix = "squash! " if opts["squash"] is not None else "fixup! "
        if opts["fixup"] and re.match(r"^(amend|reword):", opts["fixup"]):
            prefix = "amend! "
        return prefix + target, context
    parts = list(opts["message"])
    if opts["file"] is not None:
        if opts["file"] == "-":
            if stdin_body is None:
                raise Unresolvable("-F - reads stdin; supply it with a quoted heredoc (<<'EOF')")
            parts.append(stdin_body)
        else:
            path = Path(os.path.expanduser(opts["file"]))
            if not path.is_absolute() and not cwd:
                raise Unresolvable(f"the working directory is not known statically, so the relative message file "
                                   f"{opts['file']} cannot be located; use an absolute -F path")
            path = path if path.is_absolute() else Path(cwd) / path
            try:
                info = path.stat()
                if info.st_size > 65536:
                    raise Unresolvable("message file exceeds 64 KiB")
                parts.append(path.read_text(encoding="utf-8", errors="replace"))
            except FileNotFoundError:
                raise Unresolvable(f"message file {opts['file']} does not exist yet; write it in a separate "
                                   "step, then run git commit -F <file>") from None
            except OSError:
                raise Unresolvable(f"message file {opts['file']} is unreadable") from None
    if opts["reuse"] is not None and not parts:
        if facts is None:
            raise Unresolvable("cannot read the reused commit message outside a repository")
        try:
            parts.append(git(facts["top"], "log", "-1", "--format=%B", opts["reuse"], "--"))
        except (OSError, subprocess.TimeoutExpired):
            raise Unresolvable(f"cannot read commit {opts['reuse']!r} to reuse its message") from None
        if not opts["no_edit"]:
            raise Unresolvable("-c opens an editor; use -C, -m or -F")
    if not parts:
        if opts["amend"] and opts["no_edit"]:
            if facts is None or facts["head"] is None:
                raise Unresolvable("cannot read HEAD to validate --amend --no-edit")
            parts.append(facts["head"])
        else:
            raise Unresolvable("this commit would open an editor; pass the message with -m, -F <file> or "
                               "-F - <<'EOF'")
    message = "\n\n".join(normalize(part) for part in parts)
    return _apply_trailers(message, opts["trailer"]), context


def _gh_merge(args):
    squash = any(arg in ("--squash", "-s") for arg in args)
    if not squash:
        return None
    subject = body = None
    i = 0
    while i < len(args):
        arg = args[i]
        name, eq, value = arg.partition("=")
        if name in ("--subject", "-t", "--body", "-b", "--body-file", "-F"):
            if not eq:
                if i + 1 >= len(args):
                    raise Unresolvable(f"{name} needs a value")
                value = args[i + 1]
                i += 1
            if name in ("--subject", "-t"):
                subject = value
            elif name in ("--body", "-b"):
                body = value
            else:
                raise Unresolvable("gh pr merge --body-file cannot be checked statically; pass --body")
        i += 1
    if subject is None or body is None:
        raise Unresolvable("gh pr merge --squash needs an explicit compliant --subject and --body; the squash "
                           "commit is the final published message")
    return subject + "\n\n" + body


GITHUB_SLUG = re.compile(r"github\.com[:/](?P<slug>[\w.-]+/[\w.-]+?)(?:\.git)?/?$")


def _gh_create(args, cwd, remote):
    """Resolve repo/base/head/title/body for gh pr create so the range can be checked on GitHub."""
    values = {"repo": None, "base": None, "head": None, "title": None, "body": None}
    names = {"-R": "repo", "--repo": "repo", "-B": "base", "--base": "base", "-H": "head", "--head": "head",
             "-t": "title", "--title": "title", "-b": "body", "--body": "body"}
    i = 0
    while i < len(args):
        name, eq, value = args[i].partition("=")
        if name in ("-F", "--body-file"):
            raise Unresolvable("gh pr create --body-file cannot be checked statically; pass --body")
        if name in names:
            if not eq:
                if i + 1 >= len(args):
                    raise Unresolvable(f"{name} needs a value")
                value = args[i + 1]
                i += 1
            values[names[name]] = value
        i += 1
    if remote or not cwd:
        if not values["repo"] or not values["head"]:
            raise Unresolvable("gh pr create on a remote host needs explicit -R <owner/repo> --head <branch> "
                               "(and --base) so the commit range can be checked on GitHub first")
        return values
    facts = repo_facts(cwd)
    if values["repo"] is None and facts and facts["origin"]:
        match = GITHUB_SLUG.search(facts["origin"])
        values["repo"] = match.group("slug") if match else None
    if values["head"] is None and facts:
        values["head"] = facts["branch"] or None
    if not values["repo"] or not values["head"]:
        raise Unresolvable("cannot tell which repository and branch gh pr create publishes; pass -R and --head")
    return values


WRAPPERS = {"env", "command", "exec", "time", "nohup", "nice", "builtin", "caffeinate", "timeout",
            "gtimeout", "stdbuf", "ionice", "chronic"}
COMMIT_TEXT = re.compile(r"\bgit\b[^|;&]*\b(?:commit|commit-tree|revert)\b|\bgh\s+pr\s+(?:create|merge)\b")
SHELL_VALUE_OPTIONS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
WRAPPER_VALUE_FLAGS = {"nice": {"-n", "--adjustment"}, "timeout": {"-s", "-k", "--signal", "--kill-after"},
                       "gtimeout": {"-s", "-k", "--signal", "--kill-after"}, "ionice": {"-c", "-n", "-p", "-t"},
                       "stdbuf": {"-i", "-o", "-e"}, "env": {"-u", "--unset", "-C", "--chdir"}}
READ_ONLY = {"cat", "head", "tail", "wc", "grep", "rg", "less", "ls", "test", "[", "stat", "file", "echo"}
READ_ONLY_GIT = {"add", "diff", "status", "show", "log", "commit"}
RESERVED = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "fi", "done", "in"}
TEXT_TOOLS = {"echo", "printf", "grep", "egrep", "rg", "ag", "awk", "sed", "cat", "less", "man", "head", "tail"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh"}


SSH_ARG_OPTIONS = set("BbcDEeFIiJLlmOoPpQRSWw")
GIT_KNOWN = {"add", "am", "archive", "backfill", "bisect", "branch", "bundle", "checkout", "cherry-pick",
             "citool", "clean", "clone", "commit", "describe", "diff", "fetch", "format-patch", "gc", "gitk",
             "grep", "gui", "init", "log", "maintenance", "merge", "mv", "notes", "pull", "push",
             "range-diff", "rebase", "reset", "restore", "revert", "rm", "scalar", "shortlog", "show",
             "sparse-checkout", "stash", "status", "submodule", "switch", "tag", "worktree", "config",
             "fast-export", "fast-import", "filter-branch", "mergetool", "pack-refs", "prune", "reflog",
             "refs", "remote", "repack", "replace", "annotate", "blame", "bugreport", "count-objects",
             "diagnose", "difftool", "fsck", "gitweb", "help", "instaweb", "merge-tree", "rerere",
             "show-branch", "verify-commit", "verify-tag", "version", "whatchanged", "apply",
             "checkout-index", "commit-graph", "commit-tree", "hash-object", "index-pack", "merge-file",
             "merge-index", "mktag", "mktree", "multi-pack-index", "pack-objects", "prune-packed",
             "read-tree", "replay", "symbolic-ref", "unpack-objects", "update-index", "update-ref",
             "write-tree", "cat-file", "cherry", "diff-files", "diff-index", "diff-pairs", "diff-tree",
             "for-each-ref", "for-each-repo", "get-tar-commit-id", "last-modified", "ls-files", "ls-remote",
             "ls-tree", "merge-base", "name-rev", "pack-redundant", "repo", "rev-list", "rev-parse",
             "show-index", "show-ref", "unpack-file", "var", "verify-pack", "check-attr", "check-ignore",
             "check-mailmap", "check-ref-format", "column", "credential", "hook", "interpret-trailers",
             "mailinfo", "mailsplit", "patch-id", "stripspace", "lfs"}


def _mentions_commit(text, depth):
    try:
        return bool(analyze(text, None, depth + 1))
    except Unresolvable:
        return True


def _shell_script(argv, stdin_body):
    """(script text, dynamic) for `bash [-opts]c 'script'`, `bash -s`/`bash` reading a heredoc."""
    i = 1
    while i < len(argv):
        word = argv[i][1]
        if word in SHELL_VALUE_OPTIONS:
            i += 2
            continue
        if word.startswith("--"):
            i += 1
            continue
        if word[:1] in "-+" and len(word) > 1:
            if word[0] == "-" and "c" in word[1:]:
                j = i + 1
                if j < len(argv) and argv[j][1] == "--":
                    j += 1
                return (argv[j][1], argv[j][2]) if j < len(argv) else None
            # -euo pipefail: a trailing o (or O) in a group takes the next word as its value
            i += 2 if word[-1] in "oO" else 1
            continue
        # A script file runs code the hook cannot see. Refuse only when the same
        # invocation visibly mentions a commit; plain `bash deploy.sh` stays allowed.
        if any(COMMIT_TEXT.search(w[1]) or w[1] == "commit" for w in argv[i:]):
            raise Unresolvable(f"{os.path.basename(argv[0][1])} {word} hides its script from the policy; "
                               "run git commit directly")
        return None
    return (stdin_body, False) if stdin_body else None


def _ssh_remote(argv, stdin_body, bodies):
    """Return (host, remote command text) for an ssh invocation, or None without a command."""
    i = 1
    while i < len(argv):
        word = argv[i][1]
        if word == "--":
            i += 1
            break
        if not word.startswith("-") or word == "-":
            break
        i += 1
        # Grouped flags (-qi key, -tp 22): a value-taking letter consumes the rest of the
        # group, or the next argument when it is the last letter.
        for position, letter in enumerate(word[1:], 1):
            if letter in SSH_ARG_OPTIONS:
                if position == len(word) - 1:
                    i += 1
                break
    if i >= len(argv):
        return None
    host, rest = argv[i][1], argv[i + 1:]
    if any(w[2] for w in rest) and any(re.search(r"\b(?:commit|pr)\b", w[1]) for w in rest):
        raise Unresolvable("ssh remote command contains local shell expansion; quote the whole remote "
                           "command in single quotes")
    words = [expand(w[1], bodies) for w in rest]  # local $(cat <<EOF) runs before ssh sends the text
    if not words or (len(words) <= 2 and os.path.basename(words[0]) in SHELLS
                     and all(w in ("-s", "-l", "--login", "-e") for w in words[1:])):
        return (host, stdin_body) if stdin_body else None
    return host, " ".join(words)


def analyze(command: str, cwd: str, depth: int = 0, remote: str | None = None):
    """Yield (message, cwd, context) for every commit-creating invocation in a shell command.

    remote names the ssh host when the text runs there: its files and repository
    cannot be read from here, so only inline messages can be checked.
    """
    if depth > 3:
        raise Unresolvable("nested shells are too deep to analyze")
    text, bodies = _heredocs(command)
    found, writes = [], []  # writes: normalized paths this command may write (None = unknown)

    def write_target(word):
        if word[2]:
            return None
        path = os.path.expanduser(word[1])
        if not os.path.isabs(path):
            if not cwd:
                return None
            path = os.path.join(cwd, path)
        return os.path.normpath(path)

    segments = []  # (argv words, git subcommand) for the -F mention check
    previous_op = ""
    for words, operator in simple_commands(tokenize(text)):
        piped, previous_op = previous_op in ("|", "|&"), operator
        stdin_body = stdin_raw = None
        argv = []
        skip_next = write_next = False
        for index, token in enumerate(words):
            if token[0] == "heredoc":
                stdin_raw = bodies[token[1]][0]
                stdin_body = stdin_raw if bodies[token[1]][1] or not re.search(r"[$`\\]", stdin_raw) else None
                continue
            if skip_next:
                skip_next = False
                if write_next:
                    writes.append(write_target(token))
                continue
            if REDIRECTS.match(token[1]):
                skip_next, write_next = True, ">" in token[1]
                continue
            attached = re.match(r"^\d*&?>>?(\S+)$", token[1])
            if attached:
                writes.append(write_target((token[0], attached.group(1), token[2])))
                continue
            if re.match(r"^\d*<\S+$", token[1]) and not argv:
                continue
            argv.append(token)
        for word in argv:
            if word[2] and re.search(r"\$\(|`", word[1]):
                inner = [a or b for a, b in re.findall(r"\$\((.*)\)|`([^`]*)`", word[1], re.S)]
                if COMMIT_TEXT.search(word[1]) or any(_mentions_commit(part, depth) for part in inner):
                    raise Unresolvable("git commit inside $(...) or backticks cannot be checked; run git commit "
                                       "as its own command (capture output with 2>&1 | tee if needed)")
        if argv and argv[0][2] and any(w[1] == "commit" for w in argv[1:]):
            raise Unresolvable("the command name is computed at run time ($VAR or $(...)); run git commit directly")
        while argv and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0][1]) or argv[0][1] in RESERVED):
            argv = argv[1:]
        while argv and os.path.basename(argv[0][1]) in WRAPPERS:
            wrapper = os.path.basename(argv[0][1])
            if wrapper == "env" and any(w[1] in ("-S", "--split-string") or w[1].startswith("--split-string=")
                                        for w in argv[1:]):
                raise Unresolvable("env -S splits a string the policy cannot follow; run git commit directly")
            argv = argv[1:]
            takes_value = WRAPPER_VALUE_FLAGS.get(wrapper, set())
            while argv and (argv[0][1].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0][1])):
                argv = argv[2:] if argv[0][1] in takes_value else argv[1:]
            if wrapper in ("timeout", "gtimeout") and argv and re.match(r"^\d+(?:\.\d+)?[smhd]?$", argv[0][1]):
                argv = argv[1:]
        # Closing rule: a git commit handed to another program (xargs, find -exec, parallel,
        # a script runner) cannot be seen; refuse instead of silently allowing it.
        names = [os.path.basename(w[1]) for w in argv]
        if argv and names[0] not in ("git", "gh", "ssh", *SHELLS, *TEXT_TOOLS) and "git" in names[1:] \
                and "commit" in names[names.index("git", 1):]:
            raise Unresolvable(f"git commit run through {names[0]} cannot be checked; run git commit directly")
        if not argv:
            continue
        name = os.path.basename(argv[0][1])
        operands = [w for w in argv[1:] if not w[1].startswith("-")]
        if name == "tee":
            writes.extend(write_target(w) for w in operands)
        elif name in ("cp", "mv", "install", "ln", "rsync") and len(operands) >= 2:
            destination = write_target(operands[-1])
            writes.append(destination)
            if destination:
                writes.extend(os.path.join(destination, os.path.basename(w[1])) for w in operands[:-1])
        sub_name = next((w[1] for w in argv[1:] if not w[1].startswith("-")), "") if name == "git" else ""
        segments.append(([w[1] for w in argv], name, sub_name))
        if name in ("cd", "pushd") and len(argv) >= 2:
            if argv[1][2]:
                cwd = None
            else:
                target = os.path.expanduser(argv[1][1])
                cwd = target if os.path.isabs(target) else (os.path.join(cwd, target) if cwd else None)
            continue
        if name in SHELLS:
            if ((piped and COMMIT_TEXT.search(text))
                    or (stdin_raw and stdin_body is None and COMMIT_TEXT.search(stdin_raw))):
                raise Unresolvable(f"{name} reads its script from a pipe or an unquoted heredoc the policy cannot "
                                   "see exactly; run git commit directly or use a quoted heredoc (<<'EOF')")
            script = _shell_script(argv, stdin_body)
            if script is not None and re.search(r"\b(?:commit|revert|merge|pr)\b", script[0]):
                if script[1]:
                    raise Unresolvable(f"{name} with a dynamic script cannot be checked")
                found.extend(analyze(expand(script[0], bodies), cwd, depth + 1, remote))
            continue
        if name == "ssh":
            target = _ssh_remote(argv, stdin_body, bodies)
            if target and re.search(r"\b(?:git|gh)\b", target[1]) and re.search(
                    r"\b(?:commit|commit-tree|revert|merge|pr)\b", target[1]):
                found.extend(analyze(target[1], None, depth + 1, target[0]))
            continue
        if name in ("eval", "xargs") and any(re.search(r"\bcommit\b", w[1]) for w in argv[1:]):
            raise Unresolvable(f"{name} around git commit cannot be checked; run git commit directly")
        if name == "gh" and len(argv) >= 3 and argv[1][1] == "pr" and argv[2][1] in ("merge", "create"):
            if any(w[2] for w in argv[3:]):
                raise Unresolvable(f"gh pr {argv[2][1]} arguments contain shell expansion")
            values = [expand(w[1], bodies) for w in argv[3:]]
            if argv[2][1] == "create":
                found.append((None, cwd, {"pr_create": _gh_create(values, cwd, remote), "remote": remote}))
                continue
            message = _gh_merge(values)
            if message is not None:
                found.append((message, cwd, {"gh_squash": True, "remote": remote}))
            continue
        if name != "git":
            continue
        repo = cwd
        i = 1
        while i < len(argv):
            word = argv[i][1]
            if word == "-C" and i + 1 < len(argv):
                if argv[i + 1][2]:
                    repo = None
                else:
                    target = os.path.expanduser(argv[i + 1][1])
                    repo = target if os.path.isabs(target) else (os.path.join(repo, target) if repo else None)
                i += 2
            elif word in ("-c", "--namespace", "--exec-path", "--git-dir", "--work-tree", "--config-env") \
                    and i + 1 < len(argv) and "=" not in word:
                i += 2
            elif word.startswith("-"):
                i += 1
            else:
                break
        if i >= len(argv):
            continue
        if any(argv[k][1].startswith("alias.") or argv[k][1].startswith("--config-env")
               for k in range(1, i)):
            raise Unresolvable("git -c alias... defines an alias the policy cannot follow; run git commit directly")
        sub = argv[i][1]
        if sub == "history":
            raise Unresolvable("git history rewrites commit messages in an editor; use git commit --amend -F")
        if sub not in GIT_KNOWN:
            # An alias can be defined by this same command (git config, GIT_CONFIG_*), so
            # its current value proves nothing: refuse unknown subcommands next to a commit.
            raise Unresolvable(f"git {sub} is not a built-in git command (an alias?); in a command that "
                               "commits, run the underlying git command directly")
        rest = argv[i + 1:]
        if sub == "commit":
            if any(w[2] for w in rest):
                raise Unresolvable("git commit arguments contain shell expansion ($VAR, $(...) or backticks); "
                                   "use literal -m text, -F <file>, or -m \"$(cat <<'EOF' ... EOF)\"")
            values = [expand(w[1], bodies) for w in rest]
            if remote:
                opts = parse_commit_args(values)
                if opts["file"] not in (None, "-") or (opts["amend"] and not opts["message"] and opts["file"] is None) \
                        or opts["reuse"] is not None:
                    raise Unresolvable(f"git commit on {remote} reads its message from that host (a file, HEAD or "
                                       "another commit), which cannot be checked from here; pass it inline: "
                                       "ssh host 'cd repo && git commit -F - <<\"EOF\"' with the message, or -m")
            facts = repo_facts(repo) if repo and not remote else None
            message, context = resolve_commit(values, repo, stdin_body, facts)
            if context.get("file") not in (None, "-"):
                context["file_abs"] = write_target(("word", context["file"], False)) if not repo else os.path.normpath(
                    os.path.join(repo, os.path.expanduser(context["file"])))
            if message is not None:
                context["facts"] = facts
                context["remote"] = remote
                context["unknown_repo"] = repo is None
                found.append((message, repo, context))
        elif sub == "revert":
            flags = {w[1] for w in rest}
            if not flags & {"--no-commit", "-n", "--abort", "--continue", "--quit", "--skip"}:
                raise Unresolvable("git revert writes a message with no reason; run `git revert --no-commit <sha>` "
                                   "then commit with a revert(<scope>): message including Reason: and Authorized-by:")
        elif sub == "commit-tree":
            raise Unresolvable("git commit-tree bypasses message checks; use git commit")
    for _, _, context in found:
        if context.get("file") not in (None, "-"):
            base = os.path.basename(context["file"])
            for words_text, name, sub_name in segments:
                if name in READ_ONLY or (name == "git" and sub_name in READ_ONLY_GIT):
                    continue
                if any(re.search(rf"(?<![\w.-]){re.escape(base)}(?![\w.-])", w) for w in words_text):
                    raise Unresolvable(f"{name} also touches the message file {context['file']} in this command; "
                                       "write and check the message in an earlier step, then git commit -F")
        path = context.get("file_abs")
        if path and (path in writes or None in writes):
            raise Unresolvable(f"the message file {context['file']} may be written by this same command, so the "
                               "checked content may not be what git commits; write it in an earlier step")
    return found


# --------------------------------------------------------------------------- waivers

def wal_roots():
    return [Path.home() / ".claude" / "wals", Path.home() / ".agent-harness" / "codex-wals"]


def _read_lines(path: Path, limit: int = 64_000_000):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return []
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return []
        return handle.read(limit).decode("utf-8", "replace").splitlines()


def find_waiver(kind: str, subject: str, policy: dict, *, session_dir: Path | None = None):
    """A waiver counts only if the ledger entry and its WAL record (same id) both exist."""
    max_age = timedelta(hours=float(policy["waivers"].get("max_age_hours", 72)))
    now = datetime.now(timezone.utc)
    for line in reversed(_read_lines(LEDGER, 16_000_000)):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("kind") != kind or entry.get("subject") != subject:
            continue
        try:
            when = datetime.fromisoformat(entry["at"])
        except (KeyError, ValueError):
            continue
        if now - when > max_age:
            continue
        wal = Path(entry.get("wal", ""))
        if not any(wal.parent.parent == root for root in wal_roots()):
            continue
        if session_dir is not None and wal.parent != session_dir:
            continue
        marker = f'"waiver_id":"{entry.get("id")}"'
        if any(marker in item and '"event":"waiver"' in item for item in _read_lines(wal)):
            return entry
    return None


def record_waiver(wal: Path, kind: str, subject: str, reason: str, policy: dict):
    from wal import append  # sibling wal.py: Claude or Codex flavour, each enforcing its own root
    try:
        from wal_note import SECRET_PATTERN  # Claude install
    except ImportError:
        from wal import SECRET_PATTERN  # Codex install keeps it in wal.py
    reason = reason.strip()
    if len(reason) < int(policy["waivers"]["min_reason_chars"]) or len(reason) > 1000:
        raise ValueError(f"reason must be {policy['waivers']['min_reason_chars']} to 1000 characters")
    if SECRET_PATTERN.search(reason):
        raise ValueError("reason appears to contain a credential; redact it")
    wal = wal.absolute()
    if not any(wal.parent.parent == root for root in wal_roots()) or wal.suffix != ".jsonl":
        raise ValueError("--wal must be your session WAL under ~/.claude/wals or ~/.agent-harness/codex-wals")
    waiver_id = secrets.token_hex(8)
    at = datetime.now(timezone.utc).isoformat()
    append(wal, {"at": at, "event": "waiver", "waiver_id": waiver_id, "kind": kind,
                 "subject": subject, "note": "COMMIT_POLICY_WAIVER: " + reason})
    LEDGER.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(LEDGER.parent, 0o700)
    fd = os.open(LEDGER, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"at": at, "id": waiver_id, "kind": kind, "subject": subject,
                                 "wal": str(wal)}, separators=(",", ":")) + "\n")
    return waiver_id


# --------------------------------------------------------------------------- hooks

def session_wal(payload: dict):
    session = payload.get("session_id")
    if not session:
        return None, None
    sys.path.insert(0, str(HERE))
    try:
        from wal import safe_id
    except ImportError:
        return None, None
    # The Codex install lives in ~/.codex/agent-harness; its WALs live elsewhere.
    root = (Path.home() / ".agent-harness" / "codex-wals") if HERE.parent.name == ".codex" else (
        Path.home() / ".claude" / "wals")
    directory = root / safe_id(session)
    agent = payload.get("agent_id")
    return directory, directory / (f"agent-{safe_id(agent)}.jsonl" if agent else "main.jsonl")


def block_text(problems, message, policy, *, wal=None, kind="message", subject=None):
    script = HERE / "commit_policy.py"
    lines = ["Commit blocked by the Agent Harness commit policy (" + str(POLICY_FILE) + ").", "Problems:"]
    lines += [f"  - {item}" for item in problems]
    lines += ["", "Write the message in this shape (every section needs real content):", ""]
    lines += ["    " + line for line in template(message, policy).split("\n")]
    lines += ["",
              "Commit it with: git commit -F <message-file>   or   git commit -m \"$(cat <<'EOF'",
              "<message>", "EOF", ")\"",
              f"Check a draft first: python3 {script} check-message --file <message-file>"]
    if subject:
        lines += ["Only if this commit truly cannot comply, record a reasoned exception (the user is asked to approve it):",
                  f"  python3 {script} waive --wal {wal or '<your WAL path>'} --kind {kind} --subject {subject} "
                  "--reason '<why, and who authorized it>'"]
    return "\n".join(lines)


def run_hook(payload: dict, policy: dict) -> tuple:
    """Return (exit_code, stderr_text)."""
    if policy.get("enforcement") == "off":
        return 0, ""
    command = command_text(payload.get("tool_input"))
    if not command:
        raw = json.dumps(payload.get("tool_input"), ensure_ascii=False) if payload.get("tool_input") else ""
        if shell_like(payload) and re.search(r"\bgit\b", raw) and re.search(r"\bcommit\b", raw):
            return 2, ("Commit policy: this tool call looks like it runs git commit, but its input shape is not "
                       "a shell command the policy can check (e.g. interactive stdin). Run git commit as a "
                       "single shell command: git commit -F <message-file>.")
        return 0, ""
    if not command or not re.search(r"\b(?:git|gh)\b", command) or not re.search(
            r"\b(?:commit|commit-tree|revert|merge)\b|\bpr\s+create\b", command):
        return 0, ""
    session_dir, wal = session_wal(payload)
    cwd = payload.get("cwd") or os.getcwd()
    try:
        invocations = analyze(command, cwd)
    except Unresolvable as error:
        return 2, ("Commit blocked by the Agent Harness commit policy: the message cannot be checked before "
                   f"running ({error}).\nSupported forms: git commit -m '<literal>' (repeat -m per paragraph), "
                   "git commit -F <existing file>, git commit -F - <<'EOF' ... EOF, or "
                   "git commit -m \"$(cat <<'EOF' ... EOF)\". Write message files in an earlier step.")
    except Exception as error:  # never crash into an unexplained block
        return 2, f"Commit policy hook could not analyze this command ({type(error).__name__}); use git commit -F <file>."
    for message, repo, context in invocations:
        if context.get("pr_create"):
            code, text = _check_pr_create(context["pr_create"], policy, session_dir)
            if code:
                return code, text
            continue
        facts = context.get("facts")
        if facts is None and repo and not context.get("remote"):
            facts = repo_facts(repo)
        previous = None
        if facts:
            previous = facts["parent"] if context.get("amend") else facts["head"]
        problems = validate(message, policy=policy, previous=previous,
                            is_merge=bool(facts and facts["merging"]),
                            allow_autosquash=bool(facts and not facts["published"]
                                                  and facts["branch"] not in ("main", "master", "")),
                            tickets_required=(bool(policy.get("remote_tickets_required", True))
                                              if context.get("remote") or context.get("unknown_repo")
                                              else tickets_required_for(facts and facts["origin"], policy)))
        if problems:
            subject = digest(message)
            if session_dir is not None and find_waiver("message", subject, policy, session_dir=session_dir):
                continue
            text = block_text(problems, message, policy, wal=wal, subject=subject)
            if policy.get("enforcement") == "warn":
                return 0, "commit-policy (warn mode, not blocking):\n" + text
            return 2, text
    return 0, ""


def _check_pr_create(target, policy, session_dir):
    """gh pr create publishes: check the branch range on GitHub and the PR text first."""
    slug, head = target["repo"], target["head"]  # keep owner:branch for forks
    base = target["base"]
    try:
        if base is None:
            info = subprocess.run(["gh", "api", f"repos/{slug}", "--jq", ".default_branch"],
                                  capture_output=True, text=True, timeout=10)
            base = info.stdout.strip() if info.returncode == 0 else None
        if not base:
            raise OSError("cannot read the repository default branch; pass --base")
        config = policy["ticket_systems"]
        for system in config.values():
            # The hook timeout is 60s: 10s default branch + 15s compare + 25s tickets.
            system["total_deadline_seconds"] = min(float(system.get("total_deadline_seconds", 90)), 25)
        report = check_github(slug, base, head, policy, verify_tickets=True, timeout=15)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return 2, (f"PR blocked by the commit policy: the branch range could not be checked ({error}). "
                   f"Push the branch first, then run: python3 {HERE / 'commit_policy.py'} check-github "
                   f"--repo {slug} --base <base> --head {head}")
    problems = []
    if target["title"] is not None and target["body"] is not None:
        problems = validate_pr(target["title"], target["body"], policy,
                               tickets_required=tickets_required_for(f"https://github.com/{slug}", policy))
    elif target["title"] is not None or target["body"] is not None:
        problems = ["PR: pass both --title and --body (GitHub squash uses them as the final commit message)"]
    if report["status"] == "PASS" and not problems:
        return 0, ""
    text = "PR blocked by the commit policy.\n" + format_report(report)
    if problems:
        text += "\n  PR title/body:\n" + "\n".join("      - " + item for item in problems)
    if policy.get("enforcement") == "warn":
        return 0, "commit-policy (warn mode, not blocking):\n" + text
    return 2, text


PREFILTER_ACTION = re.compile(r"\b(?:commit|commit-tree|revert|merge)\b|\bpr\s+create\b")
SHELL_TOOLS = {"bash", "shell", "local_shell", "exec_command", "unified_exec", "write_stdin", "container.exec",
               "powershell"}


def shell_like(payload) -> bool:
    """Edit tools (apply_patch, Write) may mention git commit in file text; only shells run it."""
    name = str(payload.get("tool_name") or "").lower()
    return name in SHELL_TOOLS or name.startswith(("bash", "shell", "exec"))


def may_commit(payload) -> bool:
    """Cheap test run before the policy file is even loaded."""
    command = command_text(payload.get("tool_input"))
    if not command:
        raw = json.dumps(payload.get("tool_input"), ensure_ascii=False) if payload.get("tool_input") else ""
        return shell_like(payload) and bool(re.search(r"\bgit\b", raw) and re.search(r"\bcommit\b", raw))
    return bool(re.search(r"\b(?:git|gh)\b", command) and PREFILTER_ACTION.search(command))


def command_text(tool_input) -> str:
    """Claude sends {"command": str}; Codex may send a string or an argv list."""
    value = tool_input.get("command", tool_input.get("cmd")) if isinstance(tool_input, dict) else tool_input
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value) and value:
        if len(value) >= 3 and os.path.basename(value[0]) in SHELLS and value[1] in ("-c", "-lc", "-ec"):
            return value[2]
        return " ".join(shlex.quote(item) for item in value)
    return ""


# CODEX_HOME is deliberately absent: users export it in shell profiles, so it does not
# distinguish an agent from a person.
AGENT_MARKERS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "AI_AGENT")


def agent_environment() -> bool:
    return any(os.environ.get(name) for name in AGENT_MARKERS)


def run_git_hook(path: str, policy: dict) -> tuple:
    """commit-msg backstop. PreToolUse is the primary gate; this catches agent commits it
    could not see (scripts, editors) in tracked repos, and stays silent everywhere else so
    test fixtures and other repos run by agents are unaffected."""
    if policy.get("enforcement") == "off" or not agent_environment():
        return 0, ""
    facts = repo_facts(".")
    if not (facts and facts["origin"] and any(re.search(pattern, facts["origin"])
                                              for pattern in policy.get("backstop_repos", []))):
        return 0, ""
    try:
        message = normalize(Path(path).read_text(encoding="utf-8", errors="replace"), strip_comments=True)
    except OSError:
        return 1, "commit-policy: cannot read the commit message file"
    # git does not tell commit-msg hooks about --amend. A message equal to HEAD's is
    # most likely an amend --no-edit, so compare with the parent; the PreToolUse hook
    # and the publication range check still catch true consecutive duplicates.
    same_as_head = facts["head"] is not None and normalize(facts["head"]) == message
    problems = validate(message, policy=policy, previous=facts["parent"] if same_as_head else facts["head"],
                        is_merge=facts["merging"],
                        allow_autosquash=not facts["published"] and facts["branch"] not in ("main", "master", ""),
                        tickets_required=tickets_required_for(facts["origin"], policy))
    if not problems or find_waiver("message", digest(message), policy):
        return 0, ""
    text = block_text(problems, message, policy, subject=digest(message))
    if policy.get("enforcement") == "warn":
        return 0, "commit-policy (warn mode, not blocking):\n" + text
    return 1, text


# --------------------------------------------------------------------------- range and tickets

def range_commits(repo, base, head, exclude=()):
    """Commits reachable from head but not from base or any excluded tip (e.g. origin/main)."""
    tips = [f"^{item}" for item in exclude if item]
    raw = git(repo, "log", "--reverse", "--format=%H%x1f%P%x1f%ct%x1f%at%x1f%B%x1e", head, f"^{base}", *tips,
              "--", timeout=60)
    commits = []
    for record in raw.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, parents, when, authored, body = record.split("\x1f", 4)
        commits.append({"sha": sha, "parents": parents.split(), "time": int(when),
                        "author_time": int(authored), "message": body})
    return commits


def _commit_refs(message: str, policy: dict):
    _, _, sections, *_ = parse_message(normalize(message))
    text = "\n".join(sections.get(name, "") for name in ("Refs", "Authorized-by", "Reason"))
    return ticket_refs(text, policy)


def check_range(repo, base, head, policy, *, branch=None, pr=None, verify_tickets=False, adapters=None,
                exclude=()):
    """Validate every commit in base..head; optionally verify referenced tickets were updated.

    Freshness: a ticket comment naming the commit SHA (7+ hex) necessarily
    post-dates the commit. A comment naming only the branch or PR must be newer
    than the commit's committer time minus the configured skew.
    """
    if policy.get("enforcement") == "off":
        return {"base": base, "head": head, "exclude": list(exclude), "commits": [], "tickets": [],
                "waivers": [], "status": "PASS", "enforcement": "off"}
    commits = range_commits(repo, base, head, exclude)
    origin = git(repo, "remote", "get-url", "origin", check=False).strip() or None
    previous = git(repo, "log", "-1", "--format=%B", base, check=False) or None
    return evaluate(commits, policy, base=base, head=head, exclude=exclude, previous=previous,
                    tickets_required=tickets_required_for(origin, policy), branch=branch, pr=pr,
                    verify_tickets=verify_tickets, adapters=adapters)


def check_github(slug, base, head, policy, *, verify_tickets=True, adapters=None, timeout=30):
    """Check a branch range as GitHub sees it, wherever the commits were made (dev2, T2, Mac)."""
    if policy.get("enforcement") == "off":
        return {"base": base, "head": head, "commits": [], "tickets": [], "waivers": [], "status": "PASS",
                "enforcement": "off"}
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", slug or "") or not all(
            re.fullmatch(r"[\w./:-]+", item or "") and ".." not in item for item in (base, head)):
        raise ValueError("invalid repository, base or head name")
    items, total, page = [], None, 1
    while total is None or len(items) < total:
        result = subprocess.run(["gh", "api", f"repos/{slug}/compare/{base}...{head}?per_page=100&page={page}"],
                                capture_output=True, timeout=timeout)
        if result.returncode:
            raise OSError("GitHub compare failed (is the branch pushed? is gh authenticated?)")
        data = json.loads(result.stdout)
        batch = data.get("commits") or []
        total = int(data.get("total_commits", len(batch)))
        if total > 1000:
            raise OSError("range exceeds 1000 commits; check it locally with check-range")
        items.extend(batch)
        if not batch:
            break
        page += 1
    if len(items) < (total or 0):
        raise OSError("GitHub compare returned fewer commits than it reported")
    commits = []
    for item in items:
        def stamp(value):
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        commits.append({"sha": item["sha"], "parents": [p["sha"] for p in item.get("parents", [])],
                        "time": stamp(item["commit"]["committer"]["date"]),
                        "author_time": stamp(item["commit"]["author"]["date"]),
                        "message": item["commit"]["message"]})
    return evaluate(commits, policy, base=base, head=commits[-1]["sha"] if commits else head, exclude=(),
                    previous=None, tickets_required=tickets_required_for(f"https://github.com/{slug}", policy),
                    branch=head.split(":", 1)[-1], pr=None, verify_tickets=verify_tickets, adapters=adapters)


def evaluate(commits, policy, *, base, head, exclude, previous, tickets_required, branch, pr,
             verify_tickets, adapters):
    report = {"base": base, "head": head, "exclude": list(exclude), "commits": [], "tickets": [],
              "waivers": [], "status": "PASS"}
    required = tickets_required
    cutover = policy.get("enforce_after")
    cutover_ts = datetime.fromisoformat(cutover).timestamp() if cutover else None
    referenced = {}
    for commit in commits:
        merge = len(commit["parents"]) > 1
        problems = validate(commit["message"], policy=policy, previous=None if merge else previous,
                            is_merge=merge, tickets_required=required)
        # Author time survives rebase/cherry-pick/amend; committer time does not.
        legacy = bool(problems) and cutover_ts is not None and commit["author_time"] < cutover_ts
        waiver = find_waiver("commit", commit["sha"], policy) if problems and not legacy else None
        if waiver:
            report["waivers"].append({"kind": "commit", "subject": commit["sha"], "id": waiver["id"],
                                      "wal": waiver["wal"]})
        report["commits"].append({"sha": commit["sha"], "subject": normalize(commit["message"]).split("\n")[0],
                                  "problems": problems, "waived": bool(waiver), "legacy": legacy})
        if problems and not waiver and not legacy:
            report["status"] = "BLOCKED"
        if not merge:
            previous = commit["message"]
            for ref in _commit_refs(commit["message"], policy):
                referenced.setdefault(ref, []).append(commit)
    if not verify_tickets or not referenced:
        return report
    waiver = find_waiver("tickets", head, policy)
    if waiver:
        report["waivers"].append({"kind": "tickets", "subject": head, "id": waiver["id"], "wal": waiver["wal"]})
        return report
    adapters = {} if adapters is None else adapters
    for (system, project, number), commits_for in referenced.items():
        entry = {"ticket": f"{system}:{project}#{number}", "commits": [c["sha"] for c in commits_for]}
        report["tickets"].append(entry)
        try:
            from ticket_adapters import adapter_for
            config = policy["ticket_systems"][system]
            adapter = adapters.get(system) or adapter_for(config)
            adapters[system] = adapter
            ticket = adapter.lookup(project, number)
            if ticket is None:
                entry.update(status="MISSING", fix=f"{system} {project}#{number} does not exist; reference a real ticket")
                report["status"] = "BLOCKED"
                continue
            newest = max(c["time"] for c in commits_for)
            since = datetime.fromtimestamp(newest - int(config.get("clock_skew_seconds", 120)), timezone.utc)
            oldest = datetime.fromtimestamp(min(c["time"] for c in commits_for)
                                            - int(config.get("clock_skew_seconds", 120)), timezone.utc)
            pending = {c["sha"] for c in commits_for}
            for comment in adapter.comments_since(ticket, oldest):
                body = comment.body.lower()
                for c in commits_for:
                    if re.search(rf"(?<![0-9a-f]){c['sha'][:7]}[0-9a-f]*(?![0-9a-f])", body):
                        pending.discard(c["sha"])
                named = ((branch and re.search(rf"(?<![\w/.-]){re.escape(branch.lower())}(?![\w/.-])", body))
                         or (pr and re.search(rf"(?:pr\s*#|pull/){re.escape(str(pr))}\b", body)))
                if named and comment.created_at >= since:
                    pending.clear()
            if not pending:
                entry.update(status="UPDATED", title=ticket.title[:80])
            else:
                naming = "commit " + ", ".join(sha[:12] for sha in sorted(pending)) + (
                    f" (or branch {branch}, in a comment newer than {since.isoformat()})" if branch else "")
                entry.update(status="STALE", fix=adapter.update_instructions(ticket, naming))
                report["status"] = "BLOCKED"
        except Exception as error:  # includes TicketSystemUnavailable; fail closed
            entry.update(status="UNVERIFIED", error=str(error)[:200])
            if report["status"] == "PASS":
                report["status"] = "UNVERIFIED"
    return report


def format_report(report) -> str:
    lines = [f"Commit policy {report['status']} for {report['base'][:12]}..{report['head'][:12]}"]
    for item in report["commits"]:
        if item["problems"]:
            tag = "waived" if item["waived"] else ("legacy (before enforce_after)" if item.get("legacy") else "BLOCKED")
            lines.append(f"  {item['sha'][:12]} {tag}: {item['subject'][:72]}")
            lines += [f"      - {p}" for p in item["problems"]]
    for item in report["tickets"]:
        lines.append(f"  ticket {item['ticket']}: {item.get('status')}")
        if item.get("fix"):
            lines.append(f"      fix: {item['fix']}")
        if item.get("error"):
            lines.append(f"      could not verify: {item['error']}")
    for item in report.get("waivers", []):
        lines.append(f"  WAIVER used: {item['kind']} {item['subject'][:12]} (id {item['id']}, recorded in {item['wal']})")
    if report["status"] != "PASS":
        script = HERE / "commit_policy.py"
        bad_commits = any(item["problems"] and not item["waived"] and not item.get("legacy")
                          for item in report["commits"])
        stale = any(item.get("status") in ("STALE", "MISSING") for item in report["tickets"])
        if bad_commits:
            lines.append("  Fix commits: reword them (git rebase -i <base>, then git commit --amend -F <file>).")
        if stale:
            lines.append("  Fix tickets: comment on each STALE ticket naming the commit SHA or branch; reference "
                         "real tickets for MISSING ones.")
        if report["status"] == "UNVERIFIED":
            lines.append("  Tickets could not be verified (GoodQA unreachable, or the key file is missing or not "
                         "0600). Check access and retry; offline, record a tickets waiver for this head.")
        lines += [
                  f"  Check locally: python3 {script} check-range --repo <repo> --base <base> --head <head> --verify-tickets",
                  f"  Exceptional bypass (recorded in your WAL): python3 {script} waive --wal <WAL> "
                  "--kind commit|tickets --subject <sha> --reason '<why>'"]
    return "\n".join(lines)


STAGES = {
    "merged": "Merged (not yet deployed or live)",
    "delivered-local": "Delivered to the local checkout only (remote publication outstanding; not live)",
    "deployed": "Deployed / live",
}


def list_waivers(since: datetime):
    """Every ledger waiver since a time, with whether its WAL record still exists."""
    rows = []
    for line in _read_lines(LEDGER, 16_000_000):
        try:
            entry = json.loads(line)
            when = datetime.fromisoformat(entry["at"])
        except (ValueError, KeyError):
            continue
        if when < since:
            continue
        marker = f'"waiver_id":"{entry.get("id")}"'
        note = next((json.loads(item).get("note", "") for item in _read_lines(Path(entry.get("wal", "")))
                     if marker in item and '"event":"waiver"' in item), None)
        rows.append({**entry, "wal_record": note is not None,
                     "reason": note[len("COMMIT_POLICY_WAIVER: "):] if note else None})
    return rows


def notify(repo, base, head, policy, *, operation_seed, evidence, stage="merged", adapters=None, exclude=()):
    """Comment delivery evidence on every ticket referenced in the owner's range (idempotent).

    The comment leads with the stage so a reader can tell merged from live.
    """
    commits = range_commits(repo, base, head, exclude)
    refs = {}
    for commit in commits:
        for ref in _commit_refs(commit["message"], policy):
            refs.setdefault(ref, commit["sha"])
    results, adapters = [], adapters or {}
    from ticket_adapters import adapter_for
    for (system, project, number) in refs:
        label = f"{system}:{project}#{number}"
        try:
            config = policy["ticket_systems"][system]
            adapter = adapters.get(system) or adapter_for(config)
            adapters[system] = adapter
            ticket = adapter.lookup(project, number)
            if ticket is None:
                results.append({"ticket": label, "status": "MISSING"})
                continue
            op = str(uuid.uuid5(uuid.NAMESPACE_URL, f"agent-harness:{operation_seed}:{stage}:{label}:{head}"))
            body = f"**{STAGES[stage]}**: `{head}`\n\n{evidence}"
            adapter.comment(ticket, body, op)
            if stage != "deployed" and config.get("on_delivered_status"):
                adapter.set_status(ticket, config["on_delivered_status"])
            elif stage == "deployed" and config.get("on_deployed_status"):
                adapter.set_status(ticket, config["on_deployed_status"])
            results.append({"ticket": label, "status": "COMMENTED"})
        except Exception as error:
            results.append({"ticket": label, "status": "FAILED", "error": str(error)[:200]})
    return results


# --------------------------------------------------------------------------- git hook install

GIT_HOOK_NAME = "agent-harness-commit-policy"


def git_hook_command(script: Path) -> str:
    """A missing script must never break commits, so the command checks first."""
    quoted = shlex.quote(str(script))
    return f'f={quoted}; [ -f "$f" ] || exit 0; exec python3 "$f" git-hook'


def git_version(executable="git"):
    try:
        out = subprocess.run([executable, "--version"], capture_output=True, timeout=10).stdout.decode()
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"(\d+)\.(\d+)", out)
    return (int(match.group(1)), int(match.group(2))) if match else None


# --------------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hook")
    git_hook = sub.add_parser("git-hook")
    git_hook.add_argument("message_file")
    check = sub.add_parser("check-message")
    check.add_argument("--file")
    check.add_argument("--previous-file")
    rng = sub.add_parser("check-range")
    rng.add_argument("--repo", required=True)
    rng.add_argument("--base", required=True)
    rng.add_argument("--head", required=True)
    rng.add_argument("--branch")
    rng.add_argument("--pr")
    rng.add_argument("--verify-tickets", action="store_true")
    rng.add_argument("--json", action="store_true")
    gh_check = sub.add_parser("check-github", help="check a pushed branch range through the GitHub API")
    gh_check.add_argument("--repo", required=True, help="owner/name")
    gh_check.add_argument("--base", required=True)
    gh_check.add_argument("--head", required=True)
    gh_check.add_argument("--no-tickets", action="store_true")
    gh_check.add_argument("--json", action="store_true")
    waive = sub.add_parser("waive")
    waive.add_argument("--wal", required=True, type=Path)
    waive.add_argument("--kind", required=True, choices=("message", "commit", "tickets"))
    waive.add_argument("--subject", required=True)
    waive.add_argument("--reason", required=True)
    note = sub.add_parser("notify")
    note.add_argument("--repo", required=True)
    note.add_argument("--base", required=True)
    note.add_argument("--head", required=True)
    note.add_argument("--seed", required=True, help="stable id (e.g. delivery generation) for idempotency")
    note.add_argument("--evidence", required=True, help="comment text: checks run, PR, deploy evidence")
    note.add_argument("--stage", choices=sorted(STAGES), default="merged")
    note.add_argument("--exclude", action="append", default=[], help="tip to exclude (e.g. origin/main)")
    audit = sub.add_parser("report", help="list waivers recorded since a date (audit)")
    audit.add_argument("--since", required=True, help="ISO date or datetime, e.g. 2026-11-04")
    sub.add_parser("uninstall-git-hook", help="remove the global git commit-msg backstop keys")
    args = parser.parse_args(argv)
    if args.command == "uninstall-git-hook":
        result = subprocess.run(["git", "config", "--global", "--remove-section", f"hook.{GIT_HOOK_NAME}"],
                                capture_output=True)
        print(json.dumps({"status": "REMOVED" if result.returncode == 0 else "ABSENT"}))
        return 0
    payload = None
    if args.command == "hook":
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            print("commit-policy: hook payload is not JSON", file=sys.stderr)
            return 2
        payload = payload if isinstance(payload, dict) else {}
        if not may_commit(payload):
            return 0  # every non-commit tool call stays independent of the policy file
    try:
        policy = load_policy()
    except (OSError, ValueError) as error:
        print(f"commit-policy: cannot load {POLICY_FILE}: {error}; refusing to guess. Fix the JSON, or set "
              '"enforcement": "off" there to stop enforcement.', file=sys.stderr)
        return 2
    if args.command == "hook":
        code, text = run_hook(payload, policy)
        if text:
            print(text, file=sys.stderr)
        return code
    if args.command == "git-hook":
        code, text = run_git_hook(args.message_file, policy)
        if text:
            print(text, file=sys.stderr)
        return code
    if args.command == "check-message":
        message = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
        previous = Path(args.previous_file).read_text(encoding="utf-8") if args.previous_file else None
        problems = validate(message, policy=policy, previous=previous)
        print(json.dumps({"status": "BLOCKED" if problems else "PASS", "problems": problems,
                          "digest": digest(message)}, indent=1))
        return 2 if problems else 0
    if args.command == "check-range":
        sys.path.insert(0, str(HERE))
        report = check_range(args.repo, args.base, args.head, policy, branch=args.branch, pr=args.pr,
                             verify_tickets=args.verify_tickets)
        print(json.dumps(report, indent=1) if args.json else format_report(report))
        return {"PASS": 0, "BLOCKED": 2, "UNVERIFIED": 4}[report["status"]]
    if args.command == "check-github":
        sys.path.insert(0, str(HERE))
        try:
            report = check_github(args.repo, args.base, args.head, policy, verify_tickets=not args.no_tickets)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            print(f"commit-policy: {error}", file=sys.stderr)
            return 4
        print(json.dumps(report, indent=1) if args.json else format_report(report))
        return {"PASS": 0, "BLOCKED": 2, "UNVERIFIED": 4}[report["status"]]
    if args.command == "waive":
        if not re.fullmatch(r"[0-9a-f]{20}|[0-9a-f]{40}|[0-9a-f]{64}", args.subject):
            parser.error("--subject must be the message digest or a full commit SHA printed by the checker")
        sys.path.insert(0, str(HERE))
        try:
            waiver_id = record_waiver(args.wal, args.kind, args.subject, args.reason, policy)
        except ValueError as error:
            parser.error(str(error))
        print(json.dumps({"status": "WAIVED", "id": waiver_id, "kind": args.kind, "subject": args.subject}))
        return 0
    if args.command == "notify":
        sys.path.insert(0, str(HERE))
        results = notify(args.repo, args.base, args.head, policy, operation_seed=args.seed, evidence=args.evidence,
                         stage=args.stage, exclude=args.exclude)
        print(json.dumps({"tickets": results}, indent=1))
        return 0 if all(item["status"] == "COMMENTED" for item in results) else 5
    if args.command == "report":
        since = datetime.fromisoformat(args.since)
        since = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        rows = list_waivers(since)
        print(json.dumps({"since": since.isoformat(), "waivers": rows, "count": len(rows),
                          "missing_wal_record": sum(1 for row in rows if not row["wal_record"])}, indent=1))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
