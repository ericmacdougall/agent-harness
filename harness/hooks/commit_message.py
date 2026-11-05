#!/usr/bin/env python3
"""Build and validate policy-valid commit and PR messages from structured fields (GoodQA #14624).

Commit-policy refusals were the largest harness-caused tool failure (about 409 of 1,766 errors in one session: the
subject over 72 characters, a Testing line without an exact command or a result, a missing body). This module builds the
message from fields, applies only SAFE normalizations, and ALWAYS runs commit_policy.validate on the result: it never
returns a message the policy rejects. What it cannot fix comes back as field-level errors {field, problem, fix}
before git is touched. Stdlib plus sibling hooks; `ah commit` / `ah pr` are thin wrappers over build_message / build_pr.

  commit_message.py build --type T --scope S --summary .. --why .. --what .. --testing-command C --testing-result R
                          --ticket 123 [--reason .. --authorized-by ..] [--commit [--repo DIR]]
  commit_message.py check --file F          validate an existing message file (at most 16 KiB)
  commit_message.py pr --title .. --why .. --what .. --testing-command C --testing-result R --ticket 123

OUTPUT CONTRACT. Every path prints exactly one JSON object and exits 0 (ok), 2 (refused, or the commit outcome is not a
clean success) or 4 (internal). Under --commit every result carries "committed": true, false or "unknown", including
SIGHUP, SIGINT, SIGQUIT and SIGTERM, and the message file never survives. Exit 2 with "committed": true means the commit
landed but its text is not policy-valid (a hook rewrote it).

HOW THE OUTCOME IS JUDGED. By what git recorded, never by "HEAD moved" and never by the exit code alone. Before launch
the current branch ref and its tip are captured. Afterwards the first-parent chain from that ref is walked back to the
captured tip: its direct child is the only commit this run can have made. Same message: ours, committed true (whatever
git's exit code, for example a hook that hung after the commit). Different message: committed true only if git exited 0
and it is the tip (a hook rewrote the text), otherwise unknown. Tip unchanged: false if git failed, unknown if git
exited 0 (a hook moved things). No path from the tip to the captured commit, or an unreadable repository: unknown.

WHAT COUNTS AS TESTING EVIDENCE. There are no prose word lists. The only accepted forms are testing_command plus
testing_result, 'not run: <reason>', or an already-backticked `cmd`: result (several allowed). Unwrapped text is refused,
because splitting it means guessing where a command ends (`curl -H Accept: application/json http://x: 200 ok`). A
command must have a command's shape, see _command_problem: every shell segment starts with an optional NAME=value
prefix and a KNOWN_TOOLS name or a path; an interpreter must be given a flag or a script. Each result must itself state a
result (commit_policy.RESULT_HINT), so a word inside the command cannot satisfy that check.

Limits, stated plainly:
- A command's shape is checked, not its truth: `make tests pass` parses exactly as `make all` does, and `npm is happy` as
  `npm test` does. Nothing short of running it can tell them apart. The structured fields make this a deliberate claim.
- A tool not in KNOWN_TOOLS is refused until written as a path (./x, bin/x, /usr/bin/x), or added to the list.
- commit_policy.PR_REF is quadratic on a long dotted Refs value. --check is capped at 16 KiB and fields at 4 KiB, which
  keeps it short; the regex itself belongs to the policy.
- commit_policy.repo_facts still reads messages with `git log`, which log.showSignature and i18n.logOutputEncoding
  change, so the commit hook's duplicate check inherits that. This module reads commits with `git cat-file` instead.
- The imperative mapping can change a meaning ('made' to 'make'); it always emits a warning.
- SIGKILL of this process, or a hook group that ignores SIGTERM and is then killed, can leave .git/index.lock behind.
  Git hooks run in their own session, so one that needs a terminal fails rather than hangs. A hook's background child
  that outlives git is not waited for, and loses its output pipe.
- The commit-policy hook cannot see the message inside `commit_message.py --commit`, so --commit applies the hook's own
  rules itself (ticket rule from the repo's origin, previous-message duplicate check). NOT YET WIRED: the commit hook's
  block text does not call ready_message, and `ah commit` / `ah pr` (the ah owner) wrap this module after it merges.
- With a closed stdout the JSON has nowhere to go; the exit code is still the result. A signal that arrives before the
  interpreter reaches main() ends the process the usual way; nothing has happened by then. POSIX only.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

IMPERATIVE = {
    "added": "add", "adds": "add", "adding": "add", "fixed": "fix", "fixes": "fix", "fixing": "fix",
    "updated": "update", "updates": "update", "updating": "update", "changed": "change", "changes": "change",
    "changing": "change", "removed": "remove", "removes": "remove", "removing": "remove", "made": "make",
    "makes": "make", "making": "make", "implemented": "implement", "implements": "implement",
    "implementing": "implement", "refactored": "refactor", "refactors": "refactor", "reverted": "revert",
    "reverts": "revert", "improved": "improve", "improves": "improve", "moved": "move", "moves": "move",
    "renamed": "rename", "renames": "rename", "created": "create", "creates": "create"}
FIELD_FIX = {
    "subject": "write '<type>(<scope>): <imperative summary>' of at most 72 characters with a lowercase scope",
    "Why": "give the problem or motivation in a real sentence (12+ characters, not a restatement of the diff)",
    "What": "describe the key changes and their behaviour in a real sentence (12+ characters)",
    "Testing": "give the exact command in `backticks` and its result (for example `python3 -m unittest`: 14 tests OK), "
               "or 'not run: <concrete reason>'",
    "Refs": "name a ticket ('GoodQA #1234'); only chore and docs may use 'none (<reason of 8+ characters>)'",
    "Risk": "omit Risk when there is none, otherwise give a real sentence",
    "body": "put a blank line after the subject, then Why:, What:, Testing:, Refs: sections in that order",
    "trailers": "pass a list of 'Name-By: value' trailer lines (Co-Authored-By, Signed-off-by)",
    "message": "describe this change specifically (the message equals the previous commit)",
    "revert": "use type revert with Reason: and Authorized-by: citing the ticket (--reason, --authorized-by)",
    "git": "fix the cause named in the problem (staged changes, git identity, a commit hook) and run again",
    "input": "pass plain text without control or invisible characters",
}
FIELD_OF = {"summary": "subject", "scope": "subject", "type": "subject", "why": "Why", "what": "What",
            "testing": "Testing", "testing_command": "Testing", "testing_result": "Testing", "ticket": "Refs",
            "refs": "Refs", "risk": "Risk", "reason": "revert", "authorized_by": "revert"}
MAX_CHECK_BYTES = 16 * 1024  # the largest real commit body in the refusal fixture is 3,434 characters
MAX_FIELD = 4096
OUTPUT_TAIL_BYTES = 64 * 1024  # git and hook output kept in memory; the rest is read and dropped
READ_BYTES = 1024 * 1024  # a commit object bigger than this is treated as unreadable
MAX_WALK = 16  # first-parent hops looked at when later commits landed on top of ours
SECRETISH = re.compile(r"(?i)sk-|ghp_|xox[a-z]-|secret|token|passw|api[_-]?key|credential|bearer")
# Letters and marks that render as nothing; control and format characters are refused by category.
FILLER_CHARS = set("\u3164\u115f\u1160\uffa0\u2800\u034f\u17b4\u17b5")
STACKED_SELECTORS = re.compile("[\ufe00-\ufe0f]{2,}")  # one variation selector is a normal emoji
TRAILER = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*: \S.*$")
TEXT_FIELDS = ("summary", "why", "what", "testing", "testing_command", "testing_result", "risk", "refs", "reason",
               "authorized_by", "title")

# PLACEHOLDERS, the documented list. Refused: (1) a phrase below, inside <>, [] or {}; (2) a whole value, or the reason of
# 'not run:' / 'none (...)', that is one of these phrases with an optional 'here' or 'goes here'; (3) <...> with a space
# or comma inside, not glued to an identifier (Map<a, b>) and holding no '/', '!', 'name=' or quote (markup, paths); '< x >' only
# where an operand cannot precede it (x < 3 and y > 2 is a comparison); (4) a value that is only <...> tokens; (5) a value
# wholly wrapped in [] or {} with a space inside; (6) a value starting with TODO, FIXME, TBD or XXX (upper case).
# NOT refused: Promise<void>, <table>, <b>3 passed</b>, a@b.c in a trailer. Commands are checked with quotes masked,
# so grep '<a b>' passes.
TEMPLATE_PHRASES = frozenset((
    "reason", "why", "what", "who", "n", "number", "result", "results", "command", "scope", "type", "ticket",
    "ticket number", "summary", "imperative summary", "problem", "motivation", "problem or motivation",
    "the problem or motivation", "key changes", "the key changes", "exact command", "the exact command", "risk", "trailers",
    "description", "text", "fill in", "fill this in", "write this"))
ANGLE = re.compile(r"(?<![\w>])<([^<>]*)>")
BRACKETED = re.compile(r"\[([^\[\]]*)\]|\{([^{}]*)\}")
ONLY_ANGLES = re.compile(r"(?:\s*<[^<>]*>){2,}\s*")
UNFINISHED = re.compile(r"(?:TODO|FIXME|TBD|XXX)\b")
QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
REASON_OF = re.compile(r"(?is)^(?:not run:\s*|none\s*\(\s*)(.*?)\s*\)?\s*\.?$")

# COMMANDS: what may start a shell segment. It extends the tools in commit_policy.COMMAND_HINT (a test keeps them in step).
KNOWN_TOOLS = frozenset("""
    python python3 pytest npm pnpm yarn npx node go cargo make git bash sh uv tox ruby bundle rake mvn gradle dotnet swift
    xcodebuild deno bun vitest jest playwright curl ruff mypy eslint tsc terraform kubectl docker
    ah ansible ant aws awk biome black cabal cat cd clang cmake composer conda coverage ctest cypress dart diff dig
    elixir esbuild flake8 flutter gcc gcloud gh golangci-lint gofmt gq grep gunicorn helm hatch http isort java javac jq
    julia k6 lua meson mix mocha netwatch next ninja nox nc openssl perl php phpunit pip pip3 pipenv pipx
    pnpx poetry pre-commit prettier psql pylint rails rebar3 rg rollup rspec rsync rustc rustfmt sbt scp sed shellcheck
    sqlite3 ssh stack staticcheck tail tar ts-node tsx uvx vite webpack wget wrangler zsh dash head wc xcrun
    actionlint bandit docker-compose find gitleaks hadolint kustomize ls pip-audit podman semgrep tofu trivy yamllint
    """.split())
INTERPRETERS = re.compile(r"(?:python\d*(?:\.\d+)?|node|ruby|perl|php|lua|bash|sh|zsh|dash)")
VERSIONED_PYTHON = re.compile(r"python\d+(?:\.\d+)?")
WRAPPERS = frozenset("sudo env time timeout gtimeout nice ionice nohup command exec xargs stdbuf caffeinate".split())
ENV_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)
SHELL_SEPARATORS = frozenset(("&&", "||", ";", ";;", "|", "|&", "&", "(", ")"))
SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
EXTRA_SECRETS = re.compile(r"\bglpat-[A-Za-z0-9_-]{8,}|\b(?:gh[pousr]|sk|xox[a-z])[-_][A-Za-z0-9_-]{6,}")


def _policy_mod():
    import commit_policy
    return commit_policy


def field_errors(problems: list) -> list:
    """Map commit_policy problem lines ('Field: text') to {field, problem, fix}."""
    out = []
    for item in problems:
        head = item.partition(":")[0].strip()
        field = head if head in FIELD_FIX else "message"
        out.append({"field": field, "problem": item, "fix": FIELD_FIX[field]})
    return out


def _err(field: str, problem: str, fix: str | None = None) -> dict:
    return {"field": field, "problem": f"{field}: {problem}", "fix": fix or FIELD_FIX.get(field, FIELD_FIX["message"])}


def _one_line(value) -> str:
    return re.sub(r"\s+", " ", str(value if value is not None else "")).strip()


def _is_filler_value(text: str) -> bool:
    words = " ".join(text.split()).casefold().rstrip(".")
    words = re.sub(r"\s+(?:goes\s+)?here$", "", words)
    return words in TEMPLATE_PHRASES


def _placeholder(text: str):
    """The unfilled template text in this value, or None; the rules are documented at TEMPLATE_PHRASES."""
    for match in ANGLE.finditer(text):
        inner = " ".join(match.group(1).split())
        if inner.casefold() in TEMPLATE_PHRASES:
            return match.group(0)
        if not inner or not re.search(r"[\s,]", inner) or re.search(r"[/!\"']|\w=", inner):
            continue
        if not match.group(1)[0].isspace() or text[:match.start()].rstrip()[-1:] in ("", "(", ":", ",", "-"):
            return match.group(0)
    for match in BRACKETED.finditer(text):
        if " ".join((match.group(1) or match.group(2) or "").split()).casefold() in TEMPLATE_PHRASES:
            return match.group(0)
    whole = text.strip()
    reason = REASON_OF.match(whole)
    value = reason.group(1) if reason else whole
    if ONLY_ANGLES.fullmatch(whole) or _is_filler_value(value) or UNFINISHED.match(value):
        return value[:40]
    if len(whole) > 2 and whole[0] + whole[-1] in ("[]", "{}") and " " in whole:
        return whole[:40]
    return None


def _bad_characters(raw: str) -> bool:
    flat = raw.replace("\n", " ").replace("\t", " ")
    return (any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co") or c in FILLER_CHARS for c in flat)
            or bool(STACKED_SELECTORS.search(flat)))


def _scan(fields: dict) -> list:
    """Refuse non-text values, control, format and invisible filler characters, unfilled placeholders, over-long and
    (almost) contentless values in any text field."""
    errors = []
    for key, value in fields.items():
        if key == "trailers" or value is None:
            continue
        field = FIELD_OF.get(key, "input")
        if not isinstance(value, str):
            errors.append(_err(field, f"{key} must be text, not {type(value).__name__}", FIELD_FIX["input"]))
            continue
        text = _one_line(value)
        probe = QUOTED.sub("''", text) if key in ("testing", "testing_command") else text
        found = _placeholder(probe) if key in TEXT_FIELDS else None
        if _bad_characters(value):
            errors.append(_err(field, f"{key} contains control or invisible characters", FIELD_FIX["input"]))
        elif len(text) > MAX_FIELD:
            errors.append(_err(field, f"{key} is longer than {MAX_FIELD} characters", "shorten it; the details belong in the diff or a ticket"))
        elif found:
            errors.append(_err(field, f"{key} still contains an unfilled placeholder {found!r}",
                               "replace the template text with the real content"))
        elif key in ("why", "what") and text and sum(c.isalnum() for c in text) < 8:
            errors.append(_err(field, f"{key} has no real words", FIELD_FIX[field]))
    kind, scope = _one_line(fields.get("type")), _one_line(fields.get("scope"))
    if "type" in fields and kind and not re.fullmatch(r"[A-Za-z]+", kind):
        errors.append(_err("subject", "type must be letters only"))
    if scope and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,39}", scope):
        errors.append(_err("subject", "scope must be a short lowercase word such as 'deliver' (no spaces or brackets)"))
    return errors


def _ticket_ref(ticket, errors: list, project="GoodQA") -> str:
    t = _one_line(ticket)
    if not t:
        return ""
    if re.fullmatch(r"#?\d{1,9}", t, re.ASCII):
        return f"{project} #{t.lstrip('#')}"
    if re.fullmatch(r"(?:GoodQA\s+)?[A-Za-z0-9_-]*#\d{1,9}", t, re.ASCII) or re.fullmatch(r"GoodQA\s+[A-Za-z0-9_-]+#\d{1,9}", t, re.ASCII):
        return t if t.startswith("GoodQA") else f"GoodQA {t}"
    errors.append(_err("Refs", f"ticket {t[:40]!r} is not a ticket number", "pass a number (14552), 'GoodQA #14552' or "
                       "'GoodQA project#14552'; use --refs for free text such as a PR"))
    return ""


def _imperative(summary: str, warnings: list) -> str:
    words = summary.split()
    if words and words[0].lower() in IMPERATIVE:
        new = IMPERATIVE[words[0].lower()]
        warnings.append(f"subject: '{words[0]}' changed to the imperative '{new}'")
        words[0] = new
    return " ".join(words)


def _is_executable(word: str) -> bool:
    if "/" in word:  # ./x, bin/x, /usr/bin/x; a trailing slash is a directory and 'n/a' is not a program
        return bool(re.fullmatch(r"[\w.~+@/-]+", word)) and not word.endswith("/") and word.casefold() != "n/a"
    return word in KNOWN_TOOLS or word in WRAPPERS or bool(VERSIONED_PYTHON.fullmatch(word))


def _segment_is_command(words: list) -> bool:
    while words and ENV_PREFIX.fullmatch(words[0]):
        words = words[1:]
    if not words or not _is_executable(words[0]):
        return False
    if words[0] in WRAPPERS:  # sudo -u bob make test: whatever comes next must itself be a command
        rest = words[1:]
        return any(_is_executable(w) and _segment_is_command(rest[i:]) for i, w in enumerate(rest))
    if INTERPRETERS.fullmatch(words[0]):
        return len(words) > 1 and (words[1].startswith("-") or "/" in words[1] or "." in words[1])
    return True


def _command_problem(text: str):
    """Why this is not a command, or None. The principled rule: split on shell operators; every segment is an optional
    NAME=value prefix, then a known tool or a path, then any arguments; an interpreter also needs a flag or a script."""
    if not text.strip():
        return "the command is empty"
    if "`" in text:
        return "a command cannot contain a backtick"
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return "its quotes are not balanced"
    segments, current = [], []
    for token in tokens:
        if token in SHELL_SEPARATORS:
            segments.append(current)
            current = []
        else:
            current.append(token)
    segments = [s for s in [*segments, current] if s]
    if not segments or not all(_segment_is_command(s) for s in segments):
        return "it does not start with a known tool or a path (./x, bin/x), followed by its arguments"
    return None


def _result_problem(text: str):
    if not text:
        return "give the result of the command"
    if not _policy_mod().RESULT_HINT.search(text):
        return "state the result (for example '14 passed', 'ok', 'exit 0')"
    return None


USE_TWO_FIELDS = ("pass --testing-command with the exact command and --testing-result with what happened, or "
                  "'not run: <concrete reason>'; a tool that is not known can be written as a path (./x, bin/x)")


def _backticked(text: str, errors: list) -> str:
    """Only `cmd`: result, repeated if needed, each piece checked. Anything else would mean guessing."""
    parts = text.split("`")
    if len(parts) < 3 or len(parts) % 2 == 0 or parts[0].strip():
        errors.append(_err("Testing", f"{text[:40]!r} is not in a form that can be read without guessing", USE_TWO_FIELDS))
        return ""
    for command, result in zip(parts[1::2], parts[2::2]):
        clean = re.sub(r"^\s*(?:->|=>|\u2192|[:=-])?\s*", "", result).rstrip(" ;,.")
        problem = _command_problem(command) or _result_problem(clean)
        if problem:
            errors.append(_err("Testing", f"{command[:40]!r}: {problem}", USE_TWO_FIELDS))
            return ""
    return text


def _testing(fields: dict, warnings: list, errors: list) -> str:
    cmd, res = _one_line(fields.get("testing_command")), _one_line(fields.get("testing_result"))
    if cmd or res:
        if not (cmd and res):
            errors.append(_err("Testing", "give both testing_command and testing_result (or 'not run: <reason>')"))
            return ""
        bare = cmd.strip("`")
        problem = _command_problem(bare)
        if problem:
            errors.append(_err("Testing", f"{cmd[:40]!r}: {problem}", USE_TWO_FIELDS))
            return ""
        problem = _result_problem(res)
        if problem:
            errors.append(_err("Testing", problem))
            return ""
        if _one_line(fields.get("testing")):
            warnings.append("Testing: testing was ignored because testing_command and testing_result are given")
        return f"`{bare}`: {res}"
    text = _one_line(fields.get("testing"))
    if not text or text.lower().startswith("not run:"):
        return text
    return _backticked(text, errors)


def _refs(fields: dict, errors: list, warnings: list) -> str:
    refs, ticket = _one_line(fields.get("refs")), fields.get("ticket")
    if refs and _one_line(ticket):
        warnings.append("Refs: refs overrides ticket")
    return refs or _ticket_ref(ticket, errors)


def _trailers(value, errors: list) -> list:
    if value in (None, [], ()):
        return []
    cp = _policy_mod()
    if not isinstance(value, (list, tuple)) or any(not isinstance(t, str) for t in value):
        errors.append(_err("trailers", "trailers must be a list of strings"))
        return []
    raw = [str(t) for t in value]
    if any("\n" in t or "\r" in t for t in raw):
        errors.append(_err("trailers", "each trailer must be one line"))
        return []
    if any(_bad_characters(t) for t in raw):
        errors.append(_err("trailers", "a trailer contains control or invisible characters"))
        return []
    out = [_one_line(t) for t in raw if _one_line(t)]
    bad = [t for t in out if not (TRAILER.match(t) and cp.TRAILER_LINE.match(t)) or _placeholder(t)]
    if bad:
        errors.append(_err("trailers", f"{len(bad)} trailer(s) are not 'Name-By: value' lines"))
        return []
    return out


def build_message(fields: dict, policy: dict | None = None, *, tickets_required: bool = True,
                  previous: str | None = None) -> dict:
    """{'ok': bool, 'message': str | None, 'errors': [...], 'warnings': [...]}; message is set only if it validates."""
    cp = _policy_mod()
    policy = policy or cp.load_policy()
    warnings: list = []
    errors = _scan(fields)
    kind = _one_line(fields.get("type")).lower()
    scope = _one_line(fields.get("scope")).lower()
    summary = _imperative(_one_line(fields.get("summary")).rstrip("."), warnings)
    subject = f"{kind}({scope}): {summary}" if scope else f"{kind}: {summary}"
    limit = int(policy["subject"]["max_length"])
    lines = [subject, "", f"Why: {_one_line(fields.get('why'))}", f"What: {_one_line(fields.get('what'))}",
             f"Testing: {_testing(fields, warnings, errors)}", f"Refs: {_refs(fields, errors, warnings)}"]
    if _one_line(fields.get("risk")):
        lines.append(f"Risk: {_one_line(fields.get('risk'))}")
    for name, label in (("reason", "Reason"), ("authorized_by", "Authorized-by")):
        if _one_line(fields.get(name)):
            lines.append(f"{label}: {_one_line(fields.get(name))}")
    trailers = _trailers(fields.get("trailers"), errors)
    if errors:
        return {"ok": False, "message": None, "errors": errors, "warnings": warnings}
    if trailers:
        lines += [""] + trailers
    message = "\n".join(lines) + "\n"
    problems = cp.validate(message, policy=policy, previous=previous, tickets_required=tickets_required)
    if problems:
        errs = field_errors(problems)
        for e in errs:
            if e["problem"].startswith("subject:") and "chars, limit" in e["problem"]:
                over = len(subject) - limit
                e["fix"] = f"shorten the summary by at least {over} character(s); the subject is {len(subject)} of {limit}"
        return {"ok": False, "message": None, "errors": errs, "warnings": warnings}
    return {"ok": True, "message": message, "errors": [], "warnings": warnings}


def build_pr(fields: dict, policy: dict | None = None, *, tickets_required: bool = True) -> dict:
    """A PR title (<=64 characters, so the squash subject '<title> (#N)' fits 72) and a Why/What/Testing/Refs body."""
    cp = _policy_mod()
    policy = policy or cp.load_policy()
    warnings: list = []
    errors = _scan(fields)
    title = _one_line(fields.get("title")).rstrip(".")
    lines = [f"Why: {_one_line(fields.get('why'))}", f"What: {_one_line(fields.get('what'))}",
             f"Testing: {_testing(fields, warnings, errors)}", f"Refs: {_refs(fields, errors, warnings)}"]
    if _one_line(fields.get("risk")):
        lines.append(f"Risk: {_one_line(fields.get('risk'))}")
    for name, label in (("reason", "Reason"), ("authorized_by", "Authorized-by")):
        if _one_line(fields.get(name)):
            lines.append(f"{label}: {_one_line(fields.get(name))}")
    if fields.get("trailers"):
        warnings.append("trailers are not part of a PR body and were ignored")
    body = "\n".join(lines) + "\n"
    if errors:
        return {"ok": False, "title": None, "body": None, "errors": errors, "warnings": warnings}
    problems = list(cp.validate_pr(title, body, policy, tickets_required=tickets_required))
    if problems:
        errs = []
        for item in problems:
            head = item.replace("PR ", "", 1).partition(":")[0].strip()
            field = head if head in FIELD_FIX else ("subject" if "title" in item.lower() or "subject" in item.lower() else "body")
            fix = "shorten the PR title to at most 64 characters" if "chars" in item and field == "subject" else FIELD_FIX.get(field)
            errs.append({"field": field, "problem": item, "fix": fix})
        return {"ok": False, "title": None, "body": None, "errors": errs, "warnings": warnings}
    return {"ok": True, "title": title, "body": body, "errors": [], "warnings": warnings}


def ready_message(problems: list, message: str, task_fields: dict | None = None, policy: dict | None = None) -> str:
    """A ready-to-fill `commit_message.py build` command for the hook's block output. STRUCTURE ONLY: the type is the
    refused subject's type only when it is one of the policy's types; the scope and ticket come from the task fields
    alone, strictly validated; no part of the refused text, no secret and no session text is ever copied."""
    cp = _policy_mod()
    policy = policy or cp.load_policy()
    task = task_fields if isinstance(task_fields, dict) else {}
    m = cp.SUBJECT.match(message.split("\n", 1)[0]) if isinstance(message, str) else None
    kind = m.group("type").lower() if m and m.group("type").lower() in policy["subject"]["types"] else "fix"
    scope = task.get("scope") if isinstance(task.get("scope"), str) else ""
    scope = scope.lower()
    ok_scope = re.fullmatch(policy["subject"]["scope_pattern"], scope) and not scope.startswith("-") and not SECRETISH.search(scope)
    scope = scope if ok_scope else "<scope>"
    ticket = task.get("ticket") if isinstance(task.get("ticket"), str) else ""
    ticket = ticket.strip()
    good = re.fullmatch(r"(?:GoodQA\s+(?:[a-z][a-z0-9_-]{0,30})?#\d{1,9}|\d{1,9})", ticket, re.ASCII) and not SECRETISH.search(ticket)
    ticket = ticket if good else "<ticket number>"
    q = shlex.quote
    return (f"python3 {q(str(HERE / 'commit_message.py'))} build --type {q(kind)} --scope {q(scope)} "
            f"--summary '<imperative summary>' --why '<problem or motivation>' --what '<key changes>' "
            f"--testing-command '<exact command>' --testing-result '<result>' --ticket {q(ticket)} --commit")


def _temp_roots() -> set:
    """The system temp directories. Tests replace this function; there is deliberately no environment switch."""
    roots = {tempfile.gettempdir(), "/tmp", "/var/tmp", "/var/folders"}
    try:
        user_tmp = subprocess.run(["getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True, timeout=5).stdout.strip()
        if user_tmp:
            roots.add(user_tmp)
    except (OSError, subprocess.SubprocessError):
        pass
    return roots


def _in_temp(path: Path) -> bool:
    """Is this path inside a temp dir? Judged by file identity on the nearest existing ancestor, so symlinks (/tmp to
    /private/tmp) and the case aliases of a case-insensitive volume (/PRIVATE/TMP) cannot get around it."""
    existing = path
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    roots = [r for r in _temp_roots() if os.path.exists(r)]
    return any(os.path.samefile(ancestor, root) for ancestor in (existing, *existing.parents) for root in roots)


def work_dir() -> Path:
    """Durable, private directory for message files: absolute, outside the system temp dirs, never a symlink, mode 0700
    and ours. An existing directory that others can access is refused, not chmod-ed."""
    raw = os.environ.get("HARNESS_WORK_DIR") or str(Path.home() / ".agent-harness" / "work" / "commit-messages")
    base = Path(raw)
    if not base.is_absolute():
        raise ValueError("HARNESS_WORK_DIR must be an absolute path")
    if base.is_symlink():
        raise ValueError("the work directory is a symlink")
    if _in_temp(base.resolve(strict=False)):
        raise ValueError("the message file belongs in the durable work directory, not the system temp dir")
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(f"cannot create the work directory {base}: {exc.strerror}") from None
    st = base.lstat()
    if not base.is_dir() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError("the work directory must be a directory owned by you with mode 0700")
    return base


def _message_path(work: Path) -> Path:
    return work / f"msg-{os.getpid()}-{os.urandom(4).hex()}.txt"


def _write_message(path: Path, message: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(message)
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def commit_message_file(message: str) -> Path:
    path = _message_path(work_dir())
    _write_message(path, message)
    return path


def _redact(text: str) -> str:
    """Every string that can hold hook output goes through the harness's two redactors, plus the few shapes they lack."""
    from integrate_local import redact_output
    from redact import redact
    return EXTRA_SECRETS.sub("[redacted]", redact(redact_output(text)))


def _scrub(value, key: str = ""):
    if key in ("message", "title", "body"):  # the text this run built; a hook's rewritten text is redacted when read back
        return value
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v, k) for k, v in value.items()}
    return value


def _tail(output: str, lines: int = 8, chars: int = 700) -> str:
    return "\n".join(output.strip().splitlines()[-lines:])[-chars:]


class _Interrupted(BaseException):
    """A signal arrived. BaseException, so that no `except Exception` can swallow it."""


class _Guard:
    """One handler for every signal that would otherwise end the process with no JSON. The first signal while armed
    raises _Interrupted, once; every other signal is only recorded, so cleanup and the final JSON cannot be cut short."""

    def __init__(self):
        self.signum = None
        self.armed = True
        self.survivor = False  # a child that SIGKILL did not end within the bound
        self._old = {}

    def _on_signal(self, signum, _frame):
        if self.signum is None:
            self.signum = signum
        if self.armed:
            self.armed = False
            raise _Interrupted()

    def install(self):
        with contextlib.suppress(ValueError):  # not the main thread: signals are not ours to handle
            for signum in SIGNALS:
                self._old[signum] = signal.signal(signum, self._on_signal)

    def restore(self):
        for signum, handler in self._old.items():
            signal.signal(signum, handler)
        self._old.clear()

    @contextlib.contextmanager
    def held(self):
        """Delay a signal across a step that must not be split, such as spawning a child and recording it."""
        was = self.armed
        self.armed = False
        try:
            yield
        finally:
            self.armed = was
            if was and self.signum is not None:
                self.armed = False
                raise _Interrupted()

    def name(self) -> str:
        return signal.Signals(self.signum).name if self.signum is not None else ""


def _stop(proc, guard: _Guard) -> None:
    """End the child's whole process group: killing git alone would leave its hook running."""
    from process import TERMINATION_GRACE_SECONDS, signal_group
    with guard.held():
        signal_group(proc.pid, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=TERMINATION_GRACE_SECONDS)
        signal_group(proc.pid, signal.SIGKILL)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            guard.survivor = True


def _drain(proc, buffer: bytearray, cap: int, deadline: float):
    """Read until the child itself exits, keeping the last `cap` bytes. Its exit is what counts, not EOF: a background
    child of a hook can hold the pipe open for ever. Returns the exit code, or None at the deadline."""
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    last_read = None
    with selectors.DefaultSelector() as poller:
        poller.register(fd, selectors.EVENT_READ)
        open_pipe = True
        while True:
            now = time.monotonic()
            code = proc.poll()
            if code is None and now > deadline:
                return None
            if code is not None and last_read is None:
                last_read = now + 0.5  # what git itself wrote is already in the pipe; a writer that goes on is not git
            if not open_pipe:
                if code is not None:
                    return code
                time.sleep(0.02)
                continue
            if poller.select(0 if code is not None else 0.05):
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    poller.unregister(fd)
                    open_pipe = False
                elif chunk:
                    buffer += chunk
                    if len(buffer) > cap:
                        del buffer[:-cap]
            elif code is not None:
                return code
            if code is not None and time.monotonic() > last_read:
                return code


def _run(command: list, guard: _Guard, timeout: float, *, buffer: bytearray | None = None, cap: int = OUTPUT_TAIL_BYTES,
         merge: bool = False):
    """Run a command in its own session with no stdin and capped output. (exit code or None at the deadline, output).
    On a deadline or a signal its process group is ended first."""
    buffer = bytearray() if buffer is None else buffer
    proc = None
    try:
        with guard.held():
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT if merge else subprocess.DEVNULL, start_new_session=True)
        code = _drain(proc, buffer, cap, time.monotonic() + timeout)
        if code is None:
            _stop(proc, guard)
        return code, bytes(buffer)
    except BaseException:
        if proc is not None and proc.poll() is None:
            _stop(proc, guard)
        raise
    finally:
        if proc is not None:
            proc.stdout.close()


def _git(top: str, guard: _Guard, timeout: float, *args):
    return _run(["git", "-C", top, *args], guard, timeout, cap=READ_BYTES)


def _branch_ref(top: str, guard: _Guard, timeout: float):
    """The ref a commit here will move: the branch, or HEAD when detached; None if git cannot say."""
    code, out = _git(top, guard, timeout, "symbolic-ref", "-q", "HEAD")
    if code == 0 and out.strip():
        return out.decode("utf-8", "surrogateescape").strip()
    return "HEAD" if code == 1 else None


def _tip(top: str, ref: str, guard: _Guard, timeout: float):
    """The commit at ref, '' if the branch has no commits yet, None if git cannot say."""
    code, out = _git(top, guard, timeout, "rev-parse", "-q", "--verify", ref)
    if code == 0 and out.strip():
        return out.decode("ascii", "replace").strip()
    return "" if code == 1 else None


def _record(top: str, rev: str, guard: _Guard, timeout: float):
    """(parents, message) as git stored them, or None. `git cat-file` is immune to log.showSignature and
    i18n.logOutputEncoding, which change what `git log` prints."""
    code, raw = _git(top, guard, timeout, "cat-file", "commit", rev)
    if code != 0 or not raw or len(raw) >= READ_BYTES:
        return None
    header, _, body = raw.partition(b"\n\n")
    parents = [line[7:].decode("ascii", "replace") for line in header.split(b"\n") if line.startswith(b"parent ")]
    return parents, body.decode("utf-8", "replace")


def _judge(top: str, ref: str, before: str, message: str, code, guard: _Guard, timeout: float) -> dict:
    """What git recorded: {'state': True | False | 'unknown', 'why': str, 'back': text, 'sha': str, 'hops': int}."""
    cp = _policy_mod()
    tip = _tip(top, ref, guard, timeout)
    if tip is None:
        return {"state": "unknown", "why": "could not read the branch after the commit"}
    if tip == before:
        if code == 0:
            return {"state": "unknown", "why": "git reported success but the branch did not move (did a hook move it?)"}
        if guard.survivor:
            return {"state": "unknown", "why": "git could not be stopped, so it may still commit"}
        return {"state": False, "why": ""}
    current, hops = tip, 0
    while hops < MAX_WALK:
        record = _record(top, current, guard, timeout)
        if record is None:
            return {"state": "unknown", "why": "could not read the new commit back"}
        parents, back = record
        if (parents[0] if parents else "") == before:
            if cp.normalize(back) == cp.normalize(message):
                return {"state": True, "back": back, "sha": current, "hops": hops, "tip": tip}
            if code == 0 and hops == 0:
                return {"state": True, "back": back, "sha": current, "hops": 0, "tip": tip}
            return {"state": "unknown", "why": "the branch moved to a commit with a different message"}
        if not parents:
            break
        current, hops = parents[0], hops + 1
    return {"state": "unknown", "why": "the branch moved, and not from the commit it was on before this run"}


def _seconds(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    if not re.fullmatch(r"[1-9][0-9]{0,6}", raw, re.ASCII):
        raise ValueError(f"{name} must be a positive whole number of seconds")
    return int(raw)


def _refused(r: dict, errors: list) -> tuple:
    return 2, {**r, "ok": False, "message": None, "committed": False, "errors": errors}


def _commit(r: dict, top: str, policy: dict, tickets: bool, guard: _Guard) -> tuple:
    """--commit. All setup comes before the message file exists, and the file is gone before the outcome is reported."""
    timeout, read_timeout = _seconds("HARNESS_COMMIT_TIMEOUT_S", 600), _seconds("HARNESS_COMMIT_READ_TIMEOUT_S", 30)
    work = work_dir()
    ref = _branch_ref(top, guard, read_timeout)
    before = _tip(top, ref, guard, read_timeout) if ref else None
    if before is None:
        return _refused(r, [_err("git", "could not read the current branch, so the outcome could not be judged")])
    path = _message_path(work)
    code, cause, output = None, "", bytearray()
    try:
        try:
            _write_message(path, r["message"])
            code, _ = _run(["git", "-C", top, "commit", "-F", str(path)], guard, timeout, buffer=output, merge=True)
            if code is None:
                cause = f"git commit did not finish within {timeout} s"
        except (OSError, subprocess.SubprocessError) as exc:
            cause = f"could not run git commit ({type(exc).__name__})"
        guard.armed = False  # the handler disarms before it raises, so from here on signals are only recorded
    except _Interrupted:
        pass
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
    return _outcome(r, top, ref, before, code, cause, output, policy, tickets, guard, read_timeout)


def _outcome(r: dict, top: str, ref: str, before: str, code, cause: str, output: bytearray, policy: dict, tickets: bool,
             guard: _Guard, read_timeout: int) -> tuple:
    """Disarmed: one bounded look at the repository, one result."""
    try:
        tail = _tail(output.decode("utf-8", "replace"))
        if guard.signum is not None:
            cause = f"interrupted by {guard.name()}"
            read_timeout = min(read_timeout, 5)
        verdict = _judge(top, ref, before, r["message"], code, guard, read_timeout)
        result = {**r, "commit_exit": code, "committed": verdict["state"]}
        if guard.signum is not None:
            result["interrupted"] = guard.name()
        if verdict["state"] is True:
            return _landed(result, verdict, code, cause, tickets, policy, top, guard, read_timeout)
        reason = cause or (f"git commit failed (exit {code})" if code else "")
        text = "; ".join(p for p in (reason, verdict["why"], tail) if p) or "git commit did not commit"
        if verdict["state"] == "unknown":
            text += "; inspect git log -1 before trying again"
        return 2, {**result, "ok": False, "message": None, "errors": [_err("git", text)]}
    except Exception as exc:  # noqa: BLE001
        return 4, {"ok": False, "message": None, "committed": "unknown", "commit_exit": code, "error": f"internal: {type(exc).__name__}"}


def _landed(result: dict, verdict: dict, code, cause: str, tickets: bool, policy: dict, top: str, guard: _Guard, read_timeout: int) -> tuple:
    cp = _policy_mod()
    warnings = list(result["warnings"])
    if code != 0:
        warnings.append(f"the commit landed but git did not finish cleanly ({cause or f'exit {code}'})")
    if verdict["hops"]:
        warnings.append(f"{verdict['hops']} later commit(s) landed on top of this one (a hook?)")
    if _tip(top, "HEAD", guard, read_timeout) != verdict["tip"]:
        warnings.append("HEAD is no longer at this branch tip (a hook switched it)")
    result.update(warnings=warnings, commit=verdict["sha"])
    if cp.normalize(verdict["back"]) != cp.normalize(result["message"]):
        problems = cp.validate(verdict["back"], policy=policy, tickets_required=tickets)
        warnings.append("the committed text differs from the validated message (a hook or git cleanup changed it); "
                        "the commit landed, inspect git log -1")
        result.update(message=_redact(verdict["back"]), committed_valid=not problems)
        if problems:
            return 2, {**result, "ok": False, "errors": field_errors(problems)}
    return 0, result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _parser() -> _Parser:
    ap = _Parser(description=__doc__.splitlines()[0], allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    common = _Parser(add_help=False, allow_abbrev=False)
    for flag in ("why", "what", "testing", "testing-command", "testing-result", "ticket", "refs", "risk"):
        common.add_argument("--" + flag, default="")
    common.add_argument("--no-tickets", action="store_true", help="repo with no ticket system")
    b = sub.add_parser("build", parents=[common], allow_abbrev=False)
    for flag in ("type", "scope", "summary", "reason", "authorized-by"):
        b.add_argument("--" + flag, default="")
    b.add_argument("--trailer", action="append", default=[])
    b.add_argument("--commit", action="store_true")
    b.add_argument("--repo", default=".")
    c = sub.add_parser("check", allow_abbrev=False)
    c.add_argument("--file", required=True)
    c.add_argument("--no-tickets", action="store_true")
    p = sub.add_parser("pr", parents=[common], allow_abbrev=False)
    p.add_argument("--title", default="")
    p.add_argument("--reason", default="")
    p.add_argument("--authorized-by", default="")
    return ap


def _dispatch(argv, guard: _Guard) -> tuple:
    """(exit code, JSON object, or None after --help)."""
    try:
        args = _parser().parse_args(argv)
    except ValueError as exc:
        return 2, {"ok": False, "errors": [_err("input", f"bad arguments: {exc}", "run with --help")]}
    except SystemExit as exc:  # --help
        return int(exc.code or 0), None
    cp = _policy_mod()
    policy = cp.load_policy()
    need = not args.no_tickets
    if args.cmd == "check":
        import safe_input
        try:
            text = safe_input.read_bounded(args.file, MAX_CHECK_BYTES).decode("utf-8", "replace")
        except safe_input.InputRejected as exc:
            return 2, {"ok": False, "errors": [_err("input", f"cannot read {args.file}: {exc.message}", f"pass a regular file of at most {MAX_CHECK_BYTES} bytes")]}
        problems = cp.validate(text, policy=policy, tickets_required=need)
        return (2 if problems else 0), {"ok": not problems, "errors": field_errors(problems)}
    fields = {k: v for k, v in vars(args).items() if k not in ("cmd", "commit", "repo", "no_tickets", "trailer")}
    if args.cmd == "pr":
        r = build_pr(fields, policy, tickets_required=need)
        return (0 if r["ok"] else 2), r
    fields["trailers"] = args.trailer or ([os.environ["HARNESS_COMMIT_TRAILER"]] if os.environ.get("HARNESS_COMMIT_TRAILER") else [])
    if not args.commit:
        r = build_message(fields, policy, tickets_required=need)
        return (0 if r["ok"] else 2), r
    try:
        facts = cp.repo_facts(args.repo)
    except subprocess.TimeoutExpired:
        return 2, {"ok": False, "message": None, "committed": False, "errors": [_err("git", f"git did not answer in {args.repo}")]}
    previous = None
    if facts is not None:
        need = cp.tickets_required_for(facts["origin"], policy)  # exactly the hook's rule for this repo
        record = _record(facts["top"], "HEAD", guard, _seconds("HARNESS_COMMIT_READ_TIMEOUT_S", 30))
        previous = record[1] if record else None
    r = build_message(fields, policy, tickets_required=need, previous=previous)
    if not r["ok"]:
        return 2, {**r, "committed": False}
    if facts is None:
        return _refused(r, [_err("git", f"{args.repo} is not a git repository, or git is not installed")])
    return _commit(r, facts["top"], policy, need, guard)


def main(argv=None, *, keep_handlers: bool = False) -> int:
    """The one place that prints. keep_handlers is for the CLI: a late signal must not change the exit code."""
    guard = _Guard()
    committing = "--commit" in (sys.argv[1:] if argv is None else argv)
    pre_launch = {"committed": False} if committing else {}
    try:
        try:
            guard.install()
            code, data = _dispatch(argv, guard)
        except ValueError as exc:
            code, data = 2, {"ok": False, **pre_launch, "errors": [_err("input", str(exc)[:300], "fix the input named in the problem")]}
        except Exception as exc:  # noqa: BLE001
            code, data = 4, {"ok": False, **pre_launch, "error": f"internal: {type(exc).__name__}"}
        guard.armed = False
    except _Interrupted:  # only before git was launched: _commit disarms before it can return or raise
        code, data = 2, {"ok": False, **pre_launch, "interrupted": guard.name(),
                         "errors": [_err("input", f"interrupted by {guard.name()} before anything was committed", "run it again")]}
    code = _print(code, data)
    if not keep_handlers:
        guard.restore()
    return code


def _print(code: int, data) -> int:
    if data is None:
        return code
    try:
        text = json.dumps(_scrub(data), sort_keys=True)
    except Exception as exc:  # noqa: BLE001
        code = 4
        text = json.dumps({"ok": False, "committed": data.get("committed", "unknown"), "error": f"internal: {type(exc).__name__}"}, sort_keys=True)
    with contextlib.suppress(OSError):
        print(text, flush=True)
    return code


def _entry() -> None:
    """The CLI. It leaves with os._exit because interpreter shutdown puts the default signal handlers back: a signal in
    that window ended the process with 143 after the JSON had already said exit 0 (seen under load, 2 of 92 runs)."""
    code = main(keep_handlers=True)
    with contextlib.suppress(OSError, ValueError):
        sys.stdout.flush()
    os._exit(code)


if __name__ == "__main__":
    _entry()
