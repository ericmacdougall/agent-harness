#!/usr/bin/env python3
"""Build and validate policy-valid commit and PR messages from structured fields (GoodQA #14624).

Commit-policy refusals were the largest harness-caused tool failure (about 409 of 1,766 errors in one session: the
subject over 72 characters, a Testing line without an exact command or a result, a missing body). This module builds the
message from fields, applies only SAFE normalizations, and ALWAYS runs commit_policy.validate on the result: it never
returns a message the policy rejects. What it cannot fix comes back as field-level errors {field, problem, fix}
before git is touched. Stdlib only; `ah commit` / `ah pr` are thin wrappers over build_message / build_pr.

  commit_message.py build --type T --scope S --summary .. --why .. --what .. --testing-command C --testing-result R
                          --ticket 123 [--reason .. --authorized-by ..] [--commit [--repo DIR]]
  commit_message.py check --file F          validate an existing message file
  commit_message.py pr --title .. --why .. --what .. --testing-command C --testing-result R --ticket 123

Exit codes: 0 ok (0 with warnings), 2 refused with field errors (nothing committed, no file left behind), 4 internal.
Limits, stated plainly: the commit-policy hook cannot see the message inside `commit_message.py --commit`, so --commit
applies the hook's own rules itself (ticket rule from the repo's origin, previous-message duplicate check); the
installed git commit-msg backstop is a second layer only where git supports config hooks. NOT YET WIRED: the commit
hook's block text does not call ready_message, and `ah commit` / `ah pr` (the ah owner) wrap this module after it merges.
Exit 2 with "committed": true means the commit landed but its text is not policy-valid (a hook rewrote it).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
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
MAX_FILE = 1_000_000
MAX_FIELD = 4096
STOP = {"sure", "through", "looks", "everything", "works", "fine", "good", "manually", "hand", "by", "the", "it", "all",
        "things", "that", "this", "myself", "okay", "right"}
SECRETISH = re.compile(r"(?i)sk-|ghp_|xox[a-z]-|secret|token|passw|api[_-]?key|credential|bearer")
INVISIBLE = set("\u3164\u115f\u1160\uffa0\u2800\u034f\ufe0f\u180e\u2062\u2063")
PLACEHOLDER = re.compile(r"<[A-Za-z][^<>@]*>")  # never an e-mail address
TRAILER = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*: \S.*$")
TEXT_FIELDS = ("summary", "why", "what", "testing", "testing_command", "testing_result", "risk", "refs", "reason",
               "authorized_by", "title")


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


def _scan(fields: dict) -> list:
    """Refuse control, format and surrogate characters, unfilled <placeholder> tokens, over-long and (almost) contentless
    values in any text field."""
    errors = []
    for key, value in fields.items():
        if key == "trailers" or value is None or isinstance(value, (list, tuple, dict)):
            continue
        raw = str(value)
        text = _one_line(value)
        field = FIELD_OF.get(key, "input")
        if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in raw.replace("\n", " ").replace("\t", " ")):
            errors.append(_err(field, f"{key} contains control or invisible characters", FIELD_FIX["input"]))
        elif len(text) > MAX_FIELD:
            errors.append(_err(field, f"{key} is longer than {MAX_FIELD} characters", "shorten it; the details belong in the diff or a ticket"))
        elif key in TEXT_FIELDS and PLACEHOLDER.search(text):
            errors.append(_err(field, f"{key} still contains an unfilled placeholder {PLACEHOLDER.search(text).group(0)!r}",
                               "replace the <...> text with the real content"))
        elif key in ("why", "what") and text and sum(c.isalnum() and c not in INVISIBLE for c in text) < 8:
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


def _balanced(text: str) -> bool:
    return text.count("'") % 2 == 0 and text.count('"') % 2 == 0 and text.count("`") % 2 == 0


def _looks_like_command(text: str) -> bool:
    """A known tool followed by what looks like an argument, and no English filler words: prose such as 'make sure
    everything works' or 'I eyeballed it' is not a command."""
    cp = _policy_mod()
    words = text.split()
    if not words or not cp.COMMAND_HINT.search(text) or not _balanced(text):
        return False
    return not (len(words) > 1 and any(w.lower().strip(".,;") in STOP for w in words[1:])) and (
        len(words) > 1 or words[0] in ("pytest", "tox", "nox", "jest", "vitest"))


def _bare(text: str, errors: list) -> str:
    """Unwrapped Testing text passes only if it itself reads as a command line; the policy's keyword heuristic alone
    accepts prose such as 'make sure tests pass'."""
    if re.match(r"^\S+:\s", text) or not _looks_like_command(text):  # 'node: ok' is a label and a verdict
        errors.append(_err("Testing", f"{text[:40]!r} does not look like a command with a result"))
    return text


def _testing(fields: dict, warnings: list, errors: list) -> str:
    cmd, res = _one_line(fields.get("testing_command")), _one_line(fields.get("testing_result"))
    if cmd or res:
        if not (cmd and res):
            errors.append(_err("Testing", "give both testing_command and testing_result (or 'not run: <reason>')"))
            return ""
        if not _looks_like_command(cmd.strip("`")):
            errors.append(_err("Testing", f"{cmd[:40]!r} does not look like a command", FIELD_FIX["Testing"]))
            return ""
        if _one_line(fields.get("testing")):
            warnings.append("Testing: testing was ignored because testing_command and testing_result are given")
        return f"`{cmd.strip('`')}`: {res}"
    text = _one_line(fields.get("testing"))
    if not text or text.lower().startswith("not run:") or "`" in text:
        return text
    # an arrow splits on its LAST occurrence (commands may contain '->'); otherwise the first ': ' splits
    if " -> " in text:
        left, _, right = text.rpartition(" -> ")
    else:
        left, sep, right = text.partition(": ")
        if not sep:
            return _bare(text, errors)
    if left.strip() and right.strip() and _looks_like_command(left.strip()):
        warnings.append("Testing: wrapped the command in backticks")
        return f"`{left.strip()}`: {right.strip()}"
    return _bare(text, errors)


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
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for t in raw for c in t):
        errors.append(_err("trailers", "a trailer contains control or invisible characters"))
        return []
    if any("\n" in t or "\r" in t for t in raw):
        errors.append(_err("trailers", "each trailer must be one line"))
        return []
    out = [_one_line(t) for t in raw if _one_line(t)]
    bad = [t for t in out if not (TRAILER.match(t) and cp.TRAILER_LINE.match(t)) or PLACEHOLDER.search(t)]
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
    roots = {Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve(), Path("/var/tmp").resolve(),
             Path("/var/folders").resolve()}
    try:
        user_tmp = subprocess.run(["getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True, timeout=5).stdout.strip()
        if user_tmp:
            roots.add(Path(user_tmp).resolve())
    except (OSError, subprocess.SubprocessError):
        pass
    return roots


def work_dir() -> Path:
    """Durable, private directory for message files: absolute, outside the system temp dirs (judged on the resolved
    path, so /tmp, /var/tmp and macOS /private aliases all count), never a symlink, mode 0700 and ours. An existing
    directory that others can access is refused, not chmod-ed. HARNESS_ALLOW_TMP_WORK=1 is a TEST hook only."""
    raw = os.environ.get("HARNESS_WORK_DIR") or str(Path.home() / ".agent-harness" / "work" / "commit-messages")
    base = Path(raw)
    if not base.is_absolute():
        raise ValueError("HARNESS_WORK_DIR must be an absolute path")
    if base.is_symlink():
        raise ValueError("the work directory is a symlink")
    resolved = base.resolve(strict=False)
    if os.environ.get("HARNESS_ALLOW_TMP_WORK") != "1" and any(t == resolved or t in resolved.parents for t in _temp_roots()):
        raise ValueError("the message file belongs in the durable work directory, not the system temp dir")
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(f"cannot create the work directory {base}: {exc.strerror}") from None
    st = base.lstat()
    if not base.is_dir() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError("the work directory must be a directory owned by you with mode 0700")
    return base


def commit_message_file(message: str) -> Path:
    path = work_dir() / f"msg-{os.getpid()}-{os.urandom(4).hex()}.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(message)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


REDACT = re.compile(r"(?i)\b(?:token|secret|passw(?:or)?d|api[_-]?key|authorization)\b\s*[=:]\s*\S+|\b(?:ghp|gho|sk|xox[a-z])[-_][A-Za-z0-9_-]{6,}")


def _tail(output: str, lines: int = 8, chars: int = 700) -> str:
    return REDACT.sub("[redacted]", "\n".join(output.strip().splitlines()[-lines:]))[-chars:]


def _emit(code: int, data: dict) -> int:
    print(json.dumps(data, sort_keys=True))
    return code


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _head(top: str):
    done = subprocess.run(["git", "-C", top, "rev-parse", "-q", "--verify", "HEAD"], capture_output=True, text=True, timeout=30)
    return done.stdout.strip() if done.returncode == 0 else ""


def _commit(r: dict, args, policy: dict) -> int:
    """--commit: apply the hook's own rules (ticket rule from the origin, duplicate of the last message), commit from a
    0600 file under the work dir, report git failures as errors, read the commit back, never leave the file behind.
    After git has been launched the outcome is judged by HEAD, never by an exception: committed is true, false or unknown."""
    cp = _policy_mod()
    facts = cp.repo_facts(args.repo)
    if facts is None:
        return _emit(2, {**r, "ok": False, "message": None, "errors": [_err("git", f"{args.repo} is not a git repository, or git is not installed")]})
    tickets = cp.tickets_required_for(facts["origin"], policy)
    again = cp.validate(r["message"], policy=policy, previous=facts["head"], tickets_required=tickets)
    if again:
        return _emit(2, {**r, "ok": False, "message": None, "errors": field_errors(again)})
    path = commit_message_file(r["message"])
    old_term = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(143)))
    top, before = facts["top"], _head(facts["top"])
    timeout = int(os.environ.get("HARNESS_COMMIT_TIMEOUT_S", "600"))
    state = "unknown"
    try:
        try:
            done = subprocess.run(["git", "-C", top, "commit", "-F", str(path)], capture_output=True, stdin=subprocess.DEVNULL,
                                  timeout=timeout)
            output = (done.stdout + done.stderr).decode("utf-8", "replace")
            code = done.returncode
        except subprocess.TimeoutExpired:
            output, code = f"git commit did not finish within {timeout} s", None
        after = _head(top)
        state = "true" if after and after != before else ("false" if after == before else "unknown")
        if state != "true":
            cause = _tail(output) if code is not None else output
            return _emit(2, {**r, "ok": False, "message": None, "committed": state == "true" if state != "unknown" else "unknown",
                             "errors": [_err("git", f"git commit failed (exit {code}): {cause}" if code is not None else cause)],
                             "commit_exit": code})
        back = subprocess.run(["git", "-C", top, "log", "-1", "--format=%B"], capture_output=True, timeout=30).stdout.decode("utf-8", "replace")
        r.update(commit_exit=code, committed=True)
        if cp.normalize(back) != cp.normalize(r["message"]):
            problems = cp.validate(back, policy=policy, tickets_required=tickets)
            r.update(message=back, warnings=r["warnings"] + ["the committed text differs from the validated message (a hook or "
                     "git cleanup changed it); the commit landed, inspect git log -1"], committed_valid=not problems)
            if problems:
                return _emit(2, {**r, "ok": False, "errors": field_errors(problems)})
        return _emit(0, r)
    finally:
        signal.signal(signal.SIGTERM, old_term)
        try:
            path.unlink()
        except OSError:
            pass


def main(argv=None) -> int:
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
    try:
        args = ap.parse_args(argv)
    except ValueError as exc:
        return _emit(2, {"ok": False, "errors": [_err("input", f"bad arguments: {exc}", "run with --help")]})
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    try:
        cp = _policy_mod()
        policy = cp.load_policy()
        need = not args.no_tickets
        if args.cmd == "check":
            sys.path.insert(0, str(HERE))
            import safe_input
            try:
                text = safe_input.read_bounded(args.file, MAX_FILE).decode("utf-8", "replace")
            except safe_input.InputRejected as exc:
                return _emit(2, {"ok": False, "errors": [_err("input", f"cannot read {args.file}: {exc.message}")]})
            problems = cp.validate(text, policy=policy, tickets_required=need)
            return _emit(2 if problems else 0, {"ok": not problems, "errors": field_errors(problems)})
        fields = {k: v for k, v in vars(args).items() if k not in ("cmd", "commit", "repo", "no_tickets", "trailer")}
        if args.cmd == "pr":
            r = build_pr(fields, policy, tickets_required=need)
            return _emit(0 if r["ok"] else 2, r)
        fields["trailers"] = args.trailer or ([os.environ["HARNESS_COMMIT_TRAILER"]] if os.environ.get("HARNESS_COMMIT_TRAILER") else [])
        facts = cp.repo_facts(args.repo) if args.commit else None
        if facts is not None:
            need = cp.tickets_required_for(facts["origin"], policy)  # exactly the hook's rule for this repo
        r = build_message(fields, policy, tickets_required=need, previous=facts["head"] if facts else None)
        if not r["ok"] or not args.commit:
            return _emit(0 if r["ok"] else 2, r)
        return _commit(r, args, policy)
    except ValueError as exc:
        return _emit(2, {"ok": False, "errors": [_err("input", str(exc)[:300], "fix the input named in the problem")]})
    except Exception as exc:  # noqa: BLE001
        return _emit(4, {"ok": False, "error": f"internal: {type(exc).__name__}"})


if __name__ == "__main__":
    sys.exit(main())
