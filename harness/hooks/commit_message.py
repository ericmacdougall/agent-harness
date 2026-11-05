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
installed git commit-msg backstop is a second layer only where git supports config hooks.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
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
    """Refuse control, format and surrogate characters and entirely-placeholder values (<...>) in any text field."""
    errors = []
    for key, value in fields.items():
        if key == "trailers" or value is None or isinstance(value, (list, tuple, dict)):
            continue
        text = _one_line(value)
        if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in str(value).replace("\n", " ").replace("\t", " ")):
            errors.append(_err(FIELD_OF.get(key, "input"), f"{key} contains control or invisible characters", FIELD_FIX["input"]))
        elif re.fullmatch(r"<[^<>]*>", text):
            errors.append(_err(FIELD_OF.get(key, "input"), f"{key} is an unfilled placeholder {text!r}",
                               f"replace {text!r} with the real content"))
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


def _testing(fields: dict, warnings: list, errors: list) -> str:
    cmd, res = _one_line(fields.get("testing_command")), _one_line(fields.get("testing_result"))
    if cmd or res:
        if cmd and res:
            return f"`{cmd.strip('`')}`: {res}"
        errors.append(_err("Testing", "give both testing_command and testing_result (or 'not run: <reason>')"))
        return ""
    text = _one_line(fields.get("testing"))
    cp = _policy_mod()
    if not text or text.lower().startswith("not run:") or "`" in text:
        return text
    m = re.match(r"^(.+?)(?:\s*->\s*|:\s+)(\S.*)$", text)
    # wrap only a left part that starts with a known tool and has balanced quotes; anything else passes through
    # unchanged so the policy refuses it ('tests: pass' is prose, not a command)
    if m and _balanced(m.group(1)) and cp.COMMAND_HINT.search(m.group(1)) and not re.search(r"\s", m.group(1).split()[0]):
        warnings.append("Testing: wrapped the command in backticks")
        return f"`{m.group(1).strip()}`: {m.group(2).strip()}"
    return text


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
    out = [_one_line(t) for t in value if _one_line(t)]
    bad = [t for t in out if not cp.TRAILER_LINE.match(t)]
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
    task = task_fields or {}
    m = cp.SUBJECT.match((message or "").split("\n", 1)[0])
    kind = m.group("type").lower() if m and m.group("type").lower() in policy["subject"]["types"] else "fix"
    scope = str(task.get("scope", "")).lower()
    scope = scope if re.fullmatch(policy["subject"]["scope_pattern"], scope) and not scope.startswith("-") else "<scope>"
    ticket = str(task.get("ticket", "")).strip()
    ticket = ticket if re.fullmatch(r"(?:GoodQA\s+(?:[A-Za-z0-9_-]+)?#\d{1,9}|\d{1,9})", ticket, re.ASCII) else "<ticket number>"
    q = shlex.quote
    return (f"python3 {q(str(HERE / 'commit_message.py'))} build --type {q(kind)} --scope {q(scope)} "
            f"--summary '<imperative summary>' --why '<problem or motivation>' --what '<key changes>' "
            f"--testing-command '<exact command>' --testing-result '<result>' --ticket {q(ticket)} --commit")


def work_dir() -> Path:
    """Durable, private directory for message files: absolute, outside the system temp dirs, never a symlink, mode 0700
    and ours. An existing directory that others can access is refused, not chmod-ed."""
    raw = os.environ.get("HARNESS_WORK_DIR") or str(Path.home() / ".agent-harness" / "work" / "commit-messages")
    base = Path(raw)
    if not base.is_absolute():
        raise ValueError("HARNESS_WORK_DIR must be an absolute path")
    temps = {Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve(), Path("/var/tmp").resolve()}
    real_parent = base.parent.resolve() if base.parent.exists() else base.parent
    if not os.environ.get("HARNESS_ALLOW_TMP_WORK") and any(t == real_parent or t in real_parent.parents or t == base for t in temps):
        raise ValueError("the message file belongs in the durable work directory, not the system temp dir")
    if base.is_symlink():
        raise ValueError("the work directory is a symlink")
    if not base.exists():
        base.mkdir(mode=0o700, parents=True)
    st = base.lstat()
    if not base.is_dir() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError("the work directory must be a directory owned by you with mode 0700")
    return base


def commit_message_file(message: str) -> Path:
    path = work_dir() / f"msg-{os.getpid()}-{os.urandom(4).hex()}.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(message)
    return path


def _emit(code: int, data: dict) -> int:
    print(json.dumps(data, sort_keys=True))
    return code


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _commit(r: dict, args, policy: dict) -> int:
    """--commit: apply the hook's own rules (ticket rule from the origin, duplicate of the last message), commit from a
    0600 file under the work dir, report git failures as errors, read the commit back, never leave the file behind."""
    cp = _policy_mod()
    facts = cp.repo_facts(args.repo)
    if facts is None:
        return _emit(2, {**r, "ok": False, "message": None, "errors": [_err("git", f"{args.repo} is not a git repository")]})
    tickets = cp.tickets_required_for(facts["origin"], policy)
    again = cp.validate(r["message"], policy=policy, previous=facts["head"], tickets_required=tickets)
    if again:
        return _emit(2, {**r, "ok": False, "message": None, "errors": field_errors(again)})
    path = commit_message_file(r["message"])
    try:
        done = subprocess.run(["git", "-C", facts["top"], "commit", "-F", str(path)], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=120)
        output = (done.stdout + done.stderr).strip()
        if done.returncode != 0:
            cause = "\n".join(output.splitlines()[:6])[:600]
            return _emit(2, {**r, "ok": False, "message": None, "errors": [_err("git", f"git commit failed (exit "
                             f"{done.returncode}): {cause}")], "commit_exit": done.returncode})
        back = subprocess.run(["git", "-C", facts["top"], "log", "-1", "--format=%B"], capture_output=True, text=True,
                              timeout=30).stdout
        if cp.normalize(back) != cp.normalize(r["message"]):
            r["warnings"] = r["warnings"] + ["the committed text differs from the validated message (a commit hook or "
                                              "git cleanup changed it); inspect git log -1"]
        r.update(commit_exit=0, message_file_used=str(path))
        return _emit(0, r)
    except subprocess.TimeoutExpired:
        return _emit(2, {**r, "ok": False, "message": None, "errors": [_err("git", "git commit timed out after 120 s")]})
    finally:
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
