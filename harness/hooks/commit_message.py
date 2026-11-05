#!/usr/bin/env python3
"""Build and validate policy-valid commit and PR messages from structured fields (GoodQA #14624).

Commit-policy refusals were the largest harness-caused tool failure (about 409 of 1,766 errors in one session: the
subject over 72 characters, a Testing line without an exact command or a result, a missing body). This module builds the
message from fields, applies only SAFE normalizations, and ALWAYS runs commit_policy.validate on the result: it never
returns a message the policy rejects. What it cannot fix comes back as field-level errors {field, problem, fix}
before git is touched. Stdlib only; the `ah commit` / `ah pr` verbs are thin wrappers over build_message / build_pr.

  commit_message.py build --type T --scope S --summary .. --why .. --what .. --testing .. --ticket 123 [--commit]
  commit_message.py check --file F          validate an existing message file
  commit_message.py pr --title .. --why .. --what .. --testing .. --ticket 123

Exit codes: 0 ok (0 with warnings), 2 refused with field errors (nothing written), 4 internal.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
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
    "trailers": "put Co-Authored-By lines in a final paragraph after a blank line",
    "message": "describe this change specifically (the message equals the previous commit)",
    "revert": "use type revert with Reason: and Authorized-by: citing the ticket",
}


def _policy_mod():
    import commit_policy
    return commit_policy


def field_errors(problems: list) -> list:
    """Map commit_policy problem lines ('Field: text') to {field, problem, fix}."""
    out = []
    for item in problems:
        head, _, rest = item.partition(":")
        field = head.strip() if head.strip() in FIELD_FIX else "message"
        out.append({"field": field, "problem": item, "fix": FIELD_FIX.get(field, FIELD_FIX["message"])})
    return out


def _one_line(value) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _ticket_ref(ticket, project="GoodQA") -> str:
    t = _one_line(ticket)
    if re.fullmatch(r"#?\d+", t):
        return f"{project} #{t.lstrip('#')}"
    return t


def _imperative(summary: str, warnings: list) -> str:
    words = summary.split()
    if words and words[0].lower() in IMPERATIVE:
        new = IMPERATIVE[words[0].lower()]
        warnings.append(f"subject: '{words[0]}' changed to the imperative '{new}'")
        words[0] = new
    return " ".join(words)


def _testing(fields: dict, warnings: list) -> str:
    cmd, res = _one_line(fields.get("testing_command")), _one_line(fields.get("testing_result"))
    if cmd or res:
        if cmd and res:
            return f"`{cmd.strip('`')}`: {res}"
        return _one_line(fields.get("testing")) or (f"`{cmd.strip('`')}`" if cmd else res)
    text = _one_line(fields.get("testing"))
    if not text or text.lower().startswith("not run:") or "`" in text:
        return text
    m = re.match(r"^(.+?)\s*(?:->|=>|:|\s-\s)\s*(\S.*)$", text)
    if m:  # 'python3 -m unittest: 14 passed' -> '`python3 -m unittest`: 14 passed'
        warnings.append("Testing: wrapped the command in backticks")
        return f"`{m.group(1).strip()}`: {m.group(2).strip()}"
    return text


def build_message(fields: dict, policy: dict | None = None, *, tickets_required: bool = True,
                  previous: str | None = None) -> dict:
    """{'ok': bool, 'message': str | None, 'errors': [...], 'warnings': [...]}; message is set only if it validates."""
    cp = _policy_mod()
    policy = policy or cp.load_policy()
    warnings: list = []
    kind = _one_line(fields.get("type")).lower()
    scope = _one_line(fields.get("scope")).lower()
    summary = _imperative(_one_line(fields.get("summary")).rstrip("."), warnings)
    subject = f"{kind}({scope}): {summary}" if scope else f"{kind}: {summary}"
    limit = int(policy["subject"]["max_length"])
    refs = _one_line(fields.get("refs")) or (_ticket_ref(fields.get("ticket")) if fields.get("ticket") else "")
    lines = [subject, "", f"Why: {_one_line(fields.get('why'))}", f"What: {_one_line(fields.get('what'))}",
             f"Testing: {_testing(fields, warnings)}", f"Refs: {refs}"]
    if _one_line(fields.get("risk")):
        lines.append(f"Risk: {_one_line(fields.get('risk'))}")
    trailers = [_one_line(t) for t in (fields.get("trailers") or []) if _one_line(t)]
    if trailers:
        lines += [""] + trailers
    message = "\n".join(lines) + "\n"
    problems = cp.validate(message, policy=policy, previous=previous, tickets_required=tickets_required)
    if problems:
        errors = field_errors(problems)
        for e in errors:
            if e["field"] == "subject" and len(subject) > limit:
                over = len(subject) - limit
                e["fix"] = f"shorten the summary by at least {over} character(s); the subject is {len(subject)} of {limit}"
        return {"ok": False, "message": None, "errors": errors, "warnings": warnings}
    return {"ok": True, "message": message, "errors": [], "warnings": warnings}


def build_pr(fields: dict, policy: dict | None = None, *, tickets_required: bool = True) -> dict:
    """A PR title (<=64 characters, so the squash subject '<title> (#N)' fits 72) and a Why/What/Testing/Refs body."""
    cp = _policy_mod()
    policy = policy or cp.load_policy()
    warnings: list = []
    title = _one_line(fields.get("title")).rstrip(".")
    refs = _one_line(fields.get("refs")) or (_ticket_ref(fields.get("ticket")) if fields.get("ticket") else "")
    body = "\n".join([f"Why: {_one_line(fields.get('why'))}", f"What: {_one_line(fields.get('what'))}",
                      f"Testing: {_testing(fields, warnings)}", f"Refs: {refs}"]) + "\n"
    problems = list(cp.validate_pr(title, body, policy, tickets_required=tickets_required))
    if problems:
        errors = []
        for item in problems:
            head = item.partition(":")[0].replace("PR ", "").strip()
            field = head if head in FIELD_FIX else ("subject" if "title" in item.lower() or "subject" in item.lower() else "body")
            fix = "shorten the PR title to at most 64 characters" if "chars" in item and field == "subject" else FIELD_FIX.get(field)
            errors.append({"field": field, "problem": item, "fix": fix})
        return {"ok": False, "title": None, "body": None, "errors": errors, "warnings": warnings}
    return {"ok": True, "title": title, "body": body, "errors": [], "warnings": warnings}


def ready_message(problems: list, message: str, task_fields: dict | None = None, policy: dict | None = None) -> str:
    """A ready-to-fill `commit_message.py build` command for the hook's block output. Structure only: the type and
    scope are reused when the refused subject has them in valid form, the ticket comes from the task fields; no part of
    the refused text, no secret and no session text is ever copied."""
    cp = _policy_mod()
    policy = policy or cp.load_policy()
    task = task_fields or {}
    subject = (message or "").split("\n", 1)[0]
    m = cp.SUBJECT.match(subject)
    kind = m.group("type").lower() if m and m.group("type").lower() in policy["subject"]["types"] else "fix"
    scope = m.group("scope") if m and m.group("scope") and re.match(policy["subject"]["scope_pattern"], m.group("scope")) else None
    scope = scope or (re.sub(r"[^a-z0-9._/-]", "", str(task.get("scope", "")).lower())[:40] or "<scope>")
    ticket = re.sub(r"[^A-Za-z0-9 #._-]", "", str(task.get("ticket", "")))[:40] or "<GoodQA ticket number>"
    return (f"python3 {HERE / 'commit_message.py'} build --type {kind} --scope {scope} --summary '<imperative summary>' "
            f"--why '<problem or motivation>' --what '<key changes>' --testing '<exact command>: <result>' "
            f"--ticket '{ticket}' --commit")


def work_dir() -> Path:
    base = Path(os.environ.get("HARNESS_WORK_DIR") or Path.home() / ".agent-harness" / "work" / "commit-messages")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    for flag in ("why", "what", "testing", "testing-command", "testing-result", "ticket", "refs", "risk"):
        common.add_argument("--" + flag, default="")
    common.add_argument("--no-tickets", action="store_true", help="repo with no ticket system")
    b = sub.add_parser("build", parents=[common])
    for flag in ("type", "scope", "summary"):
        b.add_argument("--" + flag, default="")
    b.add_argument("--trailer", action="append", default=[])
    b.add_argument("--commit", action="store_true")
    b.add_argument("--repo", default=".")
    c = sub.add_parser("check")
    c.add_argument("--file", required=True)
    c.add_argument("--no-tickets", action="store_true")
    p = sub.add_parser("pr", parents=[common])
    p.add_argument("--title", default="")
    args = ap.parse_args(argv)
    try:
        cp = _policy_mod()
        policy = cp.load_policy()
        need = not args.no_tickets
        if args.cmd == "check":
            problems = cp.validate(Path(args.file).read_text(), policy=policy, tickets_required=need)
            return _emit(2 if problems else 0, {"ok": not problems, "errors": field_errors(problems)})
        fields = {k.replace("-", "_"): v for k, v in vars(args).items() if k not in ("cmd", "commit", "repo", "no_tickets")}
        if args.cmd == "pr":
            r = build_pr(fields, policy, tickets_required=need)
            return _emit(0 if r["ok"] else 2, r)
        fields["trailers"] = args.trailer or ([os.environ["HARNESS_COMMIT_TRAILER"]] if os.environ.get("HARNESS_COMMIT_TRAILER") else [])
        r = build_message(fields, policy, tickets_required=need)
        if not r["ok"] or not args.commit:
            return _emit(0 if r["ok"] else 2, r)
        path = commit_message_file(r["message"])
        again = cp.validate(path.read_text(), policy=policy, tickets_required=need)
        if again:  # the file on disk must validate too
            return _emit(2, {**r, "ok": False, "errors": field_errors(again)})
        done = subprocess.run(["git", "-C", args.repo, "commit", "-F", str(path)], capture_output=True, text=True)
        r.update(commit_exit=done.returncode, message_file=str(path), git=(done.stdout + done.stderr)[-400:])
        return _emit(0 if done.returncode == 0 else 2, r)
    except Exception as exc:  # noqa: BLE001
        return _emit(4, {"ok": False, "error": f"internal: {type(exc).__name__}"})


if __name__ == "__main__":
    sys.exit(main())
