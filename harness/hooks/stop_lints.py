#!/usr/bin/env python3
"""Stop and SubagentStop lints for completion hygiene (rules W04, W06, W12, W17, S18, S26; GoodQA rules batch B4).

  stop_lints.py stop            Stop hook: lints the session's main WAL and final message
  stop_lints.py subagent-stop   SubagentStop hook: lints the subagent's own WAL and final message

Lints (all warn-only; modes live in stop_lints_policy.json, "off" disables one):
  W04  files were edited but the WAL has no intent entry before the first edit, or no result/check/handoff/commit
       entry after the last edit.
  W06  PENDING_REAL_TEST ids in the WAL that no REALLY_TESTED entry names.
  W12  the final message claims done/complete/shipped/merged without a cite (commit SHA, REALLY_TESTED id, PR number
       or URL).
  W17  the final message hands the user a chore (run, install, click, sign in ...) without saying no agent path exists.
  S18  the working tree has tracked uncommitted changes or commits that are on no remote branch.
  S26  a red-team subagent's final report lacks its Worst-case or Bound declaration.

It is a standalone entry: it never edits other hooks' state, and fails open (prints nothing, exits 0) on any error
of its own, because a warn-mode lint must never break a session. Warnings carry rule ids, counts and WAL ids only,
never message text. The check for edits counts Write/Edit/MultiEdit/NotebookEdit tool calls recorded in the WAL;
file changes made through Bash are not seen.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "stop_lints_policy.json"
RULES = ("W04", "W06", "W12", "W17", "S18", "S26")
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
INTENT_EVENTS = {"intent", "scope"}
RESULT_EVENTS = {"result", "check", "handoff", "commit"}
MAX_INPUT = 2_000_000
MAX_WAL = 4_000_000
MAX_MESSAGE = 60_000
TAIL_WINDOW = 400_000
SESSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z-]{7,63}$")
AGENT_RE = re.compile(r"^[0-9A-Za-z]{6,64}$")
ID_BODY = r"([A-Za-z0-9_][A-Za-z0-9_.\-]*[A-Za-z0-9_]|[A-Za-z0-9_])"
PENDING_RE = re.compile(r"PENDING_REAL_TEST\s+" + ID_BODY + r"(?=:)")  # the convention is `PENDING_REAL_TEST <id>:`
REALLY_RE = re.compile(r"REALLY_TESTED\s+" + ID_BODY + r"(?=[:\s,;)]|\.(?:\s|$)|$)")
DONE_WINDOW = 12_000  # the end of the message is where the claim is; also bounds every regex below
DONE_RE = re.compile(
    r"(?im)\b(?:the (?:work|task|change|fix|feature|batch|pr|migration) (?:is|are)|it(?:'s| is)|all (?:is|are)|now|all)"
    r"[ \t]+(?:done|complete|completed|finished|delivered|merged|shipped|deployed)\b"
    r"|\b(?:i|we)(?:'ve| have)?[ \t]+(?:finished|completed|shipped|merged|deployed|delivered)\b|^[ \t]*done[.!:]")
CITE_RE = re.compile(r"\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b|REALLY_TESTED[ \t]+(?=[A-Za-z0-9_.\-]*[0-9_\-])[A-Za-z0-9_][A-Za-z0-9_.\-]*"
                     r"|/pull/\d+|\bPR[ \t]*#\d+", re.I)
VERBS = r"(?:run|install|copy|paste|edit|restart|click|open|sign in|log ?in|download|approve|create|set up|configure|add)"
CHORE_RES = [re.compile(p, re.I) for p in (
    r"\byou(?:'ll| will)? (?:(?:need|have) to|must|should) " + VERBS + r"\b",
    r"\bplease " + VERBS + r"\b",
    r"\b(?:manually|by hand) " + VERBS + r"\b",
    r"\bcan you " + VERBS + r"\b")]
NO_AGENT_PATH_RE = re.compile(r"no agent[- ]doable path|agent cannot|can(?:'|no)t be done by an agent|only you can", re.I)
WORST_RE = re.compile(r"worst[- ]case", re.I)
BOUND_RE = re.compile(r"\bbounds?\b[ \t]*[:=\-\u2013\u2014]|\bbounded (?:by|to)\b", re.I)


def load_modes(path: Path = POLICY) -> dict[str, str]:
    modes = {rule: "warn" for rule in RULES}
    try:
        data = json.loads(path.read_text())
        for rule, mode in (data.get("modes") or {}).items():
            if rule in modes and mode in ("warn", "off"):
                modes[rule] = mode
    except (OSError, ValueError, AttributeError):
        pass
    return modes


def read_payload() -> dict:
    raw = sys.stdin.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def wal_path(payload: dict, subagent: bool, home: Path | None = None) -> Path | None:
    session = str(payload.get("session_id") or "")
    if not SESSION_RE.match(session):
        return None
    base = (home or Path.home()) / ".claude" / "wals" / session
    if subagent:
        agent = str(payload.get("agent_id") or "")
        return base / f"agent-{agent}.jsonl" if AGENT_RE.match(agent) else None
    return base / "main.jsonl"


def read_wal(path: Path | None) -> list[dict]:
    if path is None or not path.is_file() or path.is_symlink():
        return []
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            if size > MAX_WAL:
                fh.seek(size - MAX_WAL)
                fh.readline()
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    rows = []
    for line in data.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def stamp(row: dict) -> datetime | None:
    try:
        value = datetime.fromisoformat(str(row.get("at")))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def lint_wal_intent_result(rows: list[dict]) -> list[str]:
    """W04."""
    writes = [stamp(r) for r in rows if r.get("event") == "pretool" and r.get("tool") in WRITE_TOOLS]
    writes = [w for w in writes if w]
    if not writes:
        return []
    first, last = min(writes), max(writes)
    out = []
    if not any(r.get("event") in INTENT_EVENTS and (s := stamp(r)) and s <= first for r in rows):
        out.append("W04: files were edited but the WAL has no intent/scope entry before the first edit")
    if not any(r.get("event") in RESULT_EVENTS and (s := stamp(r)) and s >= last for r in rows):
        out.append("W04: files were edited but the WAL has no result/check/handoff/commit entry after the last edit")
    return out


def lint_pending_tests(rows: list[dict], other_rows: list[dict] | None = None) -> list[str]:
    """W06. other_rows are the same session's subagent WALs: owners record REALLY_TESTED in their own."""
    pending, done = {}, set()
    for r in other_rows or []:
        done.update(m.group(1) for m in REALLY_RE.finditer(str(r.get("note") or "")))
    for r in rows:
        note = str(r.get("note") or "")
        for m in PENDING_RE.finditer(note):
            pending.setdefault(m.group(1), r.get("id") or "")
        done.update(m.group(1) for m in REALLY_RE.finditer(note))
    dangling = [i for i in pending if i not in done]
    if not dangling:
        return []
    shown = ", ".join(dangling[:8]) + (f" (+{len(dangling) - 8} more)" if len(dangling) > 8 else "")
    return [f"W06: {len(dangling)} PENDING_REAL_TEST id(s) without a REALLY_TESTED entry: {shown}"]


def lint_done_claim(message: str) -> list[str]:
    """W12."""
    message = message[-DONE_WINDOW:]
    if DONE_RE.search(message) and not CITE_RE.search(message):
        return ["W12: the final message claims the work is done but cites no commit SHA, REALLY_TESTED id or PR"]
    return []


def lint_chore(message: str) -> list[str]:
    """W17."""
    message = message.replace("\u2019", "'").replace("\u2018", "'")
    if NO_AGENT_PATH_RE.search(message):
        return []
    hits = sum(1 for rx in CHORE_RES for _ in rx.finditer(message))
    if hits:
        return [f"W17: the final message asks the user to do {hits} chore(s) with no stated reason an agent can not do them"]
    return []


def lint_red_team(message: str, agent_type: str) -> list[str]:
    """S26."""
    if agent_type != "red-team":
        return []
    missing = [name for name, rx in (("Worst-case", WORST_RE), ("Bound", BOUND_RE)) if not rx.search(message)]
    if missing:
        return [f"S26: the red-team report has no {' or '.join(missing)} declaration for its probes"]
    return []


RISKY_CONFIG = re.compile(r"^(filter\..*|core\.fsmonitor|core\.sshcommand|core\.hookspath|core\.pager|diff\.external|"
                          r"diff\..*\.(command|textconv)|include\.path|includeif\..*)\b", re.I | re.M)
DEADLINE = [0.0]


def git(cwd: str, *args: str) -> str | None:
    left = DEADLINE[0] - time.monotonic() if DEADLINE[0] else 5.0
    if left <= 0.2:
        return None
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home()), "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0"}
    try:
        done = subprocess.run(["git", "-C", cwd, "-c", "core.fsmonitor=false", *args], capture_output=True, text=True,
                              timeout=min(5.0, left), env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def lint_unpushed(cwd: str) -> list[str]:
    """S18."""
    if not cwd or not os.path.isdir(cwd) or git(cwd, "rev-parse", "--is-inside-work-tree") is None:
        return []
    # git status runs clean filters, fsmonitor and similar commands named in the repo's own config; do not run it
    # in a repo whose local config names any (a repo an agent or an archive wrote)
    if RISKY_CONFIG.search(git(cwd, "config", "--local", "--name-only", "--list") or ""):
        return []
    if not (git(cwd, "remote") or "").strip():
        return []  # nowhere to push: every commit would be "unpushed" on every turn
    out = []
    dirty = git(cwd, "status", "--porcelain=v1", "--untracked-files=no")
    if dirty and dirty.strip():
        out.append(f"S18: {len(dirty.strip().splitlines())} tracked file(s) have uncommitted changes")
    ahead = git(cwd, "rev-list", "--count", "HEAD", "--not", "--remotes")
    if ahead and ahead.strip().isdigit() and int(ahead) > 0:
        branch = (git(cwd, "branch", "--show-current") or "").strip() or "detached HEAD"
        out.append(f"S18: {int(ahead)} commit(s) on {branch} are on no remote branch (push the feature branch)")
    return out


def last_message(payload: dict) -> str:
    direct = payload.get("last_assistant_message")
    if isinstance(direct, str) and direct.strip():
        return direct[-MAX_MESSAGE:]
    for key in ("agent_transcript_path", "transcript_path"):
        path = payload.get(key)
        text = tail_message(path) if isinstance(path, str) and path else ""
        if text:
            return text
    return ""


def tail_message(path: str) -> str:
    """Last assistant text in a transcript file under ~/.claude/projects (regular file, tail window only)."""
    try:
        real = Path(path).resolve(strict=True)
        root = (Path.home() / ".claude" / "projects").resolve()
        if not real.is_file() or root not in real.parents:
            return ""
        size = real.stat().st_size
        with open(real, "rb") as fh:
            if size > TAIL_WINDOW:
                fh.seek(size - TAIL_WINDOW)
                fh.readline()
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return ""
    for line in reversed(data.splitlines()):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("type") != "assistant":
            continue
        content = (rec.get("message") or {}).get("content")
        pieces = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"] \
            if isinstance(content, list) else ([content] if isinstance(content, str) else [])
        text = "\n".join(p for p in pieces if isinstance(p, str)).strip()
        if text:
            return text[-MAX_MESSAGE:]
    return ""


def run_lints(payload: dict, subagent: bool, modes: dict[str, str] | None = None, home: Path | None = None) -> list[str]:
    modes = modes or load_modes()
    DEADLINE[0] = time.monotonic() + 10.0
    try:
        return _run_lints(payload, subagent, modes, home)
    finally:
        DEADLINE[0] = 0.0  # no stale budget for a later direct call


def _run_lints(payload: dict, subagent: bool, modes: dict[str, str], home: Path | None) -> list[str]:
    path = wal_path(payload, subagent, home)
    rows = read_wal(path)
    siblings = []
    if not subagent and path is not None:
        for other in sorted(path.parent.glob("agent-*.jsonl"))[:60]:
            siblings += read_wal(other)
    message = last_message(payload)
    found: list[str] = []
    if modes["W04"] == "warn":
        found += lint_wal_intent_result(rows)
    if modes["W06"] == "warn":
        found += lint_pending_tests(rows, siblings)
    if message:
        if modes["W12"] == "warn":
            found += lint_done_claim(message)
        if modes["W17"] == "warn":
            found += lint_chore(message)
        if modes["S26"] == "warn" and subagent:
            found += lint_red_team(message, str(payload.get("agent_type") or ""))
    if modes["S18"] == "warn":
        found += lint_unpushed(str(payload.get("cwd") or ""))
    return found


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or argv[0] not in ("stop", "subagent-stop"):
        print(__doc__, file=sys.stderr)
        return 3
    try:
        found = run_lints(read_payload(), argv[0] == "subagent-stop")
        if found:
            print(json.dumps({"systemMessage": "stop_lints (warn mode): " + " | ".join(found)}))
    except Exception as exc:  # noqa: BLE001 - a warn-mode lint must never break a session
        print(f"stop_lints: skipped ({type(exc).__name__})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
