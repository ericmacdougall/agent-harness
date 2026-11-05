#!/usr/bin/env python3
"""Occasional reminder that a repository's local ticket ledger is not synced to GoodQA (docs/ledger.md).

  ledger_reminder.py                        hook (SessionStart and UserPromptSubmit): reads the hook JSON on
                                            stdin, prints at most one fixed line as additional context
  ledger_reminder.py dismiss --repo PATH [--days N | --forever]
                                            silence a repository (default 30 days)
  ledger_reminder.py status --repo PATH     print what is recorded for a repository

The hook never blocks and never exits non-zero: every failure is silence. It never touches the network. The
cheap gates run first (repository root, then the reminder state), so a suppressed repository never starts
`harness`. Everything fits one 2.5 s budget. `HARNESS_LEDGER_REMINDERS=0` silences it everywhere.

State: ~/.agent-harness/state/ledger-reminders.json (0600, at most 500 repositories, the least recently
reminded are evicted), changed under an exclusive non-blocking flock so two sessions cannot both remind. A
corrupt or symlinked state file counts as empty and is never followed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:  # the installed hooks directory has safe_input.py beside this file
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import safe_input
except Exception:  # pragma: no cover - a missing helper must not break the agent
    safe_input = None

BUDGET_SECONDS = 2.5
GIT_SECONDS = 0.5
DAY_MS = 24 * 3600 * 1000
SILENT_RECHECK_MS = 10 * 60 * 1000
MAX_REPOS = 500
STATE_MAX_BYTES = 512 * 1024
STDIN_MAX_BYTES = 64 * 1024
STATES = ("none", "local-only", "pending", "synced", "diverged", "tracked")
SLUG = re.compile(r"^[a-z0-9-]{1,40}$")
MIN_COMMITS_FOR_NONE = 3

TEXT = {
    "local-only": "Harness reminder (mention once, briefly, to the user): this repository keeps its tickets in a "
                  "local ledger{slug} that is not synced to GoodQA. When ready, `harness tickets export --format "
                  "goodqa-import` produces the import document. Silence with `ledger_reminder.py dismiss`.",
    "pending": "Harness reminder (mention once, briefly, to the user): the local ticket ledger{slug} has changes "
               "that are not yet synced to GoodQA. Silence with `ledger_reminder.py dismiss`.",
    "diverged": "Harness reminder (mention once, briefly, to the user): the local ticket ledger{slug} no longer "
                "matches what was last synced to GoodQA; export it again without --since-bound. Silence with "
                "`ledger_reminder.py dismiss`.",
    "none": "Harness reminder (mention once, briefly, to the user): this repository has no ticket system tracking "
            "it. `harness tickets init` starts a local ledger that GoodQA can import later. Silence with "
            "`ledger_reminder.py dismiss`.",
}


def state_dir(env) -> Path:
    override = env.get("HARNESS_STATE_DIR")
    if override:
        return Path(override)
    return Path(env.get("HOME") or os.path.expanduser("~")) / ".agent-harness" / "state"


def git_env(env) -> dict:
    keep = {k: v for k, v in env.items() if not k.startswith("GIT_")}
    keep.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                 "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    return keep


def run(argv, cwd, env, timeout, runner=subprocess.run):
    """stdout text of argv, or None on any failure or timeout."""
    try:
        done = runner(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout.decode("utf-8", errors="replace")


def git(args, cwd, env, timeout, runner=subprocess.run):
    return run(["git", "-c", "core.fsmonitor=false", *args], cwd, git_env(env), timeout, runner)


def repo_top(cwd, env, timeout=GIT_SECONDS, runner=subprocess.run):
    out = git(["rev-parse", "--show-toplevel"], cwd, env, timeout, runner)
    if not out or not out.strip():
        return None
    return os.path.realpath(out.strip())


def find_harness(env):
    for candidate in (env.get("HARNESS_BIN"), str(Path(env.get("HOME") or os.path.expanduser("~")) / ".agent-harness" / "bin" / "harness")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("harness", path=env.get("PATH"))


# ---------------------------------------------------------------------------------------------- state

def read_state(directory: Path) -> dict:
    empty = {"v": 1, "repos": {}}
    path = directory / "ledger-reminders.json"
    try:
        if safe_input is not None:
            raw = safe_input.read_bounded(path, STATE_MAX_BYTES, allowed_roots=(str(os.path.realpath(directory)),))
        else:  # pragma: no cover
            return empty
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return empty
    if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("repos"), dict):
        return empty
    repos = {}
    for key, entry in data["repos"].items():
        if not (isinstance(key, str) and isinstance(entry, dict)):
            continue
        try:  # one bad entry (NaN, Infinity, huge numbers) is dropped, never the whole file
            until = entry.get("dismissed_until_ms")
            repos[key] = {"last_ms": int(entry.get("last_ms") or 0) if isinstance(entry.get("last_ms"), (int, float)) else 0,
                          "state": entry.get("state") if entry.get("state") in STATES else "",
                          "session": str(entry.get("session") or "")[:128],
                          "dismissed_until_ms": int(until) if isinstance(until, (int, float)) else None,
                          "checked_ms": int(entry.get("checked_ms") or 0) if isinstance(entry.get("checked_ms"), (int, float)) else 0}
        except (ValueError, OverflowError):
            continue
    return {"v": 1, "repos": repos}


def write_state(directory: Path, state: dict) -> bool:
    repos = state["repos"]
    if len(repos) > MAX_REPOS:
        keep = sorted(repos, key=lambda k: repos[k]["last_ms"], reverse=True)[:MAX_REPOS]
        state = {"v": 1, "repos": {k: repos[k] for k in keep}}
    target = directory / "ledger-reminders.json"
    tmp = directory / f".ledger-reminders.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
        os.replace(tmp, target)  # replaces a symlink itself, never writes through it
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


class StateLock:
    """Exclusive non-blocking flock on a sibling lock file. Falsy when it cannot be taken."""

    def __init__(self, directory: Path):
        self.directory, self.fd = directory, None

    def __enter__(self):
        try:
            import fcntl
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.directory / "ledger-reminders.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                return None
            self.fd = fd
            return self
        except (OSError, ImportError):
            return None

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------------------------- hook

def reminder_text(state: str, slug: str) -> str:
    return TEXT[state].format(slug=f" ({slug})" if SLUG.fullmatch(slug or "") else "")


def decide(report: dict, top: str, env, remaining: float, runner=subprocess.run):
    """The state to remind about, or None."""
    state = report.get("state")
    if state not in STATES:
        return None
    if state in ("synced", "tracked"):
        return None
    if report.get("ledger") == "unusable":
        return None  # e.g. an adopted ledger whose writers still need review: "init a ledger" would mislead
    if state == "none":
        if report.get("tracked") is True:
            return None
        count = git(["rev-list", "--count", "HEAD"], top, env, min(GIT_SECONDS, max(remaining, 0.1)), runner)
        try:
            if int((count or "0").strip()) < MIN_COMMITS_FOR_NONE:
                return None
        except ValueError:
            return None
    return state


def hook(env, stdin_bytes: bytes, now_ms, runner=subprocess.run, clock=time.monotonic) -> str:
    """The text to print (JSON), or ''."""
    if env.get("HARNESS_LEDGER_REMINDERS") == "0":
        return ""
    started = clock()
    try:
        payload = json.loads(stdin_bytes.decode("utf-8", errors="replace") or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) and os.path.isdir(payload.get("cwd")) else os.getcwd()
    session = str(payload.get("session_id") or f"ppid:{os.getppid()}")[:128]
    event = payload.get("hook_event_name") if payload.get("hook_event_name") in ("SessionStart", "UserPromptSubmit") else "UserPromptSubmit"
    top = repo_top(cwd, env, runner=runner)
    if top is None:
        return ""
    directory = state_dir(env)
    now = now_ms()
    with StateLock(directory) as lock:
        if not lock:
            return ""
        state = read_state(directory)
        entry = state["repos"].get(top, {})
        until = entry.get("dismissed_until_ms")
        if until is not None and (until < 0 or until > now):
            return ""
        if entry.get("last_ms", 0) and now - entry["last_ms"] < DAY_MS:
            return ""
        if entry.get("session") == session:
            return ""
        if entry.get("checked_ms", 0) and now - entry["checked_ms"] < SILENT_RECHECK_MS:
            return ""  # the last look found nothing to say: do not start harness on every prompt
        harness = find_harness(env)
        if not harness:
            return ""
        remaining = BUDGET_SECONDS - (clock() - started)
        if remaining < 0.3:
            return ""
        out = run([harness, "tickets", "sync-state", "--json"], top, env, min(1.5, remaining - 0.2), runner)
        if not out:
            return ""
        try:
            report = json.loads(out)
        except ValueError:
            return ""
        if not isinstance(report, dict):
            return ""
        chosen = decide(report, top, env, BUDGET_SECONDS - (clock() - started), runner)
        if chosen is None:
            quiet = {**entry, "checked_ms": now}
            quiet.setdefault("last_ms", 0)
            quiet.setdefault("state", "")
            quiet.setdefault("session", "")
            quiet.setdefault("dismissed_until_ms", None)
            state["repos"][top] = quiet
            write_state(directory, state)
            return ""
        slug = report.get("slug") if isinstance(report.get("slug"), str) else ""
        text = reminder_text(chosen, slug)
        state["repos"][top] = {"last_ms": now, "state": chosen, "session": session, "checked_ms": 0,
                               "dismissed_until_ms": entry.get("dismissed_until_ms")}
        if not write_state(directory, state):
            return ""  # without a recorded reminder it would repeat on every prompt
    return json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}})


def dismiss(argv, env, now_ms) -> int:
    repo, days, forever = None, 30, False
    i = 0
    while i < len(argv):
        if argv[i] == "--repo" and i + 1 < len(argv):
            repo, i = argv[i + 1], i + 2
        elif argv[i] == "--days" and i + 1 < len(argv) and argv[i + 1].isascii() and argv[i + 1].isdigit():
            days, i = int(argv[i + 1]), i + 2
        elif argv[i] == "--forever":
            forever, i = True, i + 1
        else:
            print("usage: ledger_reminder.py dismiss --repo PATH [--days N | --forever]", file=sys.stderr)
            return 2
    if not repo:
        print("usage: ledger_reminder.py dismiss --repo PATH [--days N | --forever]", file=sys.stderr)
        return 2
    top = repo_top(repo, env, timeout=2) or os.path.realpath(repo)
    directory = state_dir(env)
    with StateLock(directory) as lock:
        if not lock:
            print("ledger_reminder.py: another process is updating the state; try again", file=sys.stderr)
            return 1
        state = read_state(directory)
        entry = state["repos"].get(top, {"last_ms": 0, "state": "", "session": "", "dismissed_until_ms": None})
        entry["dismissed_until_ms"] = -1 if forever else now_ms() + days * DAY_MS
        state["repos"][top] = entry
        if not write_state(directory, state):
            print("ledger_reminder.py: cannot write the state file", file=sys.stderr)
            return 1
    print(f"reminders for {top} silenced " + ("for good" if forever else f"for {days} days"))
    return 0


def status(argv, env, now_ms) -> int:
    repo = argv[1] if len(argv) == 2 and argv[0] == "--repo" else None
    if not repo:
        print("usage: ledger_reminder.py status --repo PATH", file=sys.stderr)
        return 2
    top = repo_top(repo, env, timeout=2) or os.path.realpath(repo)
    print(json.dumps({"repo": top, **read_state(state_dir(env))["repos"].get(top, {})}, sort_keys=True))
    return 0


def main(argv=None, env=None, stdin=None, now_ms=None, runner=subprocess.run) -> int:
    argv = sys.argv[1:] if argv is None else argv
    env = dict(os.environ) if env is None else env
    now_ms = now_ms or (lambda: int(time.time() * 1000))
    if argv and argv[0] == "dismiss":
        return dismiss(argv[1:], env, now_ms)
    if argv and argv[0] == "status":
        return status(argv[1:], env, now_ms)
    try:
        if stdin is None:
            try:
                stdin = safe_input.read_stdin_bounded(STDIN_MAX_BYTES) if safe_input else b""
            except Exception:
                stdin = b""
        text = hook(env, stdin, now_ms, runner)
        if text:
            sys.stdout.write(text + "\n")
    except Exception:  # never block the agent or the user
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
