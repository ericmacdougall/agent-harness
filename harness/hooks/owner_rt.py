#!/usr/bin/env python3
"""Owner runtime: long-lived, self-looping product owners (owner-runtime-drive; user 2026-11-14).

The user's words (session baab765b): "an 'owner' is responsible for proving to you, every 30 minutes, that it is
getting the product its assigned to done.. and working with you when it needs help unblocking -- but never stopping
all progress on one facet", and "they are long-lived responsible self-looping agents incharge of delivery of the
product.. they can be haded many 'tasks' related to the project and they have to internally coordinate and assign
subagents to accoplish them after proper planning and acceptance criteria and adversarial convergence".

Why a new runtime: a sub-agent ends when its turn ends and only main can resume it, so every owner's lifetime depended
on main remembering. Here an owner is a Claude Code background session (`claude --bg`, its own session with every
harness hook), bound to one mission goal (goals.json) until the goal is done. Its durable state lives on disk, so a
stop, a crash or a context limit loses nothing:

  ~/.agent-harness/owners/<goal>/      (0700)
    state.json    goal, cwd, model, permission mode, generation, session id, background id, last proof, checkpoint,
                  resume schedule, launch history (atomic replace, 0600)
    inbox.jsonl   append-only task rows and transitions (0600)
    launch.log    one line per launch attempt
  ~/.agent-harness/owners/runtime.json  {"enabled": true, "permission_mode": "auto", "max_launches_per_hour": 4,
                  "min_gap_s": 300, "fresh_bytes": 8000000}  (absent or enabled=false: tick never launches;
                  permission_mode is auto, acceptEdits, default or dontAsk, never bypassPermissions)
  ~/.agent-harness/owners/authority.json  bypass grants and drive parks, each bound to the user's structured
                  AskUserQuestion answer and re-resolved at every use (see "user authority" below)

Lifetime: `tick` (run by ops_watch every cycle, or by hand) resumes every owner whose session is idle or gone while the
goal is not done and work is due (an actionable task, a due resume, or no proof for PROOF_S). Resume is
`claude --bg --resume <session> <resume prompt>` (keeps context; Claude compacts as needed); a transcript larger than
fresh_bytes, or a missing one, starts a fresh generation from the state file instead. Bounded: at most
max_launches_per_hour, at least min_gap_s apart, and after STUCK_LAUNCHES launches in a row with no new proof the
owner is marked stuck and tick stops relaunching it until main or the owner records progress (an ops alert says so).

Inside the owner: the Stop hook (`owner_rt.py stop`) refuses to let an owner session end while any task is actionable
(not blocked with a help request, not done), or without a checkpoint newer than CHECKPOINT_S. A bounded gate only
stops careless exits; the tick provides the lifetime. Bounded per session and per actionable-task signature, never on
a session that is not a registered owner, fails open on every internal error.

Tasks (`task add`, by main or the user through main) queue in the inbox. Each moves
  queued > planned (an AC file with AC-n lines, each followed by a `Verify by:` line, and at least one NEG line)
         > converged (a reviewer agent id with verdict ACCEPT) > building > verifying > done (evidence)
  any open state > blocked (a help request: what the owner needs; it keeps working on every other task) > back.
Review-loop breaker: a REJECT round is recorded on a planned task; after LOOP_ROUNDS rejected rounds the task is in a
loop and accepts no further review round until the owner records a redesign (new AC file), an escalation (a rung
note), or parks it (blocked with a ticket).

Proof (`beat`): evidence must resolve: commit:<sha> exists in the owner's cwd repository, or wal:<id> exists in a WAL
of the owner's session. A beat with nothing that resolves is refused.

Threat model as caller_identity.py: these files are owned by the same user; the checks stop a careless or
shortcut-taking agent, not a determined same-user forger. The harness never writes Claude's workspace trust: a launch in
an untrusted directory fails, is logged and alerts. Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

PROOF_S = 30 * 60
CHECKPOINT_S = 15 * 60
LOOP_ROUNDS = 2
STUCK_LAUNCHES = 3
MAX_STOP_BLOCKS_PER_SIG = 3
MAX_STOP_BLOCKS_PER_SESSION = 40
MAX_FILE = 1 << 20
MAX_INBOX = 4 << 20
TEXT_MAX = 600
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TASK_RE = re.compile(r"^t[0-9]{1,5}$")
AGENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
WAL_ID_RE = re.compile(r"^w[0-9a-f]{11}$")
SESSION_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")
TICKET_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9-]{0,62})?#[1-9][0-9]{0,9}$")
SOURCE_RE = re.compile(r"^(user|answer|queue|ticket|wal|file|inferred|pasted):\S")
OPEN = ("queued", "planned", "converged", "building", "verifying")
STATES = OPEN + ("blocked", "done", "dropped")
NEXT = {"queued": ("planned", "blocked", "dropped"),
        "planned": ("converged", "blocked", "dropped"),
        "converged": ("building", "blocked", "dropped"),
        "building": ("verifying", "blocked", "dropped"),
        "verifying": ("done", "building", "blocked", "dropped"),
        "blocked": OPEN + ("dropped",),
        "done": (), "dropped": ()}
DEFAULT_RUNTIME = {"enabled": False, "permission_mode": "auto", "max_launches_per_hour": 4, "min_gap_s": 300,
                   "fresh_bytes": 8_000_000, "model": ""}
# Brakes an agent-writable runtime.json cannot loosen (red-team r1 M1).
BRAKES = {"max_launches_per_hour": (1, 6), "min_gap_s": (120, 86400), "fresh_bytes": (200_000, 50_000_000)}
# Owners run Opus or Sonnet; the top rungs (Fable/Astra) are never launched by the tick (CLAUDE.md, r1 M2).
MODEL_RE = re.compile(r"^(?:|opus|sonnet|claude-(?:opus|sonnet)-[0-9][0-9a-z.-]{0,30})$")
CLAUDE_DIRS = ("~/.local/bin", "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
PERMISSION_MODES = ("auto", "acceptEdits", "default", "dontAsk")  # runtime.json; bypass only by grant
SCRIPT = "python3 ~/.claude/hooks/owner_rt.py"


def script_cmd() -> str:
    """The command an owner session must run: the installed path, or this file when it runs from elsewhere (a
    checkout), prefixed with AH_HOME when this process uses a non-default home, so the owner writes the same state."""
    here = Path(__file__).resolve()
    base = SCRIPT if here == (Path.home() / ".claude" / "hooks" / "owner_rt.py").resolve() else f"python3 {here}"
    ah_home = os.environ.get("AH_HOME")
    return f"AH_HOME={ah_home} {base}" if ah_home and Path(ah_home) != Path.home() else base


class OwnerError(ValueError):
    pass


# ------------------------------------------------------------------ paths and safe I/O

def home_dir() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def owners_root(home: Path) -> Path:
    return home / ".agent-harness" / "owners"


def goal_dir(home: Path, goal: str) -> Path:
    if not ID_RE.match(goal or ""):
        raise OwnerError(f"bad goal id {goal!r}")
    return owners_root(home) / goal


def _no_links(path: Path, root: Path) -> None:
    p = Path(path)
    while True:
        if os.path.islink(p):
            raise OwnerError(f"refusing symlinked path {p}")
        if p == root or p.parent == p:
            return
        p = p.parent


def _ensure_dir(path: Path, home: Path) -> None:
    root = home / ".agent-harness"
    _no_links(path, root)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _no_links(path, root)


def _read(path: Path, cap: int = MAX_FILE) -> bytes:
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(cap + 1)
    if len(data) > cap:
        raise OwnerError(f"{path.name} is larger than {cap} bytes")
    return data


def _atomic(path: Path, obj) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _append(path: Path, row: dict) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "a") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


@contextlib.contextmanager
def locked(home: Path, goal: str):
    d = goal_dir(home, goal)
    _ensure_dir(d, home)
    fd = os.open(str(d / ".lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield d
    finally:
        os.close(fd)


def clean(text, cap: int = TEXT_MAX) -> str:
    s = " ".join(str(text or "").split())
    try:
        import redact  # noqa: PLC0415 - installed beside this file
        s = redact.redact(s) if hasattr(redact, "redact") else s
    except Exception:  # noqa: BLE001
        pass
    return s[:cap]


def now_iso(ts=None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if ts is None else ts))


# ------------------------------------------------------------------ ledger + runtime config

def mission_goals(home: Path) -> dict:
    """{goal id: goal} from goals.json; {} when there is none. A tampered or unreadable ledger raises."""
    path = home / ".agent-harness" / "mission" / "goals.json"
    if not path.exists():
        return {}
    data = json.loads(_read(path).decode("utf-8"))
    goals = data.get("goals") if isinstance(data, dict) else None
    if not isinstance(goals, list):
        raise OwnerError("goals.json has no goals list")
    return {g["id"]: g for g in goals if isinstance(g, dict) and isinstance(g.get("id"), str)}


def goal_done(goal: dict) -> bool:
    """Done only by the ledger: status done or retired, or a lifecycle `done` block (goodqa#15952: the user's words)."""
    if not isinstance(goal, dict):
        return False
    if goal.get("status") in ("done", "retired"):
        return True
    lc = goal.get("lifecycle")
    return isinstance(lc, dict) and lc.get("state") == "done" and isinstance(lc.get("done"), dict)


def runtime(home: Path) -> dict:
    cfg = dict(DEFAULT_RUNTIME)
    path = owners_root(home) / "runtime.json"
    try:
        data = json.loads(_read(path, 65536).decode("utf-8"))
    except FileNotFoundError:
        return cfg
    except (OSError, ValueError, OwnerError):
        cfg["error"] = "runtime.json unreadable"
        return cfg
    if isinstance(data, dict):
        for k, default in DEFAULT_RUNTIME.items():
            if type(data.get(k)) is type(default):  # exact type: a bool is never read as a number or back
                cfg[k] = data[k]
    for k, (lo, hi) in BRAKES.items():
        cfg[k] = min(max(int(cfg[k]), lo), hi)
    if not MODEL_RE.match(cfg["model"]):
        cfg["model"] = ""
    if cfg["permission_mode"] not in PERMISSION_MODES:
        cfg["permission_mode"] = "auto"
        if isinstance(data, dict) and data.get("permission_mode") == "bypassPermissions":
            cfg["note"] = ("bypassPermissions never comes from runtime.json: only a grant bound to the user's answer "
                           f"({SCRIPT} grant-bypass)")
    cfg["claude"] = claude_bin()
    return cfg


# ------------------------------------------------------------------ user authority (receipt v6 F1)
# The runtime never reads authority out of the user's prose: every heuristic over free text (receipts v2-v6) found a
# new way to misread it. Two decisions need the user: running owners with bypassPermissions, and parking a goal in the
# drive loop. Each is the user's answer to an AskUserQuestion whose question and option label this module generates
# from the decision's own scope. An answer counts only when the transcript's structured answer
# (toolUseResult.answers) keys exactly that question with exactly that label, from a single-question, single-choice
# AskUserQuestion of the main conversation (command_guard.resolve_user_source; no excerpt, no prose). Main records
# the decision with a main-only command; every use re-resolves the answer, so the record file alone grants nothing.
# No grant: the configured mode (auto by default). No park record: the goal is not parked.

AUTH_FILE = "authority.json"
ANSWER_RE = re.compile(r"^answer:([A-Za-z0-9._-]{1,80})/([0-9a-fA-F-]{8,64})$")
DATE_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)$")
BYPASS_LABEL = "Allow bypassPermissions"
BYPASS_MAX_H = 168
PARK_MAX_DAYS = 30
ANSWER_MAX_AGE_S = 24 * 3600


def bypass_question(scope: str, hours: int) -> str:
    who = "every owner_rt owner" if scope == "*" else f"the owner_rt owner of goal {scope}"
    return (f"Run {who} with --permission-mode bypassPermissions (no permission prompts at all) for the next "
            f"{int(hours)} hours?")


def park_question(goal: str, until: str) -> str:
    return f"Park goal {goal} in the drive loop until {until} (no required actions for it until then)?"


def park_label(goal: str, until: str) -> str:
    return f"Park {goal} until {until}"


def bypass_options(scope: str, hours: int) -> list:
    """The exact options (label and description) the grant question must offer (receipt v7 F3)."""
    who = "every owner" if scope == "*" else f"the owner of {scope}"
    return [{"label": BYPASS_LABEL,
             "description": f"{who} runs with no permission prompts for {int(hours)} hours from this answer; the "
                            "runtime stops any such session when the window ends or the grant is revoked"},
            {"label": "No bypass: keep the configured mode",
             "description": "owners keep the configured permission mode (auto by default)"}]


def park_options(goal: str, until: str) -> list:
    return [{"label": park_label(goal, until),
             "description": f"the drive loop shows no required actions for {goal} through {until} (UTC)"},
            {"label": f"Keep {goal} active", "description": f"the drive loop keeps requiring actions for {goal}"}]


def _answer_format(answer) -> None:
    if not isinstance(answer, str) or not ANSWER_RE.match(answer):
        raise OwnerError("--answer must be exactly answer:<session>/<uuid>: the user's AskUserQuestion reply "
                         "(`ah user-msg --recent 3` prints it); a user: turn, an excerpt or any prose never counts")


_ANSWER_CACHE = {}


def _resolve_answer(answer: str) -> dict:
    """command_guard.resolve_user_source, read from the account home pinned from the password database: never $HOME,
    and never AH_HOME (receipt v7 F4: a relocated harness home cannot relocate the record of the user's answers).
    Cached per process by the transcript's size and mtime (receipt v7 F5), so one tick or one hook call resolves each
    answer once; a changed transcript is read again."""
    import command_guard  # noqa: PLC0415 - installed beside this file
    import provenance  # noqa: PLC0415
    session = _answer_session(answer)
    try:
        st = provenance.find_transcript(session, Path(command_guard._pinned_home()) / ".claude").stat()  # noqa: SLF001
        key = (answer, st.st_size, st.st_mtime_ns)
    except Exception:  # noqa: BLE001 - the resolver below reports why
        key = None
    if key is not None and key in _ANSWER_CACHE:
        got = _ANSWER_CACHE[key]
        if isinstance(got, ValueError):
            raise ValueError(str(got))
        return dict(got)
    # now=inf: neither the age nor the future-date check applies here; answer_at applies both to its own clock, so a
    # cached result never carries a stale age decision. A refusal (ValueError) depends only on the transcript bytes and
    # is cached too, so a bad row does not re-read a large transcript every tick; any other error is not cached.
    try:
        got = command_guard.resolve_user_source(answer, now=float("inf"))
    except ValueError as exc:
        got = exc
    if key is not None:
        if len(_ANSWER_CACHE) > 256:
            _ANSWER_CACHE.clear()
        _ANSWER_CACHE[key] = got
    if isinstance(got, ValueError):
        raise ValueError(str(got))
    return dict(got)


def answer_at(home: Path, answer: str, question: str, options: list, now: float, max_age=None) -> float:
    """The time of the user's answer when `answer` (answer:<session>/<uuid>) is a single-question, single-choice
    AskUserQuestion reply of the main conversation that asked exactly `question` with exactly `options` (labels and
    descriptions, receipt v7 F3) and whose structured answer chose the first option; else OwnerError. Whole-string
    equality only: nothing in the user's words is parsed."""
    _answer_format(answer)
    try:
        got = _resolve_answer(answer)
    except ValueError as exc:
        raise OwnerError("the answer does not resolve: " + clean(str(exc), 200)) from None
    except Exception as exc:  # noqa: BLE001 - anything that cannot prove the answer refuses
        raise OwnerError("the answer does not resolve: " + clean(type(exc).__name__, 60)) from None
    if got.get("question") != question:
        raise OwnerError("the user answered a different question; ask exactly: " + question)
    if got.get("options") != options:
        raise OwnerError("the question did not offer exactly the generated options (labels and descriptions); "
                         "ask it with `owner_rt.py ask-text`")
    if got.get("text") != options[0]["label"] or not got.get("predefined"):
        raise OwnerError(f"the user did not choose the option {options[0]['label']!r}")
    at = float(got["at"])
    if max_age is not None and now - at > max_age:
        raise OwnerError(f"the answer is older than {int(max_age // 3600)} hours; ask again")
    if at > now + 300:
        raise OwnerError("the answer is dated in the future")
    return at


def _answer_session(answer: str) -> str:
    m = ANSWER_RE.match(answer or "")
    return m.group(1).lower() if m else ""


def _mission_answer(home: Path, answer: str) -> None:
    """Recording a decision needs the answer to come from the mission session's main conversation."""
    _answer_format(answer)
    mission = ""
    with contextlib.suppress(Exception):
        import mission_coverage  # noqa: PLC0415
        mission = (mission_coverage.mission_session_of(home) or "").lower()
    if not mission:
        raise OwnerError("no mission session is recorded, so no answer can be bound to main")
    if _answer_session(answer) != mission:
        raise OwnerError("the answer is not from the mission session's main conversation")


def load_authority(home: Path) -> dict:
    """{"bypass": [...], "parks": [...]}; a missing or malformed file holds nothing (fail closed)."""
    out = {"bypass": [], "parks": []}
    try:
        data = json.loads(_read(owners_root(home) / AUTH_FILE, 262144).decode("utf-8"))
    except (OSError, ValueError, OwnerError):
        return out
    if isinstance(data, dict):
        for k in out:
            if isinstance(data.get(k), list):
                out[k] = [r for r in data[k] if isinstance(r, dict)][:200]
    return out


@contextlib.contextmanager
def _authority_lock(home: Path):
    root = owners_root(home)
    _ensure_dir(root, home)
    fd = os.open(str(root / ".authority.lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield root
    finally:
        os.close(fd)


def _check_scope(home: Path, scope: str) -> None:
    if scope != "*" and scope not in mission_goals(home):
        raise OwnerError("--scope must be * (every owner) or a goal id in goals.json")


def _check_hours(hours) -> int:
    if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= BYPASS_MAX_H:
        raise OwnerError(f"--hours must be a whole number from 1 to {BYPASS_MAX_H}")
    return hours


def until_ts(until: str) -> float:
    """End of the named UTC day."""
    import datetime as dt  # noqa: PLC0415
    m = DATE_RE.match(until or "")
    if not m:
        raise OwnerError("--until must be a date YYYY-MM-DD")
    try:
        day = dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=dt.timezone.utc)
    except ValueError:
        raise OwnerError("--until is not a real date") from None
    return (day + dt.timedelta(days=1)).timestamp()


def grant_bypass(home: Path, scope: str, hours: int, answer: str, now=None) -> dict:
    now = time.time() if now is None else now
    _check_scope(home, scope)
    hours = _check_hours(hours)
    _mission_answer(home, answer)
    at = answer_at(home, answer, bypass_question(scope, hours), bypass_options(scope, hours), now, ANSWER_MAX_AGE_S)
    if at + hours * 3600 <= now:
        raise OwnerError("that answer's window has already ended")
    row = {"scope": scope, "hours": hours, "answer": answer, "answered_at": now_iso(at),
           "expires_at": now_iso(at + hours * 3600), "recorded_at": now_iso(now)}
    with _authority_lock(home):
        data = load_authority(home)
        data["bypass"] = [r for r in data["bypass"] if r.get("scope") != scope] + [row]
        _atomic(owners_root(home) / AUTH_FILE, data)
    return row


def revoke_bypass(home: Path, scope: str) -> dict:
    with _authority_lock(home):
        data = load_authority(home)
        before = len(data["bypass"])
        data["bypass"] = [r for r in data["bypass"] if r.get("scope") != scope]
        _atomic(owners_root(home) / AUTH_FILE, data)
    return {"scope": scope, "removed": before - len(data["bypass"])}


def bypass_grant(home: Path, goal: str, now=None):
    """The grant that lets this goal's owner run with bypassPermissions now, or None. Each candidate is re-resolved:
    its answer must still key the exact question for the grant's own scope and hours, and the window (from the
    answer's own time) must still be open."""
    now = time.time() if now is None else now
    for row in load_authority(home)["bypass"]:
        if row.get("scope") not in ("*", goal):
            continue
        try:
            hours = _check_hours(row.get("hours"))
            _mission_answer(home, str(row.get("answer") or ""))  # at use too: a row citing another session is void
            at = answer_at(home, str(row.get("answer") or ""), bypass_question(row["scope"], hours),
                           bypass_options(row["scope"], hours), now)
        except OwnerError:
            continue
        if at <= now + 300 and now < at + hours * 3600:
            return dict(row, expires_ts=at + hours * 3600)
    return None


def park_goal(home: Path, goal: str, until: str, answer: str, now=None) -> dict:
    now = time.time() if now is None else now
    if goal not in mission_goals(home):
        raise OwnerError(f"goal {goal} is not in goals.json")
    end = until_ts(until)
    _mission_answer(home, answer)
    at = answer_at(home, answer, park_question(goal, until), park_options(goal, until), now, ANSWER_MAX_AGE_S)
    if end <= now:
        raise OwnerError("--until is in the past")
    if end - at > PARK_MAX_DAYS * 86400:
        raise OwnerError(f"a park lasts at most {PARK_MAX_DAYS} days from the user's answer")
    row = {"goal": goal, "until": until, "answer": answer, "answered_at": now_iso(at), "recorded_at": now_iso(now)}
    with _authority_lock(home):
        data = load_authority(home)
        data["parks"] = [r for r in data["parks"] if r.get("goal") != goal] + [row]
        _atomic(owners_root(home) / AUTH_FILE, data)
    return row


def unpark_goal(home: Path, goal: str) -> dict:
    with _authority_lock(home):
        data = load_authority(home)
        before = len(data["parks"])
        data["parks"] = [r for r in data["parks"] if r.get("goal") != goal]
        _atomic(owners_root(home) / AUTH_FILE, data)
    return {"goal": goal, "removed": before - len(data["parks"])}


def active_park(home: Path, goal: str, now=None):
    """The park record for this goal when its answer re-resolves to the exact park question and label and the park
    has not ended; else None."""
    now = time.time() if now is None else now
    for row in load_authority(home)["parks"]:
        if row.get("goal") != goal:
            continue
        try:
            until = str(row.get("until") or "")
            end = until_ts(until)
            _mission_answer(home, str(row.get("answer") or ""))  # at use too
            at = answer_at(home, str(row.get("answer") or ""), park_question(goal, until), park_options(goal, until),
                           now)
        except OwnerError:
            continue
        if now < end and end - at <= PARK_MAX_DAYS * 86400:
            return dict(row, until_ts=end)
    return None


def ask_text(kind: str, scope: str = "", hours: int = 0, goal: str = "", until: str = "") -> dict:
    """The exact AskUserQuestion main must ask (one question, single choice) for a grant or a park."""
    if kind == "bypass":
        q, options = bypass_question(scope, _check_hours(hours)), bypass_options(scope, hours)
    else:
        until_ts(until)
        q, options = park_question(goal, until), park_options(goal, until)
    return {"question": q, "options": options, "multiSelect": False,
            "rule": "ask this one question alone, word for word, with exactly these two options (label and "
                    "description); only the first option grants"}


def claude_bin() -> str:
    """The absolute `claude` path from fixed install locations, never from a data file (r1 M1). launchd gives ops_watch
    no PATH, so ~/.local/bin is searched explicitly (r1 m5)."""
    import shutil  # noqa: PLC0415
    found = shutil.which("claude", path=os.pathsep.join(os.path.expanduser(d) for d in CLAUDE_DIRS))
    return found or ""


# ------------------------------------------------------------------ state + inbox

def load_state(home: Path, goal: str) -> dict:
    path = goal_dir(home, goal) / "state.json"
    _no_links(path, home / ".agent-harness")
    data = json.loads(_read(path).decode("utf-8"))
    if not isinstance(data, dict) or data.get("goal") != goal:
        raise OwnerError(f"state.json for {goal} is malformed")
    return data


def save_state(home: Path, goal: str, state: dict) -> None:
    _atomic(goal_dir(home, goal) / "state.json", state)


def inbox_rows(home: Path, goal: str) -> list:
    path = goal_dir(home, goal) / "inbox.jsonl"
    try:
        raw = _read(path, MAX_INBOX).decode("utf-8", "replace")
    except FileNotFoundError:
        return []
    rows = []
    for line in raw.splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict):
            rows.append(r)
    return rows


def tasks(rows) -> dict:
    """Fold inbox rows into {task id: task}. Rows are append-only; the fold is the only reader."""
    out = {}
    for r in rows:
        tid = r.get("task")
        if not isinstance(tid, str) or not TASK_RE.match(tid):
            continue
        if r.get("kind") == "task":
            out[tid] = {"id": tid, "text": r.get("text", ""), "source": r.get("source", ""), "state": "queued",
                        "at": r.get("at"), "updated": r.get("at"), "rejects": 0, "loop": False, "help": "",
                        "ac_file": "", "reviewer": "", "evidence": [], "resume_to": "", "rounds": []}
            continue
        t = out.get(tid)
        if t is None:
            continue
        kind = r.get("kind")
        t["updated"] = r.get("at")
        if kind == "move":
            if t["state"] != "blocked" and r.get("to") == "blocked":
                t["resume_to"] = t["state"]
            t["state"] = r.get("to")
            if r.get("to") == "blocked":
                t["help"] = r.get("help", "")
            for k in ("ac_file", "reviewer"):
                if r.get(k):
                    t[k] = r[k]
            if r.get("evidence"):
                t["evidence"] = list(r["evidence"])
        elif kind == "round":
            t["rounds"].append({"verdict": r.get("verdict"), "reviewer": r.get("reviewer"), "at": r.get("at")})
            if r.get("verdict") != "ACCEPT":
                t["rejects"] += 1
                t["loop"] = t["rejects"] >= LOOP_ROUNDS
        elif kind == "break":
            t["rejects"], t["loop"] = 0, False
            t["break"] = {"how": r.get("how"), "ref": r.get("ref"), "at": r.get("at")}
            if r.get("ac_file"):
                t["ac_file"] = r["ac_file"]
    return out


def actionable(task_map: dict) -> list:
    return sorted((t for t in task_map.values() if t["state"] in OPEN), key=lambda t: t["id"])


def ac_file_problem(path: str) -> str:
    """'' when the file holds at least one AC-n line each followed (before the next AC) by a `Verify by:` line, and at
    least one NEG line; else the reason."""
    try:
        import stat as _stat  # noqa: PLC0415
        fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            if not _stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return "AC file must be a regular file"
            text = fh.read(200_001).decode("utf-8", "replace")
        if len(text) > 200_000:
            return "AC file is larger than 200 KB"
    except OSError as exc:
        return f"AC file unreadable: {exc.__class__.__name__}"
    acs = list(re.finditer(r"(?m)^\W*(AC-\d+)\b", text))
    if not acs:
        return "AC file has no AC-n line"
    for i, m in enumerate(acs):
        end = acs[i + 1].start() if i + 1 < len(acs) else len(text)
        block = text[m.start():end]
        if not re.search(r"(?i)verify by:\s*\S", block):
            return f"{m.group(1)} has no `Verify by:` line"
    if not re.search(r"(?m)^\W*NEG-\d+", text):
        return "AC file has no NEG-n line"
    return ""


def init_owner(home: Path, goal: str, cwd: str, source: str, model: str = "", ticket: str = "") -> dict:
    goals = mission_goals(home)
    if goal not in goals:
        raise OwnerError(f"goal {goal} is not in goals.json; add it with mission_coverage.py add first")
    if not SOURCE_RE.match(source or ""):
        raise OwnerError("--source must be user:/answer:/queue:/ticket:/wal:/file:/inferred:")
    if not MODEL_RE.match(model or ""):
        raise OwnerError("--model must be opus, sonnet or a claude-opus/claude-sonnet id; the top rungs need the "
                         "user's named approval and are never launched by the tick")
    work = Path(cwd).expanduser()
    if not work.is_dir():
        raise OwnerError(f"cwd {cwd} is not a directory")
    # delta D1: the workspace identifies the owner session, so it must be dedicated to this one owner
    if any(_same_dir(work, p) for p in (home, Path.home(), Path("/"))):
        raise OwnerError("the owner workspace must be a dedicated directory, not a home or root directory")
    for g in owner_goals(home):
        try:
            other = load_state(home, g).get("cwd") if g != goal else None
        except Exception:  # noqa: BLE001
            other = None
        if _same_dir(work, other):
            raise OwnerError(f"workspace {work} already belongs to owner {g}; give each owner its own")
    with locked(home, goal) as d:
        if (d / "state.json").exists():
            raise OwnerError(f"owner for {goal} already exists ({SCRIPT} show --goal {goal})")
        state = {"schema": 1, "goal": goal, "title": clean(goals[goal].get("title"), 120),
                 "ticket": clean(ticket or goals[goal].get("ticket"), 40), "cwd": str(work.resolve()),
                 "model": clean(model, 40), "source": clean(source, 300), "created_at": now_iso(),
                 "generation": 0, "session_id": "", "bg_id": "", "launches": [], "last_beat": {}, "checkpoint": {},
                 "resume": {}, "stuck": False, "no_progress_launches": 0, "paused": {}}
        save_state(home, goal, state)
        return state


def add_task(home: Path, goal: str, text: str, source: str, by: str = "main") -> dict:
    if not SOURCE_RE.match(source or ""):
        raise OwnerError("--source is required (user:/answer:/queue:/ticket:/wal:/file:/inferred:)")
    if not clean(text):
        raise OwnerError("task text is empty")
    with locked(home, goal):
        load_state(home, goal)
        n = len([r for r in inbox_rows(home, goal) if r.get("kind") == "task"]) + 1
        row = {"kind": "task", "task": f"t{n}", "at": now_iso(), "by": clean(by, 64), "text": clean(text),
               "source": clean(source, 300)}
        _append(goal_dir(home, goal) / "inbox.jsonl", row)
        return row


def move_task(home: Path, goal: str, task: str, to: str, *, ac_file: str = "", reviewer: str = "", verdict: str = "",
              help_text: str = "", evidence=None, source: str = "") -> dict:
    if to not in STATES:
        raise OwnerError(f"unknown state {to}")
    with locked(home, goal):
        load_state(home, goal)
        tmap = tasks(inbox_rows(home, goal))
        t = tmap.get(task)
        if t is None:
            raise OwnerError(f"no task {task} in {goal}")
        allowed = NEXT.get(t["state"], ())
        if t["state"] == "blocked":
            allowed = (t.get("resume_to") or "queued", "dropped")
        if to not in allowed:
            raise OwnerError(f"{task} is {t['state']}; it may move to {', '.join(allowed) or 'nothing'}, not {to}")
        row = {"kind": "move", "task": task, "to": to, "at": now_iso(), "from": t["state"]}
        if to == "planned" and not (t["state"] == "blocked" and t.get("ac_file") and not ac_file):
            problem = ac_file_problem(ac_file)
            if problem:
                raise OwnerError(problem)
            row["ac_file"] = str(Path(ac_file).resolve())
        if to == "converged":
            if t["loop"]:
                raise OwnerError(f"{task} is in a review loop ({t['rejects']} rejected rounds): record a redesign, "
                                 f"an escalation or a park first ({SCRIPT} task break)")
            if verdict != "ACCEPT" or not AGENT_RE.match(reviewer or ""):
                raise OwnerError("converged needs --reviewer <agent id> and --verdict ACCEPT")
            last = t["rounds"][-1] if t["rounds"] else None
            if not last or last.get("verdict") != "ACCEPT" or last.get("reviewer") != reviewer:
                raise OwnerError(f"record the reviewer's ACCEPT round first (`task round --task {task} --reviewer "
                                 f"{reviewer} --verdict ACCEPT`); the latest round must be that ACCEPT")
            row["reviewer"] = reviewer
        if to == "blocked":
            if not clean(help_text):
                raise OwnerError("blocked needs --help: what you need, so main can unblock it")
            row["help"] = clean(help_text)
        if to == "done":
            since = parse_ts(t.get("at"))
            ev = [e for e in (evidence or []) if evidence_ts(home, goal, e) > since]
            if not ev:
                raise OwnerError("done needs --evidence made after the task was queued (commit:<sha> in the owner "
                                 "repo, or wal:<id> of a check, result, deploy or commit row)")
            row["evidence"] = ev
        if to == "dropped":
            if not SOURCE_RE.match(source or "") or source.startswith("inferred:"):
                raise OwnerError("dropping a task needs a --source that is not inferred:")
            row["source"] = clean(source, 300)
        _append(goal_dir(home, goal) / "inbox.jsonl", row)
        return row


def review_round(home: Path, goal: str, task: str, reviewer: str, verdict: str) -> dict:
    if verdict not in ("ACCEPT", "REJECT", "REVISE"):
        raise OwnerError("--verdict must be ACCEPT, REJECT or REVISE")
    if not AGENT_RE.match(reviewer or ""):
        raise OwnerError("--reviewer must be the reviewer's agent id")
    with locked(home, goal):
        load_state(home, goal)
        t = tasks(inbox_rows(home, goal)).get(task)
        if t is None or t["state"] != "planned":
            raise OwnerError(f"{task} must be planned to take a review round")
        if t["loop"]:
            raise OwnerError(f"{task} is in a review loop ({t['rejects']} rejected rounds); no more rounds until "
                             f"`{SCRIPT} task break --goal {goal} --task {task} --how redesign|escalate|park`")
        row = {"kind": "round", "task": task, "reviewer": reviewer, "verdict": verdict, "at": now_iso()}
        _append(goal_dir(home, goal) / "inbox.jsonl", row)
        return row


def break_loop(home: Path, goal: str, task: str, how: str, ref: str, ac_file: str = "") -> dict:
    with locked(home, goal):
        load_state(home, goal)
        t = tasks(inbox_rows(home, goal)).get(task)
        if t is None:
            raise OwnerError(f"no task {task}")
        row = {"kind": "break", "task": task, "how": how, "at": now_iso()}
        if how == "redesign":
            problem = ac_file_problem(ac_file)
            if problem:
                raise OwnerError("a redesign needs a new AC file: " + problem)
            row["ac_file"], row["ref"] = str(Path(ac_file).resolve()), clean(ref, 200)
        elif how == "escalate":
            if not clean(ref):
                raise OwnerError("an escalation needs --ref naming the next rung and its agent")
            row["ref"] = clean(ref, 200)
        elif how == "park":
            if not TICKET_RE.match(ref or ""):
                raise OwnerError("parking needs --ref <ticket like goodqa#123>")
            row["ref"] = ref
        else:
            raise OwnerError("--how must be redesign, escalate or park")
        _append(goal_dir(home, goal) / "inbox.jsonl", row)
        if how == "park" and t["state"] in OPEN:
            _append(goal_dir(home, goal) / "inbox.jsonl",
                    {"kind": "move", "task": task, "to": "blocked", "from": t["state"], "at": now_iso(),
                     "help": f"parked review loop on {ref}"})
        return row


# ------------------------------------------------------------------ proof

def _session_wal_dirs(home: Path, state: dict) -> list:
    sid = state.get("session_id") or ""
    out = []
    for s in [sid] + [g.get("session_id", "") for g in state.get("launches", [])[-10:]]:
        if s and SESSION_RE.match(s):
            p = home / ".claude" / "wals" / s
            if p not in out:
                out.append(p)
    return out


def evidence_ts(home: Path, goal: str, ev: str, state=None) -> float:
    """When the evidence happened (commit time, or the WAL row's `at`); 0.0 when it does not resolve."""
    try:
        state = state or load_state(home, goal)
    except (OSError, ValueError, OwnerError):
        return 0.0
    kind, _, ref = str(ev or "").partition(":")
    if kind == "commit" and SHA_RE.match(ref):
        try:
            r = subprocess.run(["git", "-C", state["cwd"], "log", "-1", "--format=%ct", f"{ref}^{{commit}}", "--"],
                               capture_output=True, text=True, timeout=10)
            return float(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip().isdigit() else 0.0
        except (OSError, subprocess.SubprocessError):
            return 0.0
    if kind == "wal" and WAL_ID_RE.match(ref):
        needle = (f'"id": "{ref}"'.encode(), f'"id":"{ref}"'.encode())
        for d in _session_wal_dirs(home, state):
            try:
                for f in d.glob("*.jsonl"):
                    for line in _read(f, 64 << 20).splitlines():
                        if needle[0] in line or needle[1] in line:
                            try:
                                rec = json.loads(line)
                            except ValueError:
                                return 0.0
                            if rec.get("event") not in PROOF_EVENTS:
                                return 0.0
                            return parse_ts(rec.get("at"))
            except (OSError, OwnerError):
                continue
    return 0.0


def parse_ts(value) -> float:
    import datetime as dt  # noqa: PLC0415
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def evidence_ok(home: Path, goal: str, ev: str, state=None) -> bool:
    return evidence_ts(home, goal, ev, state) > 0


FIRST_PROOF_WINDOW_S = 2 * 3600
PROOF_EVENTS = ("check", "result", "deploy", "commit")


def beat(home: Path, goal: str, evidence, next_text: str, now=None) -> dict:
    """A proof counts only with evidence that resolves AND happened after the previous proof (or, for the first proof,
    within FIRST_PROOF_WINDOW_S): re-citing old work never resets the clock or clears `stuck`."""
    now = time.time() if now is None else now
    with locked(home, goal):
        state = load_state(home, goal)
        prev_ts = float((state.get("last_beat") or {}).get("ts") or 0.0)
        floor = prev_ts if prev_ts else now - FIRST_PROOF_WINDOW_S
        stamped = {e: evidence_ts(home, goal, e, state) for e in evidence or []}
        good = [e for e, ts in stamped.items() if ts > floor]
        bad = [e for e in stamped if e not in good]
        if not good:
            raise OwnerError("a proof needs new evidence: commit:<sha> in "
                             f"{state['cwd']} or wal:<id> in this owner's WAL, made after the last proof "
                             f"(not new or unresolved: {', '.join(bad) or 'none'})")
        state["last_beat"] = {"at": now_iso(now), "ts": now, "evidence": good, "unresolved": bad,
                              "next": clean(next_text, 300)}
        state["no_progress_launches"], state["stuck"] = 0, False
        save_state(home, goal, state)
        return state["last_beat"]


def set_flag(home: Path, goal: str, flag: str, source: str) -> dict:
    """unstick (clear `stuck` and the no-progress count), pause (tick leaves the owner alone) or unpause. Each needs
    a source; pause also refuses inferred: (a pause stops a product, so it needs a decision someone made)."""
    if not SOURCE_RE.match(source or ""):
        raise OwnerError("--source is required")
    if flag == "pause" and source.startswith("inferred:"):
        raise OwnerError("pausing an owner needs a user:, answer:, queue:, ticket: or wal: source, not inferred:")
    with locked(home, goal):
        state = load_state(home, goal)
        if flag == "unstick":
            state["stuck"], state["no_progress_launches"] = False, 0
        elif flag == "pause":
            state["paused"] = {"at": now_iso(), "source": clean(source, 300)}
        elif flag == "unpause":
            state["paused"] = {}
        else:
            raise OwnerError(f"unknown flag {flag}")
        state.setdefault("flags", []).append({"flag": flag, "at": now_iso(), "source": clean(source, 300)})
        state["flags"] = state["flags"][-50:]
        save_state(home, goal, state)
        return {"goal": goal, "flag": flag, "stuck": state["stuck"], "paused": state["paused"]}


def checkpoint(home: Path, goal: str, text: str) -> dict:
    if not clean(text):
        raise OwnerError("checkpoint text is empty: say where things stand and the next step for each open task")
    with locked(home, goal):
        state = load_state(home, goal)
        state["checkpoint"] = {"at": now_iso(), "ts": time.time(), "text": clean(text, 2000)}
        save_state(home, goal, state)
        return state["checkpoint"]


def proof_age(state: dict, now: float) -> float:
    ts = (state.get("last_beat") or {}).get("ts")
    return now - float(ts) if isinstance(ts, (int, float)) else float("inf")


# ------------------------------------------------------------------ prompts

def owner_prompt(home: Path, goal: str, resume: bool = False) -> str:
    state = load_state(home, goal)
    tmap = tasks(inbox_rows(home, goal))
    open_lines = [f"  {t['id']} [{t['state']}{' LOOP' if t['loop'] else ''}] {t['text'][:200]}"
                  + (f" (blocked: {t['help'][:120]})" if t["state"] == "blocked" else "")
                  for t in sorted(tmap.values(), key=lambda t: t["id"]) if t["state"] not in ("done", "dropped")]
    cp = (state.get("checkpoint") or {}).get("text", "")
    g = f"--goal {goal}"
    cmd = script_cmd()
    head = ("OWNER RESUME (owner_rt tick, not typed by the user). " if resume else
            "OWNER CHARTER (owner_rt, written by the harness, not typed by the user). ")
    lines = [
        head + f"You are the long-lived owner of goal `{goal}`: {state.get('title', '')} "
        f"(ticket {state.get('ticket') or 'none'}). You own its delivery until the user declares it done; tasks come "
        f"and go, you stay.",
        f"State: {goal_dir(home, goal)}/state.json; inbox: `{cmd} show {g}`.",
        "Open tasks:" if open_lines else "Open tasks: none queued. Find the next step toward live from the ticket and "
        "the ledger, add it as a task, and work it.",
        *open_lines,
        f"Last checkpoint: {cp[:800]}" if cp else "No checkpoint yet.",
        f"Inbox head: {inbox_head(home, goal)} (generation {int(state.get('generation', 0))}). First action of this run: "
        "record a WAL intent with wal_note.py that cites this inbox head and the task you take next.",
        "How you work, every time:",
        f"  1. Plan each task; write an AC file (AC-n lines each with `Verify by:`, plus NEG-n cases); "
        f"`{cmd} task move {g} --task tN --to planned --ac-file F`.",
        f"  2. Get adversarial convergence before building: spawn a reviewer one rung above the builder; record each "
        f"round with `{cmd} task round {g} --task tN --reviewer <agent id> --verdict ACCEPT|REJECT`; then "
        f"`{cmd} task move {g} --task tN --to converged --reviewer <id> --verdict ACCEPT`. Two rejected rounds = a "
        f"loop: `{cmd} task break {g} --task tN --how redesign|escalate|park`.",
        "  3. Delegate building, fixing and testing to sub-agents; integrate, verify and push each green step.",
        f"  4. Prove progress at least every 30 minutes: `{cmd} beat {g} --evidence commit:<sha> "
        f"--evidence wal:<id> --next \"...\"`. Post checkpoints to the ticket.",
        f"  5. A blocked facet is a help request, never a pause: `{cmd} task move {g} --task tN --to blocked "
        f"--need \"what you need\"`, then keep working every other task.",
        f"  6. Before you end a turn: `{cmd} checkpoint {g} --text \"...\"`. The Stop hook refuses an end while "
        "any task is actionable. You will be resumed automatically.",
        "Follow CLAUDE.md, the repo rules and every guard. Done means deployed to live and tested live; only the user "
        "declares the goal done.",
    ]
    return "\n".join(lines)


def inbox_head(home: Path, goal: str) -> str:
    """sha256 prefix of the inbox file: which tasks this run was given."""
    try:
        return hashlib.sha256(_read(goal_dir(home, goal) / "inbox.jsonl", MAX_INBOX)).hexdigest()[:12]
    except (OSError, OwnerError):
        return "empty"


# ------------------------------------------------------------------ tick (lifetime)

def _run(argv, timeout=60, cwd=None):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def bg_sessions(cfg: dict, runner=_run) -> list:
    """Every session `claude agents --json --all` lists, validated (receipt v6 F2). Anything but a JSON array of
    valid session records raises: an unreadable listing is never proof that no owner session runs."""
    code, out = runner([cfg["claude"], "agents", "--json", "--all"], 30)
    if code != 0:
        raise OwnerError("claude agents failed: " + clean(out, 200))
    return parse_sessions(out)


def parse_sessions(out) -> list:
    """The listing must start with a JSON array (stdout; the runner appends stderr after it, which is ignored) whose
    every element is a session record. Observed 2026-11-14 (claude agents --json --all, 14 records): each has a
    sessionId, kind, name, cwd and startedAt; a live session has an integer pid and a status; a stopped one has no
    pid key."""
    text = str(out or "").lstrip()
    if not text.startswith("["):
        raise OwnerError("claude agents printed no JSON array; nothing is assumed about running sessions")
    try:
        data, _end = json.JSONDecoder().raw_decode(text)
    except ValueError:
        raise OwnerError("claude agents printed malformed JSON; nothing is assumed about running sessions") from None
    if not isinstance(data, list):
        raise OwnerError("claude agents did not print a list")
    for i, rec in enumerate(data):
        problem = session_problem(rec)
        if problem:
            raise OwnerError(f"claude agents record {i} is invalid ({problem}); nothing is assumed about sessions")
    return data


def session_problem(rec) -> str:
    if not isinstance(rec, dict):
        return "not an object"
    if not isinstance(rec.get("sessionId"), str) or not SESSION_RE.match(rec["sessionId"]):
        return "no valid sessionId"
    for key in ("id", "name", "status", "state", "kind", "cwd"):
        if key in rec and not isinstance(rec[key], str):
            return f"{key} is not text"
    if "pid" in rec:
        pid = rec["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            return "pid is not a positive integer"
        if not isinstance(rec.get("status"), str):
            return "a live session has no status"
    return ""


def stop_idle_sessions(cfg: dict, state: dict, runner=_run, busy_too: bool = False) -> str:
    """Stop every live session of this owner and prove it: '' when none is left, else why not (receipt v3 F3).
    Re-lists right before stopping and stops only sessions still idle (every session with busy_too, for a lapsed
    bypass grant), checks each `claude stop` exit code, then re-lists and requires that no live session of this
    owner remains."""
    try:
        live = owner_sessions(state, bg_sessions(cfg, runner))
    except Exception as exc:  # noqa: BLE001
        return "could not list sessions before stopping: " + clean(str(exc), 120)
    failed = []  # busy_too (a lapsed grant): every session is attempted before anything is reported
    for a in live:
        if not busy_too and not (a.get("status") == "idle" and a.get("state") == "done"):
            return f"session {clean(a.get('id') or a.get('sessionId'), 40)} is working again"
        if not a.get("id"):
            failed.append(f"live session {clean(a.get('sessionId'), 40)} has no id to stop")
        else:
            code, text = runner([cfg["claude"], "stop", str(a["id"])], 30)
            if code != 0:
                failed.append(f"claude stop {clean(a['id'], 20)} failed ({code}): " + clean(text, 120))
        if failed and not busy_too:
            return failed[0]
    if failed:
        return "; ".join(failed)
    try:
        left = owner_sessions(state, bg_sessions(cfg, runner))
    except Exception as exc:  # noqa: BLE001
        return "could not confirm the stop: " + clean(str(exc), 120)
    if left:
        return "still live after stop: " + ", ".join(clean(a.get("id") or a.get("sessionId"), 20) for a in left[:5])
    return ""


def owner_sessions(state: dict, sessions: list) -> list:
    """Live (pid) background sessions of this owner: its recorded session id, or any session named owner-<goal>
    (a launch whose id lookup failed is still found by name)."""
    sid, name = state.get("session_id"), f"owner-{state.get('goal')}"
    return [a for a in sessions if a.get("pid") and ((sid and a.get("sessionId") == sid) or a.get("name") == name)]


def session_status(state: dict, sessions: list) -> str:
    """busy | idle | gone over every live session of this owner. Observed 2026-11-14: a session mid-turn, or whose turn
    ended while a background sub-agent still runs, reads status busy / state working; it reads idle / done only when
    nothing runs. Anything not plainly idle counts as busy, so the tick never stops a working owner."""
    live = owner_sessions(state, sessions)
    if any(not (a.get("status") == "idle" and a.get("state") == "done") for a in live):
        return "busy"
    return "idle" if live else "gone"


def transcript_bytes(home: Path, state: dict) -> int:
    sid = state.get("session_id") or ""
    if not SESSION_RE.match(sid):
        return -1
    config = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    for root in dict.fromkeys((home / ".claude" / "projects", config / "projects")):  # Claude writes to its config dir
        for p in root.glob(f"*/{sid}.jsonl"):
            with contextlib.suppress(OSError):
                return p.stat().st_size
    return -1


def due_reason(home: Path, goal: str, state: dict, now: float) -> str:
    if actionable(tasks(inbox_rows(home, goal))):
        return "actionable tasks"
    due = (state.get("resume") or {}).get("due_ts")
    if isinstance(due, (int, float)) and due <= now:
        return "resume due"
    if proof_age(state, now) > PROOF_S:
        return "no proof in 30 minutes"
    return ""


_UNRESOLVED = object()


def bypass_lapse(home: Path, state: dict, now: float, grant=_UNRESOLVED) -> str:
    """Why the bypass session this owner was launched with has lost its authority ('' when it has not, or when the
    owner was not launched with bypass): its grant expired, was revoked, or its answer no longer resolves. `grant` is
    the caller's one resolution of bypass_grant (receipt v8 F1: one tick never decides on two different answers)."""
    held = state.get("bypass") or {}
    if not held:
        return ""
    if grant is _UNRESOLVED:
        grant = bypass_grant(home, state["goal"], now)
    if grant is not None:
        return ""
    return (f"the bypassPermissions grant for {state['goal']} (answer {clean(held.get('answer'), 120)}, until "
            f"{held.get('expires_at') or '?'}) no longer holds: expired, revoked, or its answer does not resolve")


def end_lapsed_bypass(home: Path, goal: str, state: dict, cfg: dict, sessions, now: float, runner=_run,
                      dry_run: bool = False, grant=_UNRESOLVED):
    """Receipt v7 F1: a session launched with bypassPermissions lives only while a grant covers its goal. When the
    grant lapses, every live session of the owner (busy too) is stopped and the stop is confirmed by a fresh
    listing; a failed or unconfirmed stop is reported every tick until it succeeds, never assumed. None when there is
    nothing to end; else the tick result. Called with the goal lock held."""
    lapse = bypass_lapse(home, state, now, grant)
    if not lapse:
        return None
    if callable(sessions):  # receipt v8 F2: list under the goal lock the caller holds, never before waiting for it
        try:
            sessions = sessions()
        except Exception:  # noqa: BLE001 - reported as unconfirmed below
            sessions = None
    out = {"goal": goal, "reason": lapse}
    if sessions is None:
        out.update(action="bypass-stop-unconfirmed", reason=lapse + "; the session listing is unreadable, so the "
                   "session cannot be stopped or shown stopped")
    elif not owner_sessions(state, sessions):
        out.update(action="bypass-ended", reason=lapse + "; no live session remains")
    elif dry_run:
        out.update(action="bypass-stop", reason=lapse)
        return out
    elif not cfg.get("claude"):
        out.update(action="bypass-stop-failed", reason=lapse + "; no claude binary to stop the session with")
    else:
        try:
            problem = stop_idle_sessions(cfg, state, runner, busy_too=True)
        except Exception as exc:  # noqa: BLE001
            problem = "stop raised " + clean(f"{type(exc).__name__}: {exc}", 120)
        out.update(action="bypass-stop-failed" if problem else "bypass-ended",
                   reason=lapse + ("; stop failed: " + problem if problem else "; stopped and confirmed"))
    if dry_run:
        return out
    row = {"ts": now, "at": now_iso(now), "event": out["action"], "permission_mode": "bypassPermissions",
           "grant_answer": (state.get("bypass") or {}).get("answer"), "out": clean(out["reason"], 300)}
    _append(goal_dir(home, goal) / "launch.log", row)
    if out["action"] == "bypass-ended":
        state.setdefault("bypass_history", []).append(dict(state["bypass"], ended_at=now_iso(now)))
        state["bypass_history"] = state["bypass_history"][-20:]
        state["bypass"] = {}
    else:
        state["bypass"]["stop_failed_at"] = now_iso(now)
    save_state(home, goal, state)
    return out


def _list_or_error(cfg: dict, runner=_run):
    """(sessions, '') or (None, why): the session listing, or the reason it was refused (receipt v6 F2)."""
    try:
        return bg_sessions(cfg, runner), ""
    except Exception as exc:  # noqa: BLE001 - no listing, no launch; the caller logs why
        return None, "session listing refused, nothing launched: " + clean(str(exc), 200)


def tick_one(home: Path, goal: str, goal_row: dict, cfg: dict, now: float, runner=_run,
             dry_run: bool = False) -> dict:
    out = {"goal": goal, "action": "none", "reason": ""}
    # receipt v9: every read that decides anything here is taken after this goal's lock is held, in this order: the
    # owner state, the grant (v8 F1: resolved once; that one result decides the lapse check and the launch mode, and
    # the launch re-checks it), and the session listing. None of them is carried in from before the lock.
    with locked(home, goal):
        state = load_state(home, goal)
        grant = bypass_grant(home, goal, now)
        sessions, listing_error = _list_or_error(cfg, runner)
        ended = end_lapsed_bypass(home, goal, state, cfg, sessions, now, runner, dry_run, grant=grant)
        if ended is not None and ended["action"] != "bypass-ended":
            return ended  # a lapsed bypass session not shown stopped: nothing else runs for this owner
        if ended is not None:
            return ended  # stopped this tick; the next tick relaunches in the configured mode when work is due
        if listing_error:  # no listing, no launch: this owner's log says why
            _append(goal_dir(home, goal) / "launch.log", {"ts": now, "at": now_iso(now), "code": None,
                                                         "launched": False, "out": listing_error})
            out.update(action="error", reason=listing_error)
            return out
        if goal_done(goal_row):
            out["reason"] = "goal done"
            return out
        if state.get("paused"):
            out["reason"] = "paused: " + clean(state["paused"].get("source"), 120)
            return out
        status = session_status(state, sessions)
        out["session"] = status
        if status == "busy":
            out["reason"] = "running"
            return out
        reason = due_reason(home, goal, state, now)
        if not reason:
            out["reason"] = "nothing due"
            return out
        if state.get("stuck") or int(state.get("no_progress_launches", 0)) >= STUCK_LAUNCHES:
            if not state.get("stuck"):
                state["stuck"] = True
                save_state(home, goal, state)
            out.update(action="stuck", reason=f"{STUCK_LAUNCHES} launches without new proof; main must look")
            return out
        recent = [x for x in state.get("launches", []) if now - float(x.get("ts", 0)) < 3600]
        if recent and now - float(recent[-1].get("ts", 0)) < cfg["min_gap_s"]:
            out["reason"] = "min gap"
            return out
        if len(recent) >= cfg["max_launches_per_hour"]:
            out["reason"] = "hourly launch limit"
            return out
        if not cfg.get("enabled"):
            out.update(action="would-launch", reason=reason + " (runtime disabled)")
            return out
        size = transcript_bytes(home, state)
        fresh = size < 0 or size > cfg["fresh_bytes"]
        # receipt v6 F1: only a re-resolved grant, per goal, never text; v8 F1: the one resolved above
        mode = "bypassPermissions" if grant else cfg["permission_mode"]
        out["permission_mode"] = mode
        argv = [cfg["claude"], "--bg", "--permission-mode", mode, "--name", f"owner-{goal}"]
        model = state.get("model") or cfg["model"]
        if model and not MODEL_RE.match(model):
            out.update(action="launch-failed", reason=f"model {clean(model, 40)} is not allowed for owners")
            return out
        if model:
            argv += ["--model", model]
        if not fresh:
            argv += ["--resume", state["session_id"]]
        prompt = owner_prompt(home, goal, resume=not fresh)
        out.update(action="launch", reason=reason, fresh=fresh)
        if dry_run:
            out["argv"] = argv
            return out
        # receipt v4 F3: the attempt is on disk before any `claude stop` or launch runs, so an exception, a timeout
        # or a killed tick still counts toward min_gap and the hourly brake; it is finalized below
        entry = {"ts": now, "at": now_iso(now), "reason": reason, "fresh": fresh, "code": None, "bg_id": "",
                 "out": "attempt started", "permission_mode": mode,  # receipt v7 F2: every launch says its mode
                 "grant_answer": grant.get("answer") if grant else None,
                 "grant_expires_at": now_iso(grant["expires_ts"]) if grant else None}
        state["launches"] = (state.get("launches") or [])[-49:] + [entry]
        # receipt v7 F1: recorded before the launch runs, so even an uncertain launch is ended when its grant lapses
        state["bypass"] = ({"answer": grant.get("answer"), "scope": grant.get("scope"), "since": now_iso(now),
                            "expires_at": now_iso(grant["expires_ts"])} if grant else {})
        save_state(home, goal, state)

        def finish(code, text):
            entry.update(code=code, out=clean(text, 200))
            save_state(home, goal, state)
            _append(goal_dir(home, goal) / "launch.log", entry)

        if status == "idle":  # stop every idle session of this owner first: never two at once
            try:
                problem = stop_idle_sessions(cfg, state, runner)
            except Exception as exc:  # noqa: BLE001
                problem = "stop raised " + clean(f"{type(exc).__name__}: {exc}", 120)
            if problem:  # receipt v3 F3: no launch unless every old session is proven stopped
                finish(-1, "replace refused: " + problem)
                out.update(action="launch-failed", reason="replace refused: " + problem)
                return out
        # receipt v8 F2: the grant is checked again right before the program runs, still under this goal's lock; a
        # revoke that landed after the resolution above cancels the bypass launch. Nothing of this owner runs here
        # (no session, or every idle one stopped and confirmed above), so the record is cleared truthfully.
        if grant is not None and bypass_grant(home, goal, now) is None:
            state["bypass"] = {}
            finish(-1, "bypass grant revoked before the launch ran; nothing launched")
            out.update(action="bypass-launch-cancelled",
                       reason="the bypass grant was revoked before the launch ran; nothing launched")
            return out
        try:
            code, text = runner(argv + [prompt], 90, cwd=state["cwd"])  # the session's workspace is its cwd
        except Exception as exc:  # noqa: BLE001
            finish(-2, f"launch raised {type(exc).__name__}: {exc}")
            out.update(action="launch-failed", reason=clean(f"launch raised {type(exc).__name__}: {exc}", 200))
            return out
        m = re.search(r"backgrounded\s*\S*\s*([0-9a-f]{6,12})", text)
        entry.update(code=code, bg_id=m.group(1) if m else "", out=clean(text, 200))
        if code == 0:
            sid = ""
            with contextlib.suppress(Exception):
                for a in bg_sessions(cfg, runner):
                    if a.get("id") == entry["bg_id"]:
                        sid = a.get("sessionId", "")
            entry["session_id"] = sid
            state["generation"] = int(state.get("generation", 0)) + 1  # every run is a generation (G2)
            state["session_id"], state["bg_id"] = sid, entry["bg_id"]  # unknown id: found by name next tick
            state["no_progress_launches"] = int(state.get("no_progress_launches", 0)) + 1
            state["resume"] = {}
            out["bg_id"] = entry["bg_id"]
        else:
            out.update(action="launch-failed", reason=clean(text, 200))
        finish(code, text)
        return out


def _end_lapsed(home: Path, goals, cfg: dict, now: float, runner=_run, dry_run: bool = False, sessions=False):
    """end_lapsed_bypass for each goal outside the normal tick (runtime disabled, the listing refused, or a revoke).
    Receipt v8 F2: without a given listing, each goal's sessions are listed under its lock, after any tick that held
    it has finished, so a session launched while this call waited is seen and stopped."""
    if sessions is False:
        sessions = (lambda: bg_sessions(cfg, runner)) if cfg.get("claude") else None
    out = []
    for g in goals:
        try:
            with locked(home, g):
                if not (goal_dir(home, g) / "state.json").exists():
                    continue  # no owner state: nothing was launched for it
                st = load_state(home, g)
                r = end_lapsed_bypass(home, g, st, cfg, sessions, now, runner, dry_run)
            if r is not None:
                out.append(r)
        except Exception as exc:  # noqa: BLE001
            out.append({"goal": g, "action": "bypass-stop-unconfirmed",
                        "reason": "cannot tell whether a lapsed bypass session runs: " + clean(str(exc), 200)})
    return out


def revoke_and_stop(home: Path, scope: str, now=None, runner=_run) -> dict:
    """revoke-bypass, then at once stop every owner session that grant was covering (receipt v7 F1: a revoke takes
    effect now, not at the next tick). The result names each stop as ended, failed or unconfirmed."""
    now = time.time() if now is None else now
    out = revoke_bypass(home, scope)
    # receipt v8 F2: no unlocked pre-filter on state.json. Every covered goal is judged under its own lock, so a tick
    # that resolved the grant but has not yet saved its record finishes first (and its pre-launch re-check sees the
    # revoke), and a session it did launch is in the listing taken under that lock.
    goals = [g for g in owner_goals(home) if scope in ("*", g)]
    out["stopped"] = _end_lapsed(home, goals, runtime(home), now, runner) if goals else []
    return out


def owner_goals(home: Path) -> list:
    root = owners_root(home)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink() and ID_RE.match(p.name)
                  and (p / "state.json").exists())


TICK_STUCK_S = 900  # a tick lock held longer than this is reported as stuck (high alert), not just busy


def tick(home: Path, now=None, runner=_run, dry_run: bool = False, only: str = "") -> list:
    """Receipt v9: one tick at a time. Every entry point (the `tick` command, `task add --wake`, drive.ops_alerts for
    ops-watch) comes through here and takes the process-wide tick lock without waiting; a second tick returns at once
    with `tick-busy` (or `tick-stuck` when the holder has run for over TICK_STUCK_S) and writes owners/tick.log."""
    now = time.time() if now is None else now
    names = [g for g in owner_goals(home) if not only or g == only]
    if not names:
        return []
    root = owners_root(home)
    fd = os.open(str(root / ".tick.lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return _tick_refused(home, now)
        _atomic(root / "tick.holder.json", {"pid": os.getpid(), "since": time.time()})
        return _tick_locked(home, names, now, runner, dry_run)
    finally:
        os.close(fd)


def _tick_refused(home: Path, now: float) -> list:
    root = owners_root(home)
    holder = {}
    with contextlib.suppress(Exception):
        holder = json.loads(_read(root / "tick.holder.json", 4096).decode("utf-8"))
    since = holder.get("since") if isinstance(holder, dict) else None
    age = time.time() - since if isinstance(since, (int, float)) else None
    action = "tick-stuck" if age is not None and age > TICK_STUCK_S else "tick-busy"
    reason = ("another owner tick is running" + (f" (pid {holder.get('pid')}, for {int(age)} s)" if age is not None
                                                 else "") + "; this tick did nothing")
    with contextlib.suppress(Exception):
        _append(root / "tick.log", {"ts": now, "at": now_iso(now), "event": action, "pid": os.getpid(),
                                    "holder": holder if isinstance(holder, dict) else {}})
    return [{"goal": "*", "action": action, "reason": reason}]


def _tick_locked(home: Path, names: list, now: float, runner=_run, dry_run: bool = False) -> list:
    cfg = runtime(home)
    goals = mission_goals(home)
    if not cfg.get("enabled") or not cfg.get("claude"):  # nothing runs a program while disabled (r1 M1) ...
        why = "runtime disabled" if not cfg.get("enabled") else "claude binary not found in " + ", ".join(CLAUDE_DIRS)
        # ... except stopping a bypass session whose grant lapsed (receipt v7 F1): it only lowers authority. Every
        # owner is judged under its own lock (receipt v9: no unlocked pre-scan picks which ones).
        out = _end_lapsed(home, names, cfg, now, runner, dry_run)
        judged = {r.get("goal") for r in out}
        for g in [g for g in names if g not in judged]:
            with contextlib.suppress(Exception), locked(home, g):
                st = load_state(home, g)
                reason = due_reason(home, g, st, now)
                out.append({"goal": g, "action": "would-launch" if reason and cfg.get("enabled") is False else
                            ("error" if reason else "none"), "reason": (reason + f" ({why})") if reason else
                            "nothing due"})
        return out
    out = []
    for g in names:
        try:
            out.append(tick_one(home, g, goals.get(g, {}), cfg, now, runner, dry_run))
        except Exception as exc:  # noqa: BLE001 - one bad owner never stops the others
            out.append({"goal": g, "action": "error", "reason": clean(str(exc), 200)})
    return out


# ------------------------------------------------------------------ Stop hook (inside the owner session)

def _same_dir(a, b) -> bool:
    try:
        return bool(a) and bool(b) and Path(a).resolve() == Path(b).resolve()
    except (OSError, ValueError):
        return False


ADOPT_WINDOW_S = 2 * 3600
OWNER_MARKERS = ("OWNER CHARTER (owner_rt", "OWNER RESUME (owner_rt")


def transcript_file(home: Path, session: str):
    if not SESSION_RE.match(session or ""):
        return None
    config = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    for root in dict.fromkeys((home / ".claude" / "projects", config / "projects")):
        for p in root.glob(f"*/{session}.jsonl"):
            if p.is_file() and not p.is_symlink():
                return p
    return None


def launched_by_tick(home: Path, session: str, goal: str) -> bool:
    """True when this session's transcript is one the tick launched for `goal`: named owner-<goal> (the --name the
    tick passes) and its first user turn is the harness's owner prompt (observed on tick launches 2026-11-14)."""
    p = transcript_file(home, session)
    if p is None:
        return False
    try:
        with open(p, "rb") as fh:
            head = fh.read(256 << 10).decode("utf-8", "replace").splitlines()
    except OSError:
        return False
    named = False
    for line in head:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        if d.get("type") == "agent-name" and d.get("agentName") == f"owner-{goal}":
            named = True
        if d.get("type") == "user":
            c = (d.get("message") or {}).get("content")
            if isinstance(c, list):
                c = next((b.get("text") for b in c if isinstance(b, dict) and b.get("type") == "text"), "")
            return named and isinstance(c, str) and c.startswith(OWNER_MARKERS)
    return False


def owner_for_session(home: Path, session: str, cwd: str = "", now=None):
    """The owner state of this session: by recorded session id, or by the owner's dedicated workspace (`claude --bg`
    assigns its own id and ignores --session-id, so a run's first Stop can come before tick records the id; live test
    2026-11-14). A workspace match adopts the id only when (delta D1) no id is recorded yet, a launch succeeded within
    ADOPT_WINDOW_S, and the session's transcript shows the tick launched it for this goal. Any other session in the
    workspace (main, a reviewer, a `claude -p` run) is never adopted."""
    if not session:
        return None
    now = time.time() if now is None else now
    by_cwd = None
    for g in owner_goals(home):
        try:
            st = load_state(home, g)
        except Exception:  # noqa: BLE001
            continue
        if st.get("session_id") == session:
            return st
        if by_cwd is None and _same_dir(cwd, st.get("cwd")):
            by_cwd = st
    if by_cwd is None or not SESSION_RE.match(session) or by_cwd.get("session_id"):
        return None
    recent = [x for x in by_cwd.get("launches") or [] if isinstance(x, dict) and x.get("code") == 0
              and isinstance(x.get("ts"), (int, float)) and 0 <= now - x["ts"] <= ADOPT_WINDOW_S]
    if not recent or not launched_by_tick(home, session, by_cwd["goal"]):
        return None
    with contextlib.suppress(Exception), locked(home, by_cwd["goal"]):
        s2 = load_state(home, by_cwd["goal"])
        if not s2.get("session_id"):
            s2["session_id"] = session
            save_state(home, by_cwd["goal"], s2)
            return s2
    return None


def stop_decision(home: Path, payload: dict, now=None) -> dict:
    now = time.time() if now is None else now
    session = str(payload.get("session_id") or "")
    st = owner_for_session(home, session, str(payload.get("cwd") or ""), now)
    if st is None:
        return {}
    goal = st["goal"]
    goals = mission_goals(home)
    if goal_done(goals.get(goal, {})):
        return {}
    open_tasks = actionable(tasks(inbox_rows(home, goal)))
    cp_ts = (st.get("checkpoint") or {}).get("ts")
    cp_fresh = isinstance(cp_ts, (int, float)) and now - cp_ts <= CHECKPOINT_S
    if not open_tasks and cp_fresh:
        with contextlib.suppress(Exception), locked(home, goal):
            s2 = load_state(home, goal)
            s2["resume"] = {"due_ts": now + PROOF_S, "due_at": now_iso(now + PROOF_S), "reason": "checkpointed stop"}
            save_state(home, goal, s2)
        return {}
    if open_tasks:
        t = open_tasks[0]
        why = (f"goal {goal} is not done and task {t['id']} is {t['state']}: {t['text'][:160]}. Keep working it "
               f"(and every other open task: {', '.join(x['id'] for x in open_tasks)}). A facet you cannot move is a "
               f"help request (`{SCRIPT} task move --goal {goal} --task {t['id']} --to blocked --help ...`), never a "
               "reason to stop the rest.")
    else:
        why = (f"goal {goal} is not done: write a checkpoint before ending (`{SCRIPT} checkpoint --goal {goal} "
               "--text ...`): where each task stands and the next step. You will be resumed automatically.")
    sig = hashlib.sha256(json.dumps([[t["id"], t["state"]] for t in open_tasks] + [bool(cp_fresh)]).encode()
                         ).hexdigest()[:16]
    if not _count_block(home, goal, session, sig):
        return {"systemMessage": "owner_rt (block budget spent, not blocked): " + why}
    return {"decision": "block", "reason": "OWNER CONTRACT (owner_rt): " + why}


def _count_block(home: Path, goal: str, session: str, sig: str) -> bool:
    try:
        with locked(home, goal) as d:
            path = d / "stop-blocks.json"
            try:
                data = json.loads(_read(path, 65536).decode("utf-8"))
            except (FileNotFoundError, ValueError):
                data = {}
            if not isinstance(data, dict) or data.get("session") != session:
                data = {"session": session, "total": 0, "sigs": {}}
            sigs = data.setdefault("sigs", {})
            if data.get("total", 0) >= MAX_STOP_BLOCKS_PER_SESSION or sigs.get(sig, 0) >= MAX_STOP_BLOCKS_PER_SIG:
                return False
            sigs[sig] = sigs.get(sig, 0) + 1
            data["total"] = data.get("total", 0) + 1
            if len(sigs) > 200:
                data["sigs"] = dict(list(sigs.items())[-100:])
            _atomic(path, data)
            return True
    except Exception:  # noqa: BLE001 - a broken counter never traps the agent
        return False


def cmd_stop(stdin) -> int:
    try:
        payload = json.loads(stdin.read(1 << 20) or "{}")
        if not isinstance(payload, dict):
            return 0
        out = stop_decision(home_dir(), payload)
        if out:
            print(json.dumps(out))
    except Exception as exc:  # noqa: BLE001 - fail open
        print(json.dumps({"systemMessage": f"owner_rt stop check failed open: {exc.__class__.__name__}"}))
    return 0


# ------------------------------------------------------------------ views

def show(home: Path, goal: str, now=None) -> dict:
    now = time.time() if now is None else now
    st = load_state(home, goal)
    tmap = tasks(inbox_rows(home, goal))
    return {"goal": goal, "title": st.get("title"), "cwd": st.get("cwd"), "generation": st.get("generation"),
            "session_id": st.get("session_id"), "bg_id": st.get("bg_id"), "stuck": st.get("stuck"),
            "proof_age_s": None if proof_age(st, now) == float("inf") else int(proof_age(st, now)),
            "last_beat": st.get("last_beat"), "checkpoint": st.get("checkpoint"), "resume": st.get("resume"),
            "tasks": sorted(tmap.values(), key=lambda t: t["id"]),
            "help": [{"task": t["id"], "need": t["help"]} for t in tmap.values() if t["state"] == "blocked"],
            "loops": [t["id"] for t in tmap.values() if t["loop"]],
            "launches": st.get("launches", [])[-5:]}


def build_parser():
    p = argparse.ArgumentParser(prog="owner_rt.py", description="Long-lived product owners: state, inbox, proof, "
                                "resume. See the module docstring.")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="register the owner of a ledger goal")
    i.add_argument("--goal", required=True)
    i.add_argument("--cwd", required=True, help="the owner's workspace (must be a directory Claude trusts)")
    i.add_argument("--source", required=True)
    i.add_argument("--model", default="")
    i.add_argument("--ticket", default="")
    t = sub.add_parser("task", help="task inbox")
    tsub = t.add_subparsers(dest="tcmd", required=True)
    ta = tsub.add_parser("add")
    ta.add_argument("--goal", required=True)
    ta.add_argument("--text", required=True)
    ta.add_argument("--source", required=True)
    ta.add_argument("--by", default="main")
    ta.add_argument("--wake", action="store_true", help="run tick for this goal right after adding")
    tm = tsub.add_parser("move")
    tm.add_argument("--goal", required=True)
    tm.add_argument("--task", required=True)
    tm.add_argument("--to", required=True, choices=STATES)
    tm.add_argument("--ac-file", default="")
    tm.add_argument("--reviewer", default="")
    tm.add_argument("--verdict", default="")
    tm.add_argument("--help-text", "--need", dest="help_text", default="")
    tm.add_argument("--evidence", action="append", default=[])
    tm.add_argument("--source", default="")
    tr = tsub.add_parser("round", help="record one adversarial review round on a planned task")
    tr.add_argument("--goal", required=True)
    tr.add_argument("--task", required=True)
    tr.add_argument("--reviewer", required=True)
    tr.add_argument("--verdict", required=True)
    tb = tsub.add_parser("break", help="break a review loop: redesign, escalate or park")
    tb.add_argument("--goal", required=True)
    tb.add_argument("--task", required=True)
    tb.add_argument("--how", required=True, choices=("redesign", "escalate", "park"))
    tb.add_argument("--ref", default="")
    tb.add_argument("--ac-file", default="")
    b = sub.add_parser("beat", help="proof of progress with resolving evidence")
    b.add_argument("--goal", required=True)
    b.add_argument("--evidence", action="append", required=True)
    b.add_argument("--next", default="")
    c = sub.add_parser("checkpoint", help="handoff text before ending a turn")
    c.add_argument("--goal", required=True)
    c.add_argument("--text", required=True)
    s = sub.add_parser("show")
    s.add_argument("--goal", required=True)
    s.add_argument("--json", action="store_true")
    sub.add_parser("list")
    pr = sub.add_parser("prompt", help="print the owner charter or resume prompt")
    pr.add_argument("--goal", required=True)
    pr.add_argument("--resume", action="store_true")
    k = sub.add_parser("tick", help="resume every idle owner with work due (ops_watch runs this)")
    k.add_argument("--dry-run", action="store_true")
    for flag, text in (("unstick", "clear stuck after looking at the owner"), ("pause", "tick leaves the owner alone"),
                       ("unpause", "resume ticking the owner")):
        f = sub.add_parser(flag, help=text)
        f.add_argument("--goal", required=True)
        f.add_argument("--source", required=True)
    q = sub.add_parser("ask-text", help="print the exact AskUserQuestion for a bypass grant or a park")
    q.add_argument("--kind", required=True, choices=("bypass", "park"))
    q.add_argument("--scope", default="*", help="bypass: * (every owner) or a goal id")
    q.add_argument("--hours", type=int, default=0)
    q.add_argument("--goal", default="")
    q.add_argument("--until", default="", help="park: YYYY-MM-DD (UTC, inclusive)")
    gb = sub.add_parser("grant-bypass", help="main only: record the user's answer allowing bypassPermissions")
    gb.add_argument("--scope", required=True)
    gb.add_argument("--hours", type=int, required=True)
    gb.add_argument("--answer", required=True, help="answer:<session>/<uuid> of the user's AskUserQuestion reply")
    rb = sub.add_parser("revoke-bypass", help="remove a bypass grant (anyone may lower authority)")
    rb.add_argument("--scope", required=True)
    pk = sub.add_parser("park", help="main only: record the user's answer parking a goal in the drive loop")
    pk.add_argument("--goal", required=True)
    pk.add_argument("--until", required=True)
    pk.add_argument("--answer", required=True)
    up = sub.add_parser("unpark", help="remove a park record (anyone may)")
    up.add_argument("--goal", required=True)
    sub.add_parser("stop", help="Stop hook (reads the hook payload on stdin)")
    _no_abbrev(p)
    return p


STAMP_PURPOSE = "owner-main"
STAMP_TTL_S = 60
# (command, needs): "main" = main of the mission session; "main-or-owner" = that, or the goal's own owner session.
GUARDED = {"init": "main", "pause": "main", "unpause": "main", "unstick": "main", "task add": "main-or-owner",
           "task drop": "main-or-owner", "grant-bypass": "main", "park": "main"}


def guarded_name(argv) -> str:
    argv = [str(a) for a in argv or []]
    if argv[:1] == ["task"] and len(argv) > 1:
        if argv[1] == "move" and ("dropped" in argv or "--to=dropped" in argv):
            return "task drop"
        return f"task {argv[1]}"
    return argv[0] if argv else ""


def argv_key(argv) -> str:
    """Digest of the exact argument list (`--flag=value` read as `--flag value`), the same as mission_gate's stamp key."""
    words = []
    for a in argv:
        a = str(a)
        words.extend(a.split("=", 1) if a.startswith("--") and "=" in a else [a])
    return hashlib.sha256(json.dumps(words, separators=(",", ":")).encode("utf-8", "replace")).hexdigest()


def authorize(argv, home: Path, goal: str) -> None:
    """Consume main's one-shot stamp for exactly this argument list (bound to main's still-running tool call, as
    mission_coverage's main-only commands) and check whose session wrote it. A sub-agent's shell, a cron job, a copied
    script or `ah own` (no stamp is written for it) is refused (red-team r1 M7). Same-user threat model."""
    name = guarded_name(argv)
    need = GUARDED.get(name)
    if not need:
        return
    import caller_identity  # noqa: PLC0415
    stamp = caller_identity.take_stamp(STAMP_PURPOSE, [name, argv_key(argv)], home=home, bound=True, ttl=STAMP_TTL_S)
    if stamp is None:
        raise OwnerError(f"`{name}` is main-only: run `{SCRIPT} ...` as a plain foreground command from main (or, for "
                         "task add and drop, from the goal's own owner session); a sub-agent asks main")
    caller = str(stamp.get("session") or "").lower()
    mission = ""
    with contextlib.suppress(Exception):
        import mission_coverage  # noqa: PLC0415
        mission = (mission_coverage.mission_session_of(home) or "").lower()
    if mission and caller == mission:
        return
    if need == "main-or-owner":
        with contextlib.suppress(Exception):
            if caller and caller == str(load_state(home, goal).get("session_id") or "").lower():
                return
    raise OwnerError(f"`{name}` is refused for session {clean(caller, 40) or 'unknown'}: only the mission's main"
                     + (" or this goal's owner session" if need == "main-or-owner" else "") + " may run it")


REPEATABLE = {"--evidence"}


def argv_problem(argv) -> str:
    """receipt v4 F1: authorization reads the goal and command from argv while argparse executes its own reading, so
    the two must agree: a repeated option (`--goal a --goal b`: argparse keeps the last) is refused before anything
    else. Abbreviations are off in build_parser, so `--goa b` is an error, not a second spelling of --goal."""
    seen = set()
    for a in argv or []:
        a = str(a)
        if not a.startswith("--"):
            continue
        flag = a.split("=", 1)[0]
        if flag in seen and flag not in REPEATABLE:
            return f"option {flag} is given more than once"
        seen.add(flag)
    return ""


def canonical_name(args) -> str:
    if args.cmd == "task":
        return "task drop" if args.tcmd == "move" and getattr(args, "to", "") == "dropped" else f"task {args.tcmd}"
    return str(args.cmd)


def _no_abbrev(parser) -> None:
    parser.allow_abbrev = False
    for action in parser._actions:  # noqa: SLF001 - argparse keeps subparsers here
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            for sub in action.choices.values():
                _no_abbrev(sub)


def _goal_arg(argv) -> str:
    argv = [str(a) for a in argv]
    for i, a in enumerate(argv):
        if a == "--goal" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--goal="):
            return a.split("=", 1)[1]
    return ""


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["stop"]:
        return cmd_stop(sys.stdin)
    home = home_dir()
    problem = argv_problem(argv)
    if problem:
        print(f"owner_rt: {problem}", file=sys.stderr)
        return 2
    name, goal = guarded_name(argv), _goal_arg(argv)
    try:
        authorize(argv, home, goal)  # before parsing: a failing command still burns its stamp
    except OwnerError as exc:
        print(f"owner_rt: {exc}", file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    canon = canonical_name(args)
    if (canon in GUARDED or name in GUARDED) and (canon != name or str(getattr(args, "goal", "")) != goal):
        print(f"owner_rt: authorized `{name}` for goal {goal!r} but the command parses as `{canon}` for goal "
              f"{getattr(args, 'goal', '')!r}; refused", file=sys.stderr)
        return 2
    try:
        if args.cmd == "init":
            out = init_owner(home, args.goal, args.cwd, args.source, args.model, args.ticket)
        elif args.cmd == "task" and args.tcmd == "add":
            out = add_task(home, args.goal, args.text, args.source, args.by)
            if args.wake:
                out = {"task": out, "tick": tick(home, only=args.goal)}
        elif args.cmd == "task" and args.tcmd == "move":
            out = move_task(home, args.goal, args.task, args.to, ac_file=args.ac_file, reviewer=args.reviewer,
                            verdict=args.verdict, help_text=args.help_text, evidence=args.evidence,
                            source=args.source)
        elif args.cmd == "task" and args.tcmd == "round":
            out = review_round(home, args.goal, args.task, args.reviewer, args.verdict)
        elif args.cmd == "task" and args.tcmd == "break":
            out = break_loop(home, args.goal, args.task, args.how, args.ref, args.ac_file)
        elif args.cmd == "beat":
            out = beat(home, args.goal, args.evidence, args.next)
        elif args.cmd == "checkpoint":
            out = checkpoint(home, args.goal, args.text)
        elif args.cmd == "show":
            out = show(home, args.goal)
        elif args.cmd == "list":
            out = {"owners": owner_goals(home)}
        elif args.cmd == "prompt":
            print(owner_prompt(home, args.goal, resume=args.resume))
            return 0
        elif args.cmd in ("unstick", "pause", "unpause"):
            out = set_flag(home, args.goal, args.cmd, args.source)
        elif args.cmd == "tick":
            out = tick(home, dry_run=args.dry_run)
        elif args.cmd == "ask-text":
            out = ask_text(args.kind, args.scope, args.hours, args.goal, args.until)
        elif args.cmd == "grant-bypass":
            out = grant_bypass(home, args.scope, args.hours, args.answer)
        elif args.cmd == "revoke-bypass":
            out = revoke_and_stop(home, args.scope)
        elif args.cmd == "park":
            out = park_goal(home, args.goal, args.until, args.answer)
        elif args.cmd == "unpark":
            out = unpark_goal(home, args.goal)
        else:
            return 2
    except (OwnerError, OSError, ValueError) as exc:
        print(f"owner_rt: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
