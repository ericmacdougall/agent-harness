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
                  "min_gap_s": 300, "fresh_bytes": 8000000}  (absent or enabled=false: tick never launches)

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
                   "fresh_bytes": 8_000_000, "model": "", "permission_source": ""}
# Brakes an agent-writable runtime.json cannot loosen (red-team r1 M1).
BRAKES = {"max_launches_per_hour": (1, 6), "min_gap_s": (120, 86400), "fresh_bytes": (200_000, 50_000_000)}
# Owners run Opus or Sonnet; the top rungs (Fable/Astra) are never launched by the tick (CLAUDE.md, r1 M2).
MODEL_RE = re.compile(r"^(?:|opus|sonnet|claude-(?:opus|sonnet)-[0-9][0-9a-z.-]{0,30})$")
CLAUDE_DIRS = ("~/.local/bin", "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
PERMISSION_MODES = ("auto", "acceptEdits", "default", "dontAsk", "bypassPermissions")
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
    if cfg["permission_mode"] == "bypassPermissions" and not user_decided(cfg.get("permission_source")):
        cfg["permission_mode"], cfg["note"] = "auto", "bypassPermissions needs permission_source with the user's words"
    cfg["claude"] = claude_bin()
    return cfg


def user_decided(source) -> bool:
    """True only for a user:/answer: source that provenance resolves to the user's own words (r1 M3)."""
    try:
        import mission_coverage  # noqa: PLC0415
        return bool(source) and mission_coverage.verify_user_source(source)
    except Exception:  # noqa: BLE001
        return False


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
        f"`task move --to converged --reviewer <id> --verdict ACCEPT`. Two rejected rounds = a loop: "
        f"`task break --how redesign|escalate|park`.",
        "  3. Delegate building, fixing and testing to sub-agents; integrate, verify and push each green step.",
        f"  4. Prove progress at least every 30 minutes: `{cmd} beat {g} --evidence commit:<sha> "
        f"--evidence wal:<id> --next \"...\"`. Post checkpoints to the ticket.",
        f"  5. A blocked facet is a help request, never a pause: `{cmd} task move {g} --task tN --to blocked "
        f"--help \"what you need\"`, then keep working every other task.",
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
    code, out = runner([cfg["claude"], "agents", "--json", "--all"], 30)
    if code != 0:
        raise OwnerError("claude agents failed: " + clean(out, 200))
    start = out.find("[")
    data = json.loads(out[start:]) if start >= 0 else []
    return [a for a in data if isinstance(a, dict)]


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


def tick_one(home: Path, goal: str, goal_row: dict, cfg: dict, sessions: list, now: float, runner=_run,
             dry_run: bool = False) -> dict:
    out = {"goal": goal, "action": "none", "reason": ""}
    with locked(home, goal):
        state = load_state(home, goal)
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
        argv = [cfg["claude"], "--bg", "--permission-mode", cfg["permission_mode"], "--name", f"owner-{goal}"]
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
        if status == "idle":  # stop every idle session of this owner first: never two at once
            for a in owner_sessions(state, sessions):
                if a.get("id"):
                    runner([cfg["claude"], "stop", str(a["id"])], 30)
        code, text = runner(argv + [prompt], 90, cwd=state["cwd"])  # the session's workspace is its cwd
        m = re.search(r"backgrounded\s*\S*\s*([0-9a-f]{6,12})", text)
        entry = {"ts": now, "at": now_iso(now), "reason": reason, "fresh": fresh, "code": code,
                 "bg_id": m.group(1) if m else "", "out": clean(text, 200)}
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
        state.setdefault("launches", []).append(entry)
        state["launches"] = state["launches"][-50:]
        save_state(home, goal, state)
        _append(goal_dir(home, goal) / "launch.log", entry)
        return out


def owner_goals(home: Path) -> list:
    root = owners_root(home)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink() and ID_RE.match(p.name)
                  and (p / "state.json").exists())


def tick(home: Path, now=None, runner=_run, dry_run: bool = False, only: str = "") -> list:
    now = time.time() if now is None else now
    cfg = runtime(home)
    goals = mission_goals(home)
    names = [g for g in owner_goals(home) if not only or g == only]
    if not names:
        return []
    if not cfg.get("enabled") or not cfg.get("claude"):  # nothing runs a program while disabled (r1 M1)
        why = "runtime disabled" if not cfg.get("enabled") else "claude binary not found in " + ", ".join(CLAUDE_DIRS)
        out = []
        for g in names:
            with contextlib.suppress(Exception):
                st = load_state(home, g)
                reason = due_reason(home, g, st, now)
                out.append({"goal": g, "action": "would-launch" if reason and cfg.get("enabled") is False else
                            ("error" if reason else "none"), "reason": (reason + f" ({why})") if reason else
                            "nothing due"})
        return out
    try:
        sessions = bg_sessions(cfg, runner)
    except Exception as exc:  # noqa: BLE001
        return [{"goal": g, "action": "error", "reason": clean(str(exc), 200)} for g in names]
    out = []
    for g in names:
        try:
            out.append(tick_one(home, g, goals.get(g, {}), cfg, sessions, now, runner, dry_run))
        except Exception as exc:  # noqa: BLE001 - one bad owner never stops the others
            out.append({"goal": g, "action": "error", "reason": clean(str(exc), 200)})
    return out


# ------------------------------------------------------------------ Stop hook (inside the owner session)

def _same_dir(a, b) -> bool:
    try:
        return bool(a) and bool(b) and Path(a).resolve() == Path(b).resolve()
    except (OSError, ValueError):
        return False


def owner_for_session(home: Path, session: str, cwd: str = ""):
    """The owner state of this session: by recorded session id, or by the owner's dedicated workspace (`claude --bg`
    assigns its own id and ignores --session-id, so a run's first Stop can come before tick records the id; live test
    2026-11-14). A workspace match adopts the id."""
    if not session:
        return None
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
    if by_cwd is not None and SESSION_RE.match(session):
        with contextlib.suppress(Exception), locked(home, by_cwd["goal"]):
            s2 = load_state(home, by_cwd["goal"])
            s2["session_id"] = session
            save_state(home, by_cwd["goal"], s2)
            by_cwd = s2
    return by_cwd


def stop_decision(home: Path, payload: dict, now=None) -> dict:
    now = time.time() if now is None else now
    session = str(payload.get("session_id") or "")
    st = owner_for_session(home, session, str(payload.get("cwd") or ""))
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
    sub.add_parser("stop", help="Stop hook (reads the hook payload on stdin)")
    return p


STAMP_PURPOSE = "owner-main"
STAMP_TTL_S = 60
# (command, needs): "main" = main of the mission session; "main-or-owner" = that, or the goal's own owner session.
GUARDED = {"init": "main", "pause": "main", "unpause": "main", "unstick": "main", "task add": "main-or-owner",
           "task drop": "main-or-owner"}


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
    try:
        authorize(argv, home, _goal_arg(argv))  # before parsing: a failing command still burns its stamp
    except OwnerError as exc:
        print(f"owner_rt: {exc}", file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
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
        else:
            return 2
    except (OwnerError, OSError, ValueError) as exc:
        print(f"owner_rt: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
