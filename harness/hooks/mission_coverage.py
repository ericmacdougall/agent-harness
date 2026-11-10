#!/usr/bin/env python3
"""Mission coverage (GoodQA goodqa#15565): every active mission goal is held by someone, waits on something named,
or is done with evidence. Anything else is UNCOVERED.

Why: on 2026-11-10 the leads goal (goodqa#15095) had no owner all night and nothing said so. The dropped-owner scan
(`ah owners`, dropped_gate.py) sees owners that existed and stopped; a goal that never had an owner is invisible to it.

Goals live in ONE canonical file, ~/.agent-harness/mission/goals.json (dir 0700, file 0600): a JSON list of
  {id, title, ticket ('goodqa#N' or 'Project#N'), priority (1 = most important .. 9), status ('active'|'done'|'deferred'),
   deferral {by: 'user'|'ask'|'ticket', ref, until (ISO), source}, done_evidence [{kind: 'deploy'|'really_tested', ref,
   session}], repos [paths, optional: where commits on the ticket count as progress], dashboard {...informational}}
Every write goes through this tool (add, set, defer, done, import-initiatives, reseal) and appends a hash-chained row
to ~/.agent-harness/state/mission-goals-audit.jsonl; a goals file that no longer matches the chain head is treated as
tampered (removing a goal by hand is visible).

A goal is covered by
  (a) a LIVE OWNER: an `ah owners` row of an owner type (never a helper) in a running state whose stream ticket (the
      first GoodQA ticket in its WAL) equals the goal's ticket. Liveness comes from `ah owners` only, never from any
      owner field in the goals file;
  (b) a LIVE DISPOSITION: a wait on an ask that is open in main's WAL, or on another ticket, with `until` in the
      future (at most WAIT_MAX_S ahead); or a deferral the user decided, whose `user:`/`answer:` source resolves
      through provenance.py (until in the future, or none);
  (c) DONE EVIDENCE: status 'done' with a deploy record and a later live REALLY_TESTED entry that name the goal's
      ticket (ah's own evidence resolvers, the DONE_LIVE rule).
STALLED: covered by owners but no owner WAL entry (hook lifecycle rows excluded) and no commit naming the ticket for
more than STALL_S.

Commands: add, set, defer, done, import-initiatives, reseal, verify, report [--json], check. Exit 0 ok, 1 uncovered
(check), 2 refused or unreadable. Stdlib only.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
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
import safe_input  # noqa: E402

STALL_S = 45 * 60
WAIT_MAX_S = 7 * 86400  # an ask or ticket wait is renewed at least weekly, never parked (same bound as ah dispositions)
MAX_GOALS_BYTES = 1 << 20
MAX_GOALS = 500
MAX_DEPTH = 8
MAX_AUDIT_BYTES = 16 << 20
STATUSES = ("active", "done", "deferred")
DEFER_BY = ("user", "ask", "ticket")
EVIDENCE_KINDS = ("deploy", "really_tested")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ASK_ID_RE = re.compile(r"^w[0-9a-f]{11}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:#-]{0,79}$")
TICKET_RE = re.compile(r"\s*(?:GoodQA\s+)?(?:([A-Za-z][A-Za-z0-9-]{0,62})\s*)?#\s*([1-9][0-9]{0,9})\s*", re.I)
LIFECYCLE_EVENTS = ("pretool", "subagent", "subagent_stop", "prompt", "session", "pending_stop")
RUNNING = ("live", "working", "quiet")  # plus SILENT / SILENT-HIGH unless main disposed of the owner (tier_gate F4)
HELPERS_DEFAULT = ("red-team", "click-tester", "reviewer", "fixer", "Explore", "Plan", "claude-code-guide",
                   "statusline-setup")
SCRIPT = "python3 ~/.claude/hooks/mission_coverage.py"
GENESIS = "0" * 64


class MissionError(ValueError):
    """A request this tool refuses; the message says why and what to do instead."""


# ------------------------------------------------------------------ paths and small helpers

def home_dir() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def goals_path(home: Path) -> Path:
    return Path(home) / ".agent-harness" / "mission" / "goals.json"


def audit_path(home: Path) -> Path:
    return Path(home) / ".agent-harness" / "state" / "mission-goals-audit.jsonl"


def head_path(home: Path) -> Path:
    return Path(home) / ".agent-harness" / "state" / "mission-goals-audit.head"


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value) -> float:
    if not isinstance(value, str) or len(value) > 40:
        return 0.0
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ticket_key(text):
    """'slug#N' (lower case, default project goodqa) for goodqa#N, GoodQA #N, GoodQA proj #N, Project#N; else None."""
    if not isinstance(text, str) or len(text) > 120:
        return None
    m = TICKET_RE.fullmatch(text)
    if not m:
        return None
    slug = (m.group(1) or "goodqa").lower()
    return f"{'goodqa' if slug == 'goodqa' else slug}#{int(m.group(2))}"


def same_ticket(a, b) -> bool:
    ka, kb = ticket_key(a), ticket_key(b)
    return bool(ka) and ka == kb


def fmt_age(seconds) -> str:
    if seconds is None:
        return "?"
    seconds = int(seconds)
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m" if seconds >= 3600 else f"{seconds // 60}m"


# ------------------------------------------------------------------ goals file: read and validate

def _check_goal(g, index: int) -> dict:
    where = f"goal {index}"
    if not isinstance(g, dict):
        raise ValueError(f"{where} is not an object")
    gid = g.get("id")
    if not isinstance(gid, str) or not ID_RE.match(gid):
        raise ValueError(f"{where} has no valid id (lower-case letters, digits, - and _)")
    where = f"goal {gid}"
    if not isinstance(g.get("title", ""), str) or len(g.get("title", "")) > 300:
        raise ValueError(f"{where}: title must be text up to 300 characters")
    ticket = g.get("ticket", "")
    if not isinstance(ticket, str) or (ticket and not ticket_key(ticket)):
        raise ValueError(f"{where}: ticket must be '' or like goodqa#123 / Project#123")
    pri = g.get("priority", 3)
    if isinstance(pri, bool) or not isinstance(pri, int) or not 1 <= pri <= 9:
        raise ValueError(f"{where}: priority must be an integer 1..9")
    if g.get("status", "active") not in STATUSES:
        raise ValueError(f"{where}: status must be one of {', '.join(STATUSES)}")
    d = g.get("deferral")
    if d is not None:
        if not isinstance(d, dict) or d.get("by") not in DEFER_BY:
            raise ValueError(f"{where}: deferral must be an object with by user, ask or ticket")
        for k in ("ref", "until", "source"):
            if d.get(k) is not None and (not isinstance(d[k], str) or len(d[k]) > 4000):
                raise ValueError(f"{where}: deferral.{k} must be text")
    ev = g.get("done_evidence")
    if ev is not None:
        rows = [ev] if isinstance(ev, dict) else ev
        if not isinstance(rows, list) or len(rows) > 10:
            raise ValueError(f"{where}: done_evidence must be a list of {{kind, ref, session}}")
        for r in rows:
            if not isinstance(r, dict) or r.get("kind") not in EVIDENCE_KINDS or not isinstance(r.get("ref"), str) \
                    or not REF_RE.match(r["ref"]) or not isinstance(r.get("session", ""), str):
                raise ValueError(f"{where}: done_evidence rows need kind deploy|really_tested and a ref")
    repos = g.get("repos")
    if repos is not None and (not isinstance(repos, list) or len(repos) > 10
                              or not all(isinstance(p, str) and 0 < len(p) < 1024 for p in repos)):
        raise ValueError(f"{where}: repos must be a list of paths")
    return g


def validate_goals(data) -> list:
    if not isinstance(data, list):
        raise ValueError("goals file must be a JSON list of goals")
    if len(data) > MAX_GOALS:
        raise ValueError(f"more than {MAX_GOALS} goals")
    seen = set()
    for i, g in enumerate(data):
        _check_goal(g, i)
        if g["id"] in seen:
            raise ValueError(f"goal id {g['id']} appears twice")
        seen.add(g["id"])
    return data


def _read_goals_bytes(home: Path):
    """Raw bytes of the goals file, None when absent; ValueError when it is not a small regular file."""
    path = goals_path(home)
    if not os.path.lexists(path):
        return None
    if os.path.islink(path):
        raise ValueError("goals file is a symlink")
    try:
        return safe_input.read_bounded(path, MAX_GOALS_BYTES)
    except safe_input.InputRejected as rejected:
        raise ValueError(rejected.message) from None


def load_goals(home: Path) -> dict:
    """{"state": "absent"} | {"state": "ok", "goals": [...], "sha": hex} | {"state": "error", "error": why}."""
    try:
        raw = _read_goals_bytes(home)
        if raw is None:
            return {"state": "absent", "goals": []}
        goals = validate_goals(safe_input.safe_json_loads(raw, max_depth=MAX_DEPTH, max_bytes=MAX_GOALS_BYTES))
        return {"state": "ok", "goals": goals, "sha": sha(raw)}
    except (ValueError, UnicodeError, RecursionError) as error:
        return {"state": "error", "goals": [], "error": str(error)[:200]}


# ------------------------------------------------------------------ audit chain

def _file_sha(home: Path) -> str:
    raw = _read_goals_bytes(home)
    return "absent" if raw is None else sha(raw)


def verify_audit(home: Path) -> dict:
    """{"ok": bool, "problem": str, "rows": n}: every row's prev is the sha256 of the row before it, the head file
    names the last row, and the goals file is the one the last row wrote."""
    path = audit_path(home)
    try:
        current = _file_sha(home)
    except ValueError as error:
        return {"ok": False, "problem": f"goals file unreadable: {error}", "rows": 0}
    if not os.path.lexists(path):
        if current == "absent":
            return {"ok": True, "problem": "", "rows": 0}
        return {"ok": False, "problem": "goals file changed outside mission_coverage.py: it has no audit trail", "rows": 0}
    prev, last, n = GENESIS, None, 0
    try:
        for number, line in safe_input.iter_jsonl_lines(path, max_line=1 << 20, max_total_bytes=MAX_AUDIT_BYTES):
            if line is None:
                return {"ok": False, "problem": f"audit row {number} is oversized", "rows": n}
            if not line.strip():
                continue
            rec = safe_input.safe_json_loads(line, max_depth=MAX_DEPTH)
            if not isinstance(rec, dict) or rec.get("prev") != prev:
                return {"ok": False, "problem": f"audit chain broken at row {number} (edited, removed or reordered)",
                        "rows": n}
            prev, last, n = sha(line + b"\n"), rec, n + 1
    except (safe_input.InputRejected, ValueError) as error:
        return {"ok": False, "problem": f"audit trail unreadable: {str(error)[:120]}", "rows": n}
    try:
        head = safe_input.read_bounded(head_path(home), 256).decode("ascii", "replace").strip()
    except (safe_input.InputRejected, OSError):
        head = ""
    if head != prev:
        return {"ok": False, "problem": "audit chain head does not match its last row (rows edited or truncated)",
                "rows": n}
    if last is None or last.get("after_sha") != current:
        removed = ""
        if last is not None:
            now_ids = {g["id"] for g in load_goals(home).get("goals") or []}
            gone = sorted(set(last.get("ids") or []) - now_ids)
            removed = f"; goals no longer in the file: {', '.join(gone)}" if gone else ""
        return {"ok": False, "problem": "goals file changed outside mission_coverage.py since the last audit row"
                                        + removed, "rows": n}
    return {"ok": True, "problem": "", "rows": n}


def _actor() -> dict:
    return {"session": (os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or "")[:80],
            "agent": (os.environ.get("AH_AGENT_ID") or os.environ.get("CLAUDE_AGENT_ID") or "")[:80],
            "pid": os.getpid()}


@contextlib.contextmanager
def _locked(home: Path):
    import fcntl  # noqa: PLC0415 - POSIX only, like the rest of the harness state
    state = audit_path(home).parent
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(state / "mission-goals.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _last_line(path: Path) -> bytes:
    if not os.path.lexists(path):
        return b""
    tail = safe_input.read_tail(path, 1 << 20)
    lines = [x for x in tail.split(b"\n") if x.strip()]
    return (lines[-1] + b"\n") if lines else b""


def _mutate(home: Path, action: str, goal_id: str, change, detail: dict, allow_broken: bool = False) -> list:
    """Load, apply change(goals) -> goals, write goals.json and one chained audit row, under one lock."""
    with _locked(home):
        audit = verify_audit(home)
        if not audit["ok"] and not allow_broken:
            raise MissionError(f"{audit['problem']}. Inspect it with `{SCRIPT} verify`, restore the file, or record "
                               f"the current file with `{SCRIPT} reseal --reason <what changed and why>`")
        state = load_goals(home)
        if state["state"] == "error":
            raise MissionError(f"goals file unreadable ({state['error']}); fix or restore it before writing")
        before = state.get("sha") or "absent"
        goals = validate_goals(change([dict(g) for g in state["goals"]]))
        data = (json.dumps(goals, indent=1, sort_keys=True) + "\n").encode()
        if len(data) > MAX_GOALS_BYTES:
            raise MissionError("goals file would exceed 1 MiB")
        _atomic(goals_path(home), data)
        row = {"at": iso(time.time()), "action": action, "goal": goal_id, "detail": detail, "before_sha": before,
               "after_sha": sha(data), "ids": [g["id"] for g in goals], "actor": _actor(),
               "prev": sha(_last_line(audit_path(home))) if os.path.lexists(audit_path(home)) else GENESIS}
        line = (json.dumps(row, sort_keys=True) + "\n").encode()
        fd = os.open(str(audit_path(home)), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        _atomic(head_path(home), (sha(line) + "\n").encode())
        return goals


def _find(goals: list, goal_id: str) -> dict:
    for g in goals:
        if g["id"] == goal_id:
            return g
    raise MissionError(f"no goal {goal_id!r}; list them with `{SCRIPT} report`")


# ------------------------------------------------------------------ write commands

def add_goal(home: Path, goal_id: str, title: str, ticket: str = "", priority: int = 3) -> list:
    if not ID_RE.match(goal_id or ""):
        raise MissionError("goal id: lower-case letters, digits, - and _, up to 64 characters")

    def change(goals):
        if any(g["id"] == goal_id for g in goals):
            raise MissionError(f"goal {goal_id} already exists; change it with `{SCRIPT} set`")
        return goals + [{"id": goal_id, "title": title or goal_id, "ticket": (ticket_key(ticket) or "") if ticket else "",
                         "priority": int(priority), "status": "active"}]
    if ticket and not ticket_key(ticket):
        raise MissionError("ticket must look like goodqa#123 or Project#123")
    return _mutate(home, "add", goal_id, change, {"title": title[:120], "ticket": ticket, "priority": priority})


def set_goal(home: Path, goal_id: str, *, title=None, ticket=None, priority=None, status=None, repos=None,
             clear_deferral: bool = False) -> list:
    if status == "done":
        raise MissionError(f"a goal is marked done only with evidence: `{SCRIPT} done --goal {goal_id} --deploy <deploy "
                           f"WAL id> --live-test <REALLY_TESTED id>`")
    if status == "deferred":
        raise MissionError(f"a goal is deferred only with a reason: `{SCRIPT} defer --goal {goal_id} ...`")
    if status not in (None, "active"):
        raise MissionError("status: set only accepts active (done and defer have their own commands)")
    if ticket is not None and ticket and not ticket_key(ticket):
        raise MissionError("ticket must look like goodqa#123 or Project#123")
    detail = {k: v for k, v in (("title", title), ("ticket", ticket), ("priority", priority), ("status", status),
                                ("repos", repos), ("clear_deferral", clear_deferral or None)) if v is not None}

    def change(goals):
        g = _find(goals, goal_id)
        if title is not None:
            g["title"] = title
        if ticket is not None:
            g["ticket"] = ticket_key(ticket) or ""
        if priority is not None:
            g["priority"] = int(priority)
        if repos is not None:
            g["repos"] = list(repos)
        if status == "active":
            g["status"] = "active"
            g.pop("done_evidence", None)
        if clear_deferral or status == "active":
            g.pop("deferral", None)
        return goals
    return _mutate(home, "set", goal_id, change, detail)


def main_wal(home: Path, session: str) -> Path:
    import ah  # noqa: PLC0415
    return ah.session_dir(home, session) / "main.jsonl"


def ask_states(home: Path, session: str) -> dict:
    if not session:
        return {}
    import ah  # noqa: PLC0415
    return ah.ask_states(main_wal(home, session))


def defer_goal(home: Path, goal_id: str, *, ask=None, ticket=None, user_source=None, until=None, session=None,
               now=None) -> list:
    now = time.time() if now is None else now
    given = [x for x in (ask, ticket, user_source) if x]
    if len(given) != 1:
        raise MissionError("name exactly one of --ask ASKID, --ticket TICKET or --user-source SOURCE")
    until_ts = parse_ts(until) if until else 0.0
    if until and not until_ts:
        raise MissionError("--until must be an ISO time such as 2026-11-12T09:00Z")
    if until and until_ts <= now:
        raise MissionError("--until is in the past")
    if ask or ticket:
        if not until:
            raise MissionError("a wait on an ask or ticket needs --until (at most 7 days ahead)")
        if until_ts - now > WAIT_MAX_S:
            raise MissionError("--until is more than 7 days ahead; renew the wait instead of parking the goal")
    if ask:
        if not ASK_ID_RE.match(ask):
            raise MissionError("--ask takes an ask id from main's WAL (w + 11 hex digits)")
        if ask_states(home, session or main_session(home)).get(ask) != "open":
            raise MissionError(f"ask {ask} is not open in main's WAL (answered or unknown); a goal cannot wait on it")
        deferral = {"by": "ask", "ref": ask, "until": iso(until_ts)}
    elif ticket:
        if not ticket_key(ticket):
            raise MissionError("--ticket must look like goodqa#123 or Project#123")
        deferral = {"by": "ticket", "ref": ticket_key(ticket), "until": iso(until_ts)}
    else:
        if not verify_user_source(user_source):
            raise MissionError("--user-source must be a user: or answer: source that resolves to the user's own words "
                               "(`ah user-msg --recent N` prints it); agent decisions, inferred:, pasted: and tickets "
                               "cannot defer a mission goal")
        deferral = {"by": "user", "source": user_source, "until": iso(until_ts) if until else None}

    def change(goals):
        g = _find(goals, goal_id)
        if ticket and same_ticket(ticket, g.get("ticket")):
            raise MissionError("a goal cannot wait on its own ticket; name the ticket it is blocked by")
        g["deferral"] = deferral
        g["status"] = "deferred" if deferral["by"] == "user" else "active"
        return goals
    return _mutate(home, "defer", goal_id, change, dict(deferral, source=(user_source or "")[:200] or None))


def done_goal(home: Path, goal_id: str, *, deploy: str, live_test: str, session=None) -> list:
    session = session or main_session(home)
    if not session:
        raise MissionError("no session: pass --session (the session whose WALs hold the evidence)")
    evidence = [{"kind": "deploy", "ref": deploy, "session": session},
                {"kind": "really_tested", "ref": live_test, "session": session}]
    state = load_goals(home)
    g = next((x for x in state.get("goals") or [] if x["id"] == goal_id), None)
    if g is None:
        raise MissionError(f"no goal {goal_id!r}")
    why = done_evidence_problem(home, dict(g, done_evidence=evidence))
    if why:
        raise MissionError(f"done refused: {why}. Done means deployed to live and tested live")

    def change(goals):
        x = _find(goals, goal_id)
        x["status"], x["done_evidence"] = "done", evidence
        x.pop("deferral", None)
        return goals
    return _mutate(home, "done", goal_id, change, {"deploy": deploy, "live_test": live_test, "session": session})


def reseal(home: Path, reason: str) -> list:
    if not isinstance(reason, str) or len(reason.strip()) < 20:
        raise MissionError("--reason must say what changed and why (20+ characters)")
    audit = verify_audit(home)
    if audit["ok"]:
        raise MissionError("the audit chain is intact; nothing to reseal")
    return _mutate(home, "reseal", "*", lambda goals: goals, {"reason": reason[:300], "problem": audit["problem"][:300]},
                   allow_broken=True)


def import_initiatives(home: Path, path) -> dict:
    """Merge the dashboard's initiatives.json into goals.json. New ids are added as active goals; existing goals keep
    every field a person set (title, ticket, priority, status, deferral, evidence, repos) and only gain a missing
    ticket and the informational `dashboard` block. Nothing is removed or marked done (a dashboard is not evidence)."""
    try:
        raw = safe_input.read_bounded(path, MAX_GOALS_BYTES)
        rows = safe_input.safe_json_loads(raw, max_depth=MAX_DEPTH)
    except (safe_input.InputRejected, ValueError) as error:
        raise MissionError(f"initiatives file unreadable: {str(error)[:120]}") from None
    if not isinstance(rows, list):
        raise MissionError("initiatives file must be a JSON list")
    counts = {"added": 0, "updated": 0, "skipped": 0}

    def info(r):
        keep = ("state", "status", "owner", "pct", "next_step", "updated")
        return {k: r[k] for k in keep if isinstance(r.get(k), (str, int, float)) and len(str(r[k])) <= 300}

    def change(goals):
        by_id = {g["id"]: g for g in goals}
        for r in rows[:MAX_GOALS]:
            gid = r.get("id") if isinstance(r, dict) else None
            if not isinstance(gid, str) or not ID_RE.match(gid):
                counts["skipped"] += 1
                continue
            title = r.get("initiative") or r.get("name") or gid
            ticket = ticket_key(r.get("ticket")) or ""
            g = by_id.get(gid)
            if g is None:
                g = {"id": gid, "title": str(title)[:300], "ticket": ticket, "priority": 3, "status": "active"}
                goals.append(g)
                by_id[gid] = g
                counts["added"] += 1
            else:
                if not g.get("ticket") and ticket:
                    g["ticket"] = ticket
                counts["updated"] += 1
            g["dashboard"] = info(r)
        return goals
    _mutate(home, "import", "*", change, {"file": os.path.basename(str(path))[:120]})
    return counts


# ------------------------------------------------------------------ verification (sources, evidence)

def claude_dir() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured) if configured else Path.home() / ".claude"


def verify_user_source(source) -> bool:
    """True only for a user: or answer: source that provenance.py resolves to a human-authored turn."""
    if not isinstance(source, str) or not source.strip():
        return False
    try:
        import provenance  # noqa: PLC0415
        parsed = provenance.parse_source(source)
        if parsed.get("kind") != "user" or parsed.get("variant", "user") not in ("user", "answer"):
            return False
        result = provenance.resolve(source, {"home": claude_dir()})
        return bool(result.get("ok") and result.get("origin") == "user" and not result.get("weak"))
    except Exception:  # noqa: BLE001 - an unresolvable source is simply not a user decision
        return False


def done_evidence_problem(home: Path, goal: dict):
    """None when the goal's done_evidence resolves (deploy record, then a live REALLY_TESTED, both naming its ticket);
    otherwise why not."""
    key = ticket_key(goal.get("ticket"))
    if not key:
        return "a done goal needs a ticket its evidence can name"
    rows = goal.get("done_evidence")
    rows = [rows] if isinstance(rows, dict) else (rows or [])
    deploy = next((r for r in rows if isinstance(r, dict) and r.get("kind") == "deploy"), None)
    test = next((r for r in rows if isinstance(r, dict) and r.get("kind") == "really_tested"), None)
    if not deploy or not test:
        return "done needs both a deploy record and a live REALLY_TESTED entry"
    try:
        import ah  # noqa: PLC0415
        slug, number = key.split("#")
        ctx = {"agent": f"mission-goal-{goal.get('id')}", "tasks": set(), "tickets": {ah._norm_ticket(slug, number)},
               "branch": None, "repo": None}
        rec, _ = ah._deploy_record(home, str(deploy.get("session") or ""), deploy["ref"], ctx)
        ah._live_test(home, str(test.get("session") or ""), test["ref"], ctx, parse_ts(rec.get("at")))
    except Exception as error:  # noqa: BLE001 - AhError carries the reason; anything else is unresolved too
        return str(error)[:200] or type(error).__name__
    return None


def verify_done_evidence(home: Path, goal: dict) -> bool:
    return done_evidence_problem(home, goal) is None


def _cached(home: Path, kind: str, key: str, check) -> bool:
    """A positive verification is remembered for a day (keyed by everything it checked), so a Stop does not rescan
    45 MB of WALs per done goal. Negative results are never cached."""
    path = audit_path(home).parent / "mission-verify-cache.json"
    digest = sha(f"{kind}|{key}".encode())
    try:
        cache = safe_input.safe_json_loads(safe_input.read_bounded(path, 256 * 1024), max_depth=4)
        cache = cache if isinstance(cache, dict) else {}
    except (safe_input.InputRejected, ValueError, OSError):
        cache = {}
    now = time.time()
    if isinstance(cache.get(digest), (int, float)) and now - cache[digest] < 86400:
        return True
    ok = bool(check())
    if ok:
        cache = {k: v for k, v in cache.items() if isinstance(v, (int, float)) and now - v < 86400}
        cache[digest] = now
        with contextlib.suppress(OSError):
            _atomic(path, json.dumps(cache).encode())
    return ok


# ------------------------------------------------------------------ owners and progress

def policy():
    try:
        import model_tiers  # noqa: PLC0415
        return model_tiers.load_policy()
    except Exception:  # noqa: BLE001 - a broken tier table leaves the defaults
        return {}


def owner_cap():
    cap = (policy().get("caps") or {}).get("session_owner_agents")
    return int(cap) if isinstance(cap, int) and cap > 0 else None


def _helper_types(pol) -> set:
    return set(((pol or {}).get("caps") or {}).get("helper_types") or HELPERS_DEFAULT)


def _slot_freed(row: dict) -> bool:
    """tier_gate F4: a silent owner frees its slot only for an ending disposition ah does not still flag."""
    disp = row.get("disposition")
    if not isinstance(disp, dict) or row.get("decision_required") is True:
        return False
    kind = disp.get("kind")
    return kind in ("closed", "superseded", "wontdo") or (kind == "reassigned" and disp.get("live") is True)


def live_owner(row, pol=None) -> bool:
    """An `ah owners` row that holds work now: an owner type (never a helper) in a running state."""
    if not isinstance(row, dict) or not isinstance(row.get("agent_id"), str):
        return False
    if str(row.get("type") or "") in _helper_types(pol):
        return False
    state = str(row.get("state") or "")
    if state.startswith(RUNNING):
        return True
    return state.startswith("SILENT") and not _slot_freed(row)


def owner_rows(home: Path, session: str, now=None) -> list:
    import ah  # noqa: PLC0415
    return list(ah.owners(home, session, now=now).get("owners") or [])


def owner_progress(home: Path, session: str, agent: str) -> float:
    """Time of the owner's last own WAL entry (hook lifecycle rows and rows others wrote for it excluded); its first
    WAL row when it has written nothing yet; 0 when there is no WAL."""
    import ah  # noqa: PLC0415
    folder = ah.session_dir(home, session)
    path = folder / f"agent-{agent}.jsonl"
    if not path.is_file():
        path = folder / f"{agent}.jsonl"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", agent or "") or not path.is_file():
        return 0.0
    try:
        tail = safe_input.read_tail(path, 256 * 1024)
        for raw in reversed(tail.split(b"\n")):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict) and rec.get("event") not in LIFECYCLE_EVENTS and rec.get("event") \
                    and (not rec.get("by") or rec.get("by") == agent):
                at = parse_ts(rec.get("at"))
                if at:
                    return at
        fd = safe_input.open_regular_file(path)
        try:
            head = os.pread(fd, 4096, 0)
        finally:
            os.close(fd)
        first = json.loads(head.split(b"\n", 1)[0])
        return parse_ts(first.get("at")) if isinstance(first, dict) else 0.0
    except (OSError, ValueError, safe_input.InputRejected):
        return 0.0


def commit_progress(repos, key: str) -> float:
    """Newest commit time naming the ticket (by number) on any branch of the goal's repos; 0 when none."""
    if not key or not repos:
        return 0.0
    number = key.split("#")[1]
    best = 0.0
    for repo in repos[:10]:
        try:
            p = subprocess.run(["git", "-C", repo, "log", "--all", "-1", "--format=%ct", "-E", "-i",
                                f"--grep=#{number}([^0-9]|$)"], capture_output=True, text=True, timeout=5)
            if p.returncode == 0 and p.stdout.strip().isdigit():
                best = max(best, float(p.stdout.strip()))
        except (OSError, subprocess.SubprocessError):
            continue
    return best


def main_session(home: Path) -> str:
    env = os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or ""
    if env:
        return env
    try:
        import ah  # noqa: PLC0415
        return ah.newest_session(home) or ""
    except Exception:  # noqa: BLE001
        return ""


# ------------------------------------------------------------------ the rule (pure)

def deferral_status(goal: dict, now: float, asks: dict, verify_source):
    """(state, reason): state WAITING or DEFERRED when the deferral is live, else None with why not."""
    d = goal.get("deferral")
    if not isinstance(d, dict):
        return None, "no live owner and no deferral"
    until = parse_ts(d.get("until")) if d.get("until") else 0.0
    by = d.get("by")
    if by in ("ask", "ticket"):
        if not until or until <= now:
            return None, f"its wait on {d.get('ref')} expired {d.get('until') or '(no until)'}"
        if until - now > WAIT_MAX_S:
            return None, f"its wait on {d.get('ref')} runs past 7 days (renew it, never park a goal)"
        if by == "ask":
            state = (asks or {}).get(str(d.get("ref") or ""))
            if not ASK_ID_RE.match(str(d.get("ref") or "")) or state != "open":
                return None, f"it waits on ask {d.get('ref')}, which is {state or 'unknown'} in main's WAL"
            return "WAITING", f"waits on open ask {d['ref']} until {d['until']}"
        if not ticket_key(d.get("ref")) or same_ticket(d.get("ref"), goal.get("ticket")):
            return None, "a ticket wait must name another ticket"
        return "WAITING", f"waits on {ticket_key(d['ref'])} until {d['until']}"
    if by == "user":
        if d.get("until") and (not until or until <= now):
            return None, f"the user's deferral ended {d.get('until')}"
        if not verify_source(d.get("source")):
            return None, "its deferral source does not resolve to the user's own words (user: or answer:)"
        return "DEFERRED", "deferred by the user" + (f" until {d['until']}" if d.get("until") else "")
    return None, "unknown deferral kind"


def evaluate(goals, rows, now, asks=None, verify_source=None, verify_evidence=None, progress=None, commits=None,
             pol=None, stall_s: int = STALL_S) -> list:
    """One result per goal: {id, title, ticket, priority, status, state, reason, owners, progress_age_s}. state is
    UNCOVERED, STALLED, COVERED, WAITING, DEFERRED or DONE. Owners come only from `rows` (ah owners)."""
    verify_source = verify_source or verify_user_source
    verify_evidence = verify_evidence or (lambda g: False)
    progress, commits = progress or {}, commits or {}
    live = [r for r in rows or [] if live_owner(r, pol)]
    out = []
    for g in goals:
        key = ticket_key(g.get("ticket"))
        res = {"id": g["id"], "title": g.get("title") or g["id"], "ticket": key or "", "priority": g.get("priority", 3),
               "status": g.get("status", "active"), "owners": [], "progress_age_s": None, "state": "UNCOVERED",
               "reason": ""}
        out.append(res)
        if res["status"] == "done":
            if verify_evidence(g):
                res["state"], res["reason"] = "DONE", "done with deploy and live-test evidence"
            else:
                res["reason"] = "marked done but its done_evidence does not resolve (deploy record + live REALLY_TESTED)"
            continue
        owners = [r for r in live if key and same_ticket(r.get("ticket"), key)]
        if owners:
            res["owners"] = sorted(r["agent_id"] for r in owners)
            last = max([progress.get(r["agent_id"]) or parse_ts(r.get("last_activity")) for r in owners]
                       + [commits.get(key) or 0.0])
            res["progress_age_s"] = int(max(0.0, now - last)) if last else None
            stalled = res["progress_age_s"] is None or res["progress_age_s"] > stall_s
            res["state"] = "STALLED" if stalled else "COVERED"
            res["reason"] = (f"owner {', '.join(res['owners'])}: no WAL entry or commit on {key} for "
                             f"{fmt_age(res['progress_age_s'])}" if stalled else f"owner {', '.join(res['owners'])}")
            continue
        state, why = deferral_status(g, now, asks, verify_source)
        if state:
            res["state"], res["reason"] = state, why
            continue
        if not key:
            why = "it has no ticket, so no owner can be matched to it (set one: " \
                  f"`{SCRIPT} set --goal {g['id']} --ticket goodqa#N`); " + why
        else:
            why = f"no live owner whose stream ticket is {key}; " + why
        res["reason"] = why
    return out


_ORDER = {"UNCOVERED": 0, "STALLED": 1, "COVERED": 2, "WAITING": 3, "DEFERRED": 3, "DONE": 4}


def sort_report(results) -> list:
    """Slowest first: UNCOVERED (by priority), STALLED (oldest progress first), covered (least recent progress
    first), then waiting/deferred, then done."""
    def key(r):
        rank = _ORDER.get(r["state"], 0)
        age = r.get("progress_age_s")
        if rank in (1, 2):
            return (rank, -(age if age is not None else 10 ** 9), r["id"])
        return (rank, r.get("priority", 3), r["id"])
    return sorted(results, key=key)


def cap_candidates(results, rows, cap, pol=None) -> list:
    """When the owner cap is full and a goal is uncovered: the live owners to free or queue, best candidate first.
    Owners on no mission goal go first (most idle first), then owners of the lowest-priority, most stalled goals.
    [] when the cap is not full or nothing is uncovered."""
    uncovered = [r for r in results if r["state"] == "UNCOVERED"]
    live = [r for r in rows or [] if live_owner(r, pol)]
    if not cap or not uncovered or len(live) < cap:
        return []
    goal_of = {}
    for res in results:
        for agent in res.get("owners") or []:
            goal_of.setdefault(agent, res)

    def rank(r):
        res = goal_of.get(r["agent_id"])
        idle = int(r.get("idle_s") or max(0.0, time.time() - parse_ts(r.get("last_activity"))))
        if res is None:
            return (0, 0, -idle, r["agent_id"])
        return (1, -int(res.get("priority", 3)), -(res.get("progress_age_s") or 0), r["agent_id"])
    def describe(r):
        res = goal_of.get(r["agent_id"])
        if res is None:
            return f"{r['agent_id']} ({r.get('ticket') or 'no ticket'}, on no mission goal)"
        return (f"{r['agent_id']} (goal {res['id']} priority {res['priority']}, "
                f"progress {fmt_age(res.get('progress_age_s'))} ago)")
    return [{"agent_id": r["agent_id"], "text": describe(r), "live": len(live)} for r in sorted(live, key=rank)]


def cap_advice(results, rows, cap, pol=None) -> str:
    """The named owner to free or queue (and the queue option) when the cap is full and a goal is uncovered."""
    ranked = cap_candidates(results, rows, cap, pol)
    if not ranked:
        return ""
    first = next(r for r in sort_report(results) if r["state"] == "UNCOVERED")
    queue_ticket = first["ticket"] or "<its ticket>"
    return (f"owner cap full ({ranked[0]['live']}/{cap}): free or queue {ranked[0]['text']}"
            + (f"; next candidates {', '.join(r['text'] for r in ranked[1:3])}" if len(ranked) > 1 else "")
            + f". Or queue the goal on ticket {queue_ticket}: `{SCRIPT} defer --goal {first['id']} --ticket "
              f"<ticket it waits on> --until <ISO>` and comment on {queue_ticket} that it is queued for the next free slot.")


_STALE_DISPOSITION = ("expired", "ended", "which is", "does not resolve", "past 7 days", "another ticket")


def coverage_map(results, victim=None) -> dict:
    """Mission Control's coverage override map: {goal id and its ticket: {status: uncovered|stalled|moving, reason,
    action}}; reason and action are one plain sentence each. The slowest goal wins a ticket two goals share."""
    out = {}
    for r in sort_report(results):
        t = r["ticket"]
        if r["state"] == "UNCOVERED":
            status = "uncovered"
            if r["status"] == "done":
                reason = "It is marked done but its deploy and live-test evidence does not resolve."
                action = "Record the deploy and live test with mission_coverage.py done, or set it active again."
            elif not t:
                reason = "It has no ticket, so no owner can be matched to it."
                action = f"Give it a ticket with mission_coverage.py set --goal {r['id']} --ticket goodqa#N, then start an owner."
            elif any(word in r["reason"] for word in _STALE_DISPOSITION):
                reason = "No live owner, and its disposition is no longer live."
                action = f"Start an owner on {t}, or record a fresh wait with mission_coverage.py defer."
            else:
                reason = "No live owner and no disposition."
                action = f"Start an owner on {t}, or record what it waits on with mission_coverage.py defer."
            if victim:
                action = action[:-1] + f"; the owner cap is full, so first free or queue owner {victim}."
        elif r["state"] == "STALLED":
            who = ", ".join(r["owners"])
            status = "stalled"
            reason = f"Owner {who} has made no WAL entry or commit on {t} for {fmt_age(r['progress_age_s'])}."
            action = f"Check on {who} and get a progress note or commit, or reassign {t}."
        else:
            status = "moving"
            reason = {"COVERED": f"Owner {', '.join(r['owners'])} is working on it.",
                      "WAITING": f"It {r['reason']}.", "DEFERRED": f"It was {r['reason']}.",
                      "DONE": "It is done with deploy and live-test evidence."}.get(r["state"], f"{r['reason']}.")
            action = "Follow up when the wait ends." if r["state"] == "WAITING" else "No action needed."
        entry = {"status": status, "reason": reason, "action": action}
        out.setdefault(r["id"], entry)
        if t:
            out.setdefault(t, entry)
    return out


def gate_message(results, advice: str = "") -> str:
    lines = []
    for r in sort_report([x for x in results if x["state"] == "UNCOVERED"]):
        g, t = r["id"], r["ticket"] or "no ticket"
        lines.append(f"  - {g} ({t}, priority {r['priority']}): {r['reason']}\n"
                     f"      fix one of: start an owner on {t} (its first WAL intent names {t}); or\n"
                     f"      {SCRIPT} defer --goal {g} --ask <open ask id> --until <ISO>\n"
                     f"      {SCRIPT} defer --goal {g} --ticket <blocking ticket> --until <ISO>\n"
                     f"      {SCRIPT} defer --goal {g} --user-source '<user:... \"the user's words\">' [--until <ISO>]\n"
                     f"      {SCRIPT} done --goal {g} --deploy <deploy WAL id> --live-test <REALLY_TESTED id>")
    text = (f"Mission coverage (goodqa#15565): {len(lines)} active goal(s) have no live owner, no live disposition "
            "and no done evidence:\n" + "\n".join(lines))
    if advice:
        text += "\n" + advice
    return text + "\nA goal nobody holds is a dropped goal: give it an owner, name what it waits on, or prove it done."


def mission_alerts(assessment: dict) -> list:
    """ops-watch alert dicts for an assessment: mission:<goal>:uncovered (high, stop_block) and mission:<goal>:stalled
    (warning); mission:goals:unreadable (high) when the file cannot be trusted."""
    state = assessment.get("state")
    if state in ("error", "tampered"):
        return [{"check": "mission", "key": "mission:goals:unreadable", "severity": "high",
                 "message": f"mission goals file cannot be trusted: {assessment.get('error')}",
                 "detail": {"stop_block": True}}]
    out = []
    for r in assessment.get("results") or [] if state == "ok" else []:
        if r["state"] == "UNCOVERED":
            out.append({"check": "mission", "key": f"mission:{r['id']}:uncovered", "severity": "high",
                        "message": f"mission goal {r['id']} ({r['ticket'] or 'no ticket'}) UNCOVERED: {r['reason']}"[:400],
                        "detail": {"goal": r["id"], "ticket": r["ticket"], "priority": r["priority"],
                                   "stop_block": True}})
        elif r["state"] == "STALLED":
            out.append({"check": "mission", "key": f"mission:{r['id']}:stalled", "severity": "warning",
                        "message": f"mission goal {r['id']} ({r['ticket']}) STALLED: {r['reason']}"[:400],
                        "detail": {"goal": r["id"], "ticket": r["ticket"], "owners": r["owners"],
                                   "age_min": (r["progress_age_s"] or 0) // 60, "stop_block": False}})
    return out


# ------------------------------------------------------------------ assessment (I/O around the rule)

def assess(home: Path, session: str, now=None, with_commits: bool = False) -> dict:
    """{"state": absent|error|tampered|owners-unavailable|ok, "results", "advice", "error"}."""
    now = time.time() if now is None else now
    loaded = load_goals(home)
    if loaded["state"] == "absent":
        return {"state": "absent", "results": []}
    if loaded["state"] == "error":
        return {"state": "error", "results": [], "error": f"goals file unreadable: {loaded['error']}"}
    audit = verify_audit(home)
    if not audit["ok"]:
        return {"state": "tampered", "results": [], "error": audit["problem"]}
    try:
        rows = owner_rows(home, session, now)
    except Exception as error:  # noqa: BLE001 - no main WAL here or an ah defect: say so, never guess coverage
        return {"state": "owners-unavailable", "results": [], "error": f"{type(error).__name__}: {str(error)[:120]}"}
    pol = policy()
    goals = loaded["goals"]
    keys = {ticket_key(g.get("ticket")) for g in goals} - {None}
    covering = [r for r in rows if live_owner(r, pol) and ticket_key(r.get("ticket")) in keys]
    progress = {r["agent_id"]: owner_progress(home, session, r["agent_id"]) for r in covering}
    commits = {}
    if with_commits:
        for g in goals:
            key = ticket_key(g.get("ticket"))
            if key and g.get("repos"):
                commits[key] = max(commits.get(key, 0.0), commit_progress(g["repos"], key))
    asks = ask_states(home, session)
    results = evaluate(goals, rows, now, asks=asks,
                       verify_source=lambda s: _cached(home, "source", str(s), lambda: verify_user_source(s)),
                       verify_evidence=lambda g: _cached(home, "evidence", json.dumps(
                           [g.get("ticket"), g.get("done_evidence")], sort_keys=True),
                           lambda: verify_done_evidence(home, g)),
                       progress=progress, commits=commits, pol=pol)
    cap = owner_cap()
    ranked = cap_candidates(results, rows, cap, pol)
    return {"state": "ok", "results": results, "advice": cap_advice(results, rows, cap, pol), "session": session,
            "victim": ranked[0]["agent_id"] if ranked else None}


# ------------------------------------------------------------------ waking main (Mission Control inbox + ring)

def _load_chat():
    try:
        import mc_chat  # noqa: PLC0415 - GoodQA #15585, not on every install yet
        return mc_chat
    except Exception:  # noqa: BLE001
        return None


def _ring_emit(home: Path, event: str, severity: str, message: str, detail: dict) -> None:
    try:
        import ops_watch  # noqa: PLC0415
        ring = ops_watch.ring_path(home)
        key = "mission:notify"
        latest = None
        for e in ops_watch.read_ring(ring):
            if e.get("source") == "mission-coverage" and e.get("key") == key:
                latest = e
        if event == "clear" and (latest is None or latest.get("event") != "raise"):
            return
        ops_watch.emit({"host": ops_watch.default_host(), "source": "mission-coverage", "event": event,
                        "severity": severity, "key": key, "message": message, "detail": detail}, path=ring)
    except Exception:  # noqa: BLE001 - best effort; the per-goal ops-watch alerts still stand
        pass


def notify_main(goal_ids, home=None, session=None, chat=None) -> None:
    """Wake the orchestrator when goals become UNCOVERED: a `mission:notify` ring event always, and a Mission Control
    inbox message through mc_chat when it is installed and main has registered a target. An empty list clears."""
    home = Path(home or home_dir())
    ids = sorted({str(g) for g in goal_ids or [] if isinstance(g, str) and ID_RE.match(g)})
    if not ids:
        _ring_emit(home, "clear", "warning", "mission goals covered again", {"goals": []})
        return
    text = (f"MISSION-COVERAGE ALERT from the harness (mission_coverage.py), not typed by the user: goal(s) "
            f"{', '.join(ids)} have no live owner, no live disposition and no done evidence. Run `{SCRIPT} report` "
            "and give each an owner, a named wait, or done evidence.")
    _ring_emit(home, "raise", "warning", text[:300], {"goals": ids[:20], "stop_block": False})
    chat = chat if chat is not None else _load_chat()
    if chat is None or not session:
        return
    client_key = "mission-" + sha(("|".join(ids) + f"|{int(time.time() // 3600)}").encode())[:24]
    try:
        chat.new_message("claude", text, client_key=client_key, session=session, thread="mission")
    except Exception:  # noqa: BLE001 - no registered target, a refusal or an older mc_chat: the ring event stands
        pass


# ------------------------------------------------------------------ CLI

def build_parser():
    p = argparse.ArgumentParser(prog="mission_coverage.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="add an active goal")
    a.add_argument("--goal", required=True)
    a.add_argument("--title", required=True)
    a.add_argument("--ticket", default="")
    a.add_argument("--priority", type=int, default=3)
    s = sub.add_parser("set", help="change title, ticket, priority, repos, or set status active")
    s.add_argument("--goal", required=True)
    s.add_argument("--title")
    s.add_argument("--ticket")
    s.add_argument("--priority", type=int)
    s.add_argument("--status", choices=STATUSES)
    s.add_argument("--repo", action="append", dest="repos")
    s.add_argument("--clear-deferral", action="store_true")
    d = sub.add_parser("defer", help="record what a goal waits on, or the user's deferral")
    d.add_argument("--goal", required=True)
    d.add_argument("--ask")
    d.add_argument("--ticket")
    d.add_argument("--user-source")
    d.add_argument("--until")
    d.add_argument("--session")
    n = sub.add_parser("done", help="mark a goal done with deploy + live-test evidence")
    n.add_argument("--goal", required=True)
    n.add_argument("--deploy", required=True)
    n.add_argument("--live-test", required=True)
    n.add_argument("--session")
    i = sub.add_parser("import-initiatives", help="merge the dashboard initiatives.json into goals.json")
    i.add_argument("file")
    r = sub.add_parser("reseal", help="record a goals file changed outside this tool (audited)")
    r.add_argument("--reason", required=True)
    sub.add_parser("verify", help="check the audit chain")
    for name in ("report", "check"):
        x = sub.add_parser(name, help="coverage report, slowest first" if name == "report" else "exit 1 when uncovered")
        x.add_argument("--json", action="store_true")
        x.add_argument("--session")
    return p


def run(args, home: Path) -> tuple:
    if args.cmd == "add":
        add_goal(home, args.goal, args.title, args.ticket, args.priority)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "set":
        set_goal(home, args.goal, title=args.title, ticket=args.ticket, priority=args.priority, status=args.status,
                 repos=args.repos, clear_deferral=args.clear_deferral)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "defer":
        defer_goal(home, args.goal, ask=args.ask, ticket=args.ticket, user_source=args.user_source, until=args.until,
                   session=args.session)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "done":
        done_goal(home, args.goal, deploy=args.deploy, live_test=args.live_test, session=args.session)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "import-initiatives":
        return dict(import_initiatives(home, args.file), ok=True), 0
    if args.cmd == "reseal":
        reseal(home, args.reason)
        return {"ok": True}, 0
    if args.cmd == "verify":
        result = verify_audit(home)
        return result, 0 if result["ok"] else 2
    a = assess(home, args.session or main_session(home), with_commits=(args.cmd == "report"))
    results = sort_report(a.get("results") or [])
    uncovered = [r["id"] for r in results if r["state"] == "UNCOVERED"]
    doc = {"state": a["state"], "error": a.get("error"), "generated": iso(time.time()), "uncovered": uncovered,
           "goals": results, "advice": a.get("advice") or "",
           "coverage": coverage_map(results, a.get("victim"))}
    rc = 2 if a["state"] in ("error", "tampered", "owners-unavailable") else (1 if uncovered and args.cmd == "check" else 0)
    return doc, rc


def render(doc: dict) -> str:
    if "goals" not in doc:
        return json.dumps(doc, indent=1)
    if doc.get("error"):
        return f"mission coverage: {doc['state']}: {doc['error']}"
    lines = [f"Mission coverage, slowest first ({len(doc['uncovered'])} uncovered):"]
    for r in doc["goals"]:
        age = f" {fmt_age(r['progress_age_s'])}" if r.get("progress_age_s") is not None else ""
        lines.append(f"  {r['state']:<9} {r['id']} ({r['ticket'] or 'no ticket'}, p{r['priority']}){age}: {r['reason']}")
    if doc.get("advice"):
        lines.append(doc["advice"])
    return "\n".join(lines)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        doc, rc = run(args, home_dir())
    except MissionError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(doc, indent=1) if getattr(args, "json", False) or args.cmd not in ("report", "check")
          else render(doc))
    return rc


if __name__ == "__main__":
    sys.exit(main())
