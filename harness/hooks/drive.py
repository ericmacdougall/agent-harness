#!/usr/bin/env python3
"""Drive loop (`ah drive`): walk EVERY initiative in the mission ledger and say what must happen next
(owner-runtime-drive, GoodQA goodqa#15968).

Evidence: 2026-11-14 the user asked "why isnt something asking this exact question [...] and then forcing you to
add/adjust/push owners [...] capacity is arbitrary". The ledger then held six goals, all `imported`, which
mission_gate never enforces, so its report read "0 uncovered" while QAC parity, Fabric, ParentProof and GoodQA launch
pieces sat ownerless or merged but not released, and main spent the night on harness review rounds.

For every goal in ~/.agent-harness/mission/goals.json, whatever its status, drive computes conditions, and each
condition carries the action that must follow:
  IMPORTED             status imported: never enforced     -> activate it (main) or retire it with the user's words
  UNOWNED              no owner_rt owner and no live owner -> create an owner (owner_rt init + task add --wake)
  STALLED              owner without resolving proof in 30 min -> resume it, escalate it, or replace it
  STUCK                owner_rt stopped relaunching (launches without proof) -> look at it, re-scope or replace it
  HELP_OPEN            an owner task is blocked with a help request -> unblock it, ask the user, or route a ticket
  REVIEW_LOOP          an owner task had 2+ rejected review rounds -> redesign, escalate, or park on a ticket
  MERGED_NOT_RELEASED  a commit naming the goal's ticket on a goal repo is newer than its last deploy -> release it
  PENDING_GATES        lifecycle pending with no gate proposal -> propose gates (an ask); building never pauses
Capacity is never a reason for no action: there is no "queue" or "none" action for an open condition.
DONE goals (status done/retired, or a lifecycle done block) show with no conditions. BLOCKED on the user (a deferral
by ask) is shown in the row; it never excuses UNOWNED, because other facets still need an owner.

A condition clears itself when the fact changes. Until then main may record a response (`drive.py respond`), which
counts only as a FACT checked when it is recorded and bound to the condition's episode (it must be newer than the
moment the condition appeared, and younger than RESPONSE_TTL_S):
  ask      an open ask in the mission session's main WAL whose text names the goal
  owner    an owner_rt launch for the goal newer than the episode (STALLED, STUCK, UNOWNED)
  ticket   a ticket reference (REVIEW_LOOP park, HELP_OPEN routed, MERGED_NOT_RELEASED release scheduled)
  park     a user:/answer: source that provenance resolves to the user's own words naming the goal
Agent text, inferred:, wal: and queue: sources never park anything.

Enforcement: `drive.py stop` is a Stop hook for the main session that owns the mission. It reads the snapshot that
`drive.py tick` writes (ops_watch runs it every cycle, after owner_rt tick) and the response ledger; it never scans
owners itself. It blocks while any action has no counting response, at most MAX_STOP_BLOCKS times per signature; past
that it lets the turn end, keeps the action open and raises a high `drive:valve` ops alert. It fails open on its own
errors. ops_watch raises one alert per unanswered action and wakes main through Mission Control.
Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import contextlib
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
import owner_rt as ort  # noqa: E402

RESPONSE_TTL_S = 4 * 3600
SNAPSHOT_MAX_S = 30 * 60
MAX_STOP_BLOCKS = 3
CONDITIONS = ("IMPORTED", "UNOWNED", "STALLED", "STUCK", "HELP_OPEN", "REVIEW_LOOP", "MERGED_NOT_RELEASED",
              "PENDING_GATES")
ACTIONS = {
    "IMPORTED": "activate it (`mission_coverage.py activate --goal {g}`) or retire it with the user's words",
    "UNOWNED": "create its owner: `owner_rt.py init --goal {g} --cwd <workspace> --source <src>` then "
               "`owner_rt.py task add --goal {g} --text <next step> --source <src> --wake`",
    "STALLED": "resume the owner (`owner_rt.py tick`), escalate it a rung, or replace it",
    "STUCK": "the owner was relaunched with no new proof: read `owner_rt.py show --goal {g}`, re-scope or replace it",
    "HELP_OPEN": "unblock {detail}, ask the user one question, or route it to a ticket",
    "REVIEW_LOOP": "break the loop on {detail}: redesign, escalate a rung, or park it on a ticket",
    "MERGED_NOT_RELEASED": "schedule the release of {detail} (deploy + live test)",
    "PENDING_GATES": "propose its gates to the user (one AskUserQuestion naming the goal); keep building meanwhile",
}
RESPONSE_KINDS = {
    "IMPORTED": ("park",), "UNOWNED": ("owner", "park"), "STALLED": ("owner", "park"), "STUCK": ("owner", "park"),
    "HELP_OPEN": ("ask", "ticket", "park"), "REVIEW_LOOP": ("ticket", "park"),
    "MERGED_NOT_RELEASED": ("ticket", "ask", "park"), "PENDING_GATES": ("ask", "park"),
}
TICKET_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9-]{0,62})?#[1-9][0-9]{0,9}$")
SCRIPT = "python3 ~/.claude/hooks/drive.py"


class DriveError(ValueError):
    pass


def home_dir() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def state_dir(home: Path) -> Path:
    return home / ".agent-harness" / "state" / "drive"


def _mc():
    import mission_coverage  # noqa: PLC0415 - installed beside this file
    return mission_coverage


def mission_session(home: Path) -> str:
    try:
        return _mc().mission_session_of(home) or ""
    except Exception:  # noqa: BLE001
        return ""


def ticket_number(ticket) -> str:
    m = re.search(r"#\s*([1-9][0-9]{0,9})", str(ticket or ""))
    return m.group(1) if m else ""


# ------------------------------------------------------------------ facts per goal

def lifecycle_state(home: Path, goal: dict) -> str:
    """goodqa#15952 effective state when lifecycle.py is installed (unverified reads pending); '' when it is not."""
    try:
        import lifecycle  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return ""
    try:
        mc = _mc()
        rows = mc.read_audit_rows(home) if hasattr(mc, "read_audit_rows") else []
        state, _note = lifecycle.effective_state(goal, rows, True)
        return "pending" if state in ("unverified", None, "") else str(state)
    except Exception:  # noqa: BLE001
        lc = goal.get("lifecycle")
        return str(lc.get("state")) if isinstance(lc, dict) and lc.get("state") else "pending"


def legacy_owners(home: Path, session: str, goal: dict, rows) -> list:
    """Live owner-type sub-agents of the mission session that hold this goal (ops-watch's signed snapshot)."""
    if not rows:
        return []
    try:
        mc = _mc()
        key = mc.ticket_key(goal.get("ticket"))
        return [r.get("agent_id") for r in rows if mc.live_owner(r) and mc._matches(r, goal, key)]
    except Exception:  # noqa: BLE001
        return []


def deploy_ts(goal: dict) -> float:
    best = 0.0
    for ev in (goal.get("evidence") or []) + (goal.get("done_evidence") or []):
        if isinstance(ev, dict) and ev.get("kind") == "deploy":
            with contextlib.suppress(Exception):
                best = max(best, ort_parse(ev.get("at")))
    return best


def ort_parse(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    import datetime as dt  # noqa: PLC0415
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def merged_commit_ts(goal: dict, runner=None) -> float:
    """Newest commit naming the goal's ticket on a repo's default remote branch (merged), 0 when none."""
    number = ticket_number(goal.get("ticket"))
    repos = [r for r in (goal.get("repos") or []) if isinstance(r, str)][:6]
    if not number or not repos:
        return 0.0
    best = 0.0
    for repo in repos:
        for ref in ("origin/HEAD", "origin/main", "origin/master"):
            try:
                p = subprocess.run(["git", "-C", repo, "log", ref, "-1", "--since=30.days", "--format=%ct", "-E", "-i",
                                    f"--grep=#{number}([^0-9]|$)"], capture_output=True, text=True, timeout=5)
            except (OSError, subprocess.SubprocessError):
                break
            if p.returncode == 0:
                if p.stdout.strip().isdigit():
                    best = max(best, float(p.stdout.strip()))
                break
    return best


def owner_view(home: Path, goal_id: str, now: float):
    try:
        st = ort.load_state(home, goal_id)
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001
        return {"error": ort.clean(str(exc), 160)}
    tmap = ort.tasks(ort.inbox_rows(home, goal_id))
    age = ort.proof_age(st, now)
    launches = st.get("launches") or []
    return {"session_id": st.get("session_id"), "bg_id": st.get("bg_id"), "generation": st.get("generation"),
            "stuck": bool(st.get("stuck")), "proof_age_s": None if age == float("inf") else int(age),
            "created_ts": ort_parse(st.get("created_at")) if st.get("created_at") else 0.0,
            "last_launch_ts": float(launches[-1].get("ts", 0)) if launches else 0.0,
            "next": (st.get("last_beat") or {}).get("next") or "",
            "checkpoint": ((st.get("checkpoint") or {}).get("text") or "")[:200],
            "open": [t["id"] for t in ort.actionable(tmap)],
            "help": [{"task": t["id"], "need": t["help"][:160]} for t in tmap.values() if t["state"] == "blocked"],
            "loops": [t["id"] for t in tmap.values() if t["loop"]],
            "states": sorted({t["state"] for t in tmap.values()}),
            "first_open": next((t["text"][:160] for t in ort.actionable(tmap)), "")}


def distance(goal: dict, owner, conds: set, done: bool) -> str:
    if done:
        return "done"
    kinds = {e.get("kind") for e in (goal.get("evidence") or []) if isinstance(e, dict)}
    if "live_test" in kinds:
        return "live-tested, not declared done"
    if "deploy" in kinds and "MERGED_NOT_RELEASED" not in conds:
        return "deployed, live test pending"
    if "MERGED_NOT_RELEASED" in conds:
        return "merged, not released"
    states = set((owner or {}).get("states") or [])
    for s, label in (("verifying", "verifying"), ("building", "building"), ("converged", "planned and converged"),
                     ("planned", "planning (AC written)"), ("queued", "tasks queued")):
        if s in states:
            return label
    return "not started" if not owner else "owner, no tasks"


def assess(home: Path, session: str = "", now=None, owner_rows=None, with_git: bool = True) -> dict:
    now = time.time() if now is None else now
    goals = ort.mission_goals(home)
    rows_out = []
    for gid, g in goals.items():
        done = ort.goal_done(g)
        status = str(g.get("status") or "")
        owner = owner_view(home, gid, now)
        legacy = legacy_owners(home, session, g, owner_rows)
        lc = lifecycle_state(home, g)
        conds = []
        if not done and not (status == "deferred" and _deferral_by_user(g)):
            if status == "imported":
                conds.append(("IMPORTED", ""))
            if owner is None and not legacy:
                conds.append(("UNOWNED", ""))
            if owner and not owner.get("error"):
                age = owner.get("proof_age_s")
                start = max(owner.get("created_ts") or 0.0, owner.get("last_launch_ts") or 0.0)
                if owner["stuck"]:
                    conds.append(("STUCK", ""))
                elif (age is None and now - start > ort.PROOF_S) or (age is not None and age > ort.PROOF_S):
                    conds.append(("STALLED", ""))
                for h in owner["help"]:
                    conds.append(("HELP_OPEN", f"{h['task']}: {h['need']}"))
                for t in owner["loops"]:
                    conds.append(("REVIEW_LOOP", t))
            if with_git:
                mts = merged_commit_ts(g)
                if mts and mts > deploy_ts(g):
                    conds.append(("MERGED_NOT_RELEASED", f"ticket {g.get('ticket')}"))
            if lc == "pending":
                lcd = g.get("lifecycle") if isinstance(g.get("lifecycle"), dict) else {}
                if not lcd.get("ask") and not lcd.get("gates"):
                    conds.append(("PENDING_GATES", ""))
        deferral = g.get("deferral") if isinstance(g.get("deferral"), dict) else {}
        blocker = ""
        if deferral:
            blocker = f"waits on {deferral.get('by')} {deferral.get('ref') or ''}".strip()
        elif owner and owner.get("help"):
            blocker = "; ".join(f"{h['task']}: {h['need']}" for h in owner["help"])[:200]
        actions = [{"cond": c, "detail": d, "key": action_key(gid, c, d),
                    "action": ACTIONS[c].format(g=gid, detail=d or gid)} for c, d in conds]
        rows_out.append({
            "goal": gid, "title": ort.clean(g.get("title"), 80), "ticket": g.get("ticket") or "",
            "priority": g.get("priority", 9), "status": status, "lifecycle": lc, "done": done,
            "owner": ("owner_rt gen %s" % owner.get("generation")) if owner and not owner.get("error") else
                     (("agents " + ", ".join(a[:8] for a in legacy)) if legacy else "NONE"),
            "owner_detail": owner, "legacy_owners": legacy,
            "proof_age_s": (owner or {}).get("proof_age_s"),
            "next": (owner or {}).get("next") or (owner or {}).get("first_open") or
                    (actions[0]["action"] if actions else ""),
            "blocker": blocker, "distance": distance(g, owner, {c for c, _ in conds}, done),
            "actions": actions})
    rows_out.sort(key=lambda r: (r["done"], -len(r["actions"]), r["priority"], r["goal"]))
    return {"at": now, "session": session, "rows": rows_out}


def action_key(goal_id: str, cond: str, detail: str = "") -> str:
    """goal:cond, plus the task id for the per-task conditions (HELP_OPEN, REVIEW_LOOP)."""
    if cond in ("HELP_OPEN", "REVIEW_LOOP") and detail:
        return f"{goal_id}:{cond}:{detail.split(':')[0].strip()[:40]}"
    return f"{goal_id}:{cond}"


def _deferral_by_user(goal: dict) -> bool:
    d = goal.get("deferral")
    return isinstance(d, dict) and d.get("by") == "user"


# ------------------------------------------------------------------ episodes, snapshot, responses

def _safe_dir(home: Path) -> Path:
    d = state_dir(home)
    ort._no_links(d, home / ".agent-harness")
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    ort._no_links(d, home / ".agent-harness")
    return d


def snapshot_path(home: Path) -> Path:
    return state_dir(home) / "snapshot.json"


def responses_path(home: Path) -> Path:
    return state_dir(home) / "responses.jsonl"


def load_snapshot(home: Path):
    try:
        data = json.loads(ort._read(snapshot_path(home), 8 << 20).decode("utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("rows"), list) else None
    except (OSError, ValueError, ort.OwnerError):
        return None


def with_episodes(home: Path, assessment: dict, prev=None) -> dict:
    """Carry each action's first-seen time (episode start) over from the previous snapshot; new actions start now."""
    prev = prev if prev is not None else (load_snapshot(home) or {})
    since = {}
    for r in prev.get("rows") or []:
        for a in r.get("actions") or []:
            if isinstance(a, dict) and isinstance(a.get("since"), (int, float)):
                since[a.get("key")] = a["since"]
    for r in assessment["rows"]:
        for a in r["actions"]:
            a["since"] = since.get(a["key"], assessment["at"])
    return assessment


def tick(home: Path, session: str = "", now=None, owner_rows=None) -> dict:
    session = session or mission_session(home)
    if owner_rows is None and session:
        with contextlib.suppress(Exception):
            snap = _mc().load_owner_snapshot(home, session, now)
            owner_rows = (snap or {}).get("rows")
    a = with_episodes(home, assess(home, session, now, owner_rows))
    d = _safe_dir(home)
    ort._atomic(d / "snapshot.json", a)
    return a


def read_responses(home: Path) -> list:
    try:
        raw = ort._read(responses_path(home), 8 << 20).decode("utf-8", "replace")
    except (OSError, ort.OwnerError):
        return []
    out = []
    for line in raw.splitlines():
        with contextlib.suppress(ValueError):
            r = json.loads(line)
            if isinstance(r, dict):
                out.append(r)
    return out


def check_response(home: Path, goal_id: str, cond: str, kind: str, ref: str, source: str, session: str,
                   goal: dict, now: float) -> str:
    """'' when the response is a fact for this goal and condition; else why not."""
    if cond not in CONDITIONS:
        return f"unknown condition {cond}"
    if kind not in RESPONSE_KINDS[cond]:
        return f"{cond} takes a response of kind {', '.join(RESPONSE_KINDS[cond])}, not {kind}"
    mc = _mc()
    if kind == "ask":
        state, note = mc._ask(mc.ask_states(home, session), ref)
        if state != "open":
            return f"ask {ref} is not an open ask of the mission session"
        if not mc.names_goal(note, goal) and goal_id not in note:
            return f"ask {ref} does not name goal {goal_id}"
        return ""
    if kind == "owner":
        try:
            st = ort.load_state(home, goal_id)
        except Exception:  # noqa: BLE001
            return f"goal {goal_id} has no owner_rt owner"
        launches = st.get("launches") or []
        if not launches or launches[-1].get("code") != 0:
            return "the owner has no successful launch"
        return ""
    if kind == "ticket":
        return "" if TICKET_RE.match(ref or "") else "ticket ref must look like goodqa#123"
    if kind == "park":
        if not mc.verify_user_source(source):
            return "a park needs a user:/answer: source that resolves to the user's own words"
        excerpt = mc.source_excerpt(source)
        if goal_id not in excerpt.lower() and not mc.names_goal(excerpt, goal):
            return f"the user's words do not name goal {goal_id}"
        return ""
    return "unknown response kind"


def respond(home: Path, goal_id: str, cond: str, kind: str, ref: str = "", source: str = "", detail: str = "",
            now=None) -> dict:
    now = time.time() if now is None else now
    goals = ort.mission_goals(home)
    if goal_id not in goals:
        raise DriveError(f"goal {goal_id} is not in goals.json")
    session = mission_session(home)
    problem = check_response(home, goal_id, cond, kind, ref, source, session, goals[goal_id], now)
    if problem:
        raise DriveError(problem)
    if cond in ("HELP_OPEN", "REVIEW_LOOP") and not detail:
        raise DriveError(f"{cond} needs --detail <task id>")
    key = action_key(goal_id, cond, detail)
    row = {"goal": goal_id, "cond": cond, "key": key, "kind": kind, "ref": ort.clean(ref, 120),
           "source": ort.clean(source, 300), "ts": now, "at": ort.now_iso(now)}
    d = _safe_dir(home)
    ort._append(d / "responses.jsonl", row)
    return row


def unanswered(snapshot: dict, responses: list, now: float) -> list:
    out = []
    for r in snapshot.get("rows") or []:
        for a in r.get("actions") or []:
            since = a.get("since", snapshot.get("at", now))
            ok = [x for x in responses if x.get("key") == a.get("key") and float(x.get("ts", 0)) >= float(since)
                  and now - float(x.get("ts", 0)) <= RESPONSE_TTL_S]
            if not ok:
                out.append({"goal": r["goal"], **a})
    return out


# ------------------------------------------------------------------ rendering

def fmt_age(s) -> str:
    if s is None:
        return "never"
    s = int(s)
    return f"{s // 60}m" if s < 7200 else f"{s // 3600}h"


def render(snapshot: dict, responses=None, now=None) -> str:
    now = time.time() if now is None else now
    open_keys = {a["key"] for a in unanswered(snapshot, responses or [], now)}
    lines = [f"Drive table ({len(snapshot.get('rows') or [])} initiatives; {len(open_keys)} actions unanswered):"]
    for r in snapshot.get("rows") or []:
        lines.append(f"- {r['goal']} [{r['status']}{'/' + r['lifecycle'] if r.get('lifecycle') else ''}] "
                     f"owner={r['owner']} proof={fmt_age(r.get('proof_age_s'))} distance={r['distance']}")
        if r.get("next"):
            lines.append(f"    next: {r['next'][:160]}")
        if r.get("blocker"):
            lines.append(f"    blocker: {r['blocker'][:160]}")
        for a in r.get("actions") or []:
            mark = "REQUIRED" if a["key"] in open_keys else "answered"
            lines.append(f"    {mark} {a['cond']}: {a['action'][:220]}")
    return "\n".join(lines)


# ------------------------------------------------------------------ Stop hook (main)

def _ring(home: Path, event: str, message: str, detail: dict, key: str = "drive:valve") -> None:
    """Raise or clear the drive valve alert in the shared ops ring, once per change. Best effort."""
    try:
        import ops_watch  # noqa: PLC0415
        path = ops_watch.ring_path(home)
        latest = None
        for e in ops_watch.read_ring(path):
            if e.get("source") == "drive" and e.get("key") == key:
                latest = e
        if (latest or {}).get("event", "clear") == event:
            return
        ops_watch.emit({"host": ops_watch.default_host(), "source": "drive", "event": event, "severity": "high",
                        "key": key, "message": message[:300], "detail": detail}, path=path)
    except Exception:  # noqa: BLE001
        pass


def _count_block(home: Path, session: str, sig: str) -> bool:
    try:
        d = _safe_dir(home)
        path = d / "stop-blocks.json"
        try:
            data = json.loads(ort._read(path, 65536).decode("utf-8"))
        except (FileNotFoundError, ValueError):
            data = {}
        if not isinstance(data, dict) or data.get("session") != session:
            data = {"session": session, "sigs": {}}
        sigs = data.setdefault("sigs", {})
        if sigs.get(sig, 0) >= MAX_STOP_BLOCKS:
            return False
        sigs[sig] = sigs.get(sig, 0) + 1
        if len(sigs) > 200:
            data["sigs"] = dict(list(sigs.items())[-100:])
        ort._atomic(path, data)
        return True
    except Exception:  # noqa: BLE001
        return False


def stop_decision(home: Path, payload: dict, now=None, is_main=None) -> dict:
    now = time.time() if now is None else now
    if is_main is None:
        import caller_identity  # noqa: PLC0415
        is_main = caller_identity.is_main(payload)
    if not is_main:
        return {}
    session = str(payload.get("session_id") or "").lower()
    mission = mission_session(home)
    if not mission or mission != session:
        return {}
    snap = load_snapshot(home)
    stale = snap is None or not 0 <= now - float(snap.get("at", 0)) <= SNAPSHOT_MAX_S
    if stale:  # cheap live view: no owner scan, no git; never a reason to pass silently
        snap = with_episodes(home, assess(home, session, now, None, with_git=False), prev=snap or {})
    todo = unanswered(snap, read_responses(home), now)
    if not todo:
        _ring(home, "clear", "drive: every initiative action answered", {})
        return {}
    lines = [f"- {t['goal']} {t['cond']}: {t['action'][:200]}" for t in todo[:12]]
    if len(todo) > 12:
        lines.append(f"- ... and {len(todo) - 12} more (`{SCRIPT} table`)")
    text = ("DRIVE LOOP (owner-runtime-drive): these initiatives have a required action with no recorded response. "
            "Take each action now, or record a response that is a fact: "
            f"`{SCRIPT} respond --goal G --cond C --kind ask|owner|ticket|park --ref R [--source user:...]`. "
            "Capacity is not a reason to leave an initiative idle.\n" + "\n".join(lines))
    if stale:
        text += "\n(drive snapshot stale: computed without owner scan or git; ops_watch refreshes it)"
    sig = hashlib.sha256("|".join(sorted(t["key"] for t in todo)).encode()).hexdigest()[:16]
    if _count_block(home, session, sig):
        return {"decision": "block", "reason": text[:4000]}
    _ring(home, "raise", f"drive valve: {len(todo)} initiative actions unanswered after {MAX_STOP_BLOCKS} blocks",
          {"goals": sorted({t['goal'] for t in todo})[:20], "stop_block": False})
    return {"systemMessage": "drive (block budget spent; the actions stay open): " + text[:3000]}


def cmd_stop(stdin) -> int:
    try:
        payload = json.loads(stdin.read(1 << 20) or "{}")
        if isinstance(payload, dict):
            out = stop_decision(home_dir(), payload)
            if out:
                print(json.dumps(out))
    except Exception as exc:  # noqa: BLE001 - fail open
        print(json.dumps({"systemMessage": f"drive stop check failed open: {exc.__class__.__name__}"}))
    return 0


# ------------------------------------------------------------------ ops_watch hook

def ops_alerts(home: Path, now=None) -> list:
    """ops_watch.check_drive: owner_rt tick, then the drive tick, then one high alert per unanswered action."""
    now = time.time() if now is None else now
    out = []
    with contextlib.suppress(Exception):
        for r in ort.tick(home, now=now):
            if r.get("action") in ("stuck", "launch-failed", "error"):
                out.append({"check": "drive", "key": f"owner:{r['goal']}:{r['action']}", "severity": "high",
                            "message": f"owner {r['goal']}: {r['action']} ({ort.clean(r.get('reason'), 160)})",
                            "detail": {"stop_block": False}})
    if not ort.mission_goals(home):
        return out
    snap = tick(home, now=now)
    for t in unanswered(snap, read_responses(home), now):
        out.append({"check": "drive", "key": f"drive:{t['key']}", "severity": "high",
                    "message": f"{t['goal']} {t['cond']}: {t['action'][:200]}", "detail": {"stop_block": True}})
    return out


def notify_main(home: Path, keys) -> None:
    """Wake main when new initiative actions appear: a Mission Control inbox message through mc_chat when installed and
    main registered a target. Best effort; the ops alerts and the Stop gate stand without it."""
    keys = [k for k in keys or [] if isinstance(k, str)][:20]
    if not keys:
        return
    session = mission_session(home)
    text = ("DRIVE-LOOP ALERT from the harness (drive.py), not typed by the user: initiative action(s) need a response: "
            f"{', '.join(k.replace('drive:', '') for k in keys)}. Run `{SCRIPT} table` and take each action.")
    try:
        chat = _mc()._load_chat()
        if chat is not None and session:
            key = "drive-" + hashlib.sha256(("|".join(keys) + f"|{int(time.time() // 3600)}").encode()).hexdigest()[:24]
            chat.new_message("claude", text, client_key=key, session=session, thread="drive")
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ CLI

def build_parser():
    p = argparse.ArgumentParser(prog="drive.py", description="Drive every initiative toward live; see the docstring.")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("table", help="compute and print the drive table (writes the snapshot)")
    t.add_argument("--json", action="store_true")
    t.add_argument("--no-write", action="store_true")
    r = sub.add_parser("respond", help="record a response to a required action (checked as a fact)")
    r.add_argument("--goal", required=True)
    r.add_argument("--cond", required=True, choices=CONDITIONS)
    r.add_argument("--kind", required=True, choices=("ask", "owner", "ticket", "park"))
    r.add_argument("--ref", default="")
    r.add_argument("--source", default="")
    r.add_argument("--detail", default="", help="the task id for HELP_OPEN / REVIEW_LOOP")
    sub.add_parser("stop", help="Stop hook (payload on stdin)")
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["stop"]:
        return cmd_stop(sys.stdin)
    args = build_parser().parse_args(argv or ["table"])
    home = home_dir()
    try:
        if args.cmd == "table":
            snap = (with_episodes(home, assess(home, mission_session(home))) if args.no_write
                    else tick(home))
            if args.json:
                print(json.dumps(snap, indent=1, default=str))
            else:
                print(render(snap, read_responses(home)))
            return 0
        if args.cmd == "respond":
            row = respond(home, args.goal, args.cond, args.kind, args.ref, args.source, args.detail)
            print(json.dumps(row))
            return 0
    except (DriveError, ort.OwnerError, OSError, ValueError) as exc:
        print(f"drive: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
