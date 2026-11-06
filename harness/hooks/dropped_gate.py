"""Dropped-owner gate: a Stop hook that blocks the main agent's turn from ending while any DROPPED owner of the
session has no live disposition (GoodQA goodqa#14791, NEVER-LOSE.md invariant I1).

Evidence: on 2026-11-05 21:10Z `ah owners` listed 12 DROPPED owners and the main agent wrote "0 dropped"; the
half-hourly prompt only advised. This hook is deterministic: it reads `ah.owners` (the shared liveness rule and the
dispositions recorded through `ah task dispose`) and blocks with the exact lines to run. The block count is bounded
per problem signature (the sorted set of undisposed agent ids) by MAX_STOP_BLOCKS, so a session cannot be trapped;
after the bound, and on a repeated Stop (`stop_hook_active`), it lets the turn end but still names the owners.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

MAX_STOP_BLOCKS = 3


def state_path(session: str) -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / "state" / "dropped-gate" / f"{session}.json"


def load_state(session: str) -> dict:
    try:
        import safe_input  # noqa: PLC0415
        data = safe_input.safe_json_loads(safe_input.read_bounded(state_path(session), 65536).decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - a damaged counter file only loses the bound, never the decision
        return {}


def save_state(session: str, state: dict) -> None:
    path = state_path(session)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except OSError:
        pass  # the gate still decides; only the bound counter is lost


def message(undisposed: list, rows: dict) -> str:
    lines = []
    for agent in undisposed:
        r = rows.get(agent) or {}
        idle = r.get("idle_s")
        age = f"{int(idle // 3600)}h{int(idle % 3600 // 60):02d}m" if isinstance(idle, (int, float)) else "?"
        if agent.startswith("dl") and not r:  # a missed deadline (goodqa#14791 G3)
            lines.append(f"  - deadline {agent} missed: run `ah deadline done --id {agent} --note <what happened>` when it is met, or\n"
                         f"      ah task dispose --agent {agent} --kind waiting --ref <ask id or GoodQA ticket> --until <ISO>  (it slipped for a named reason)")
            continue
        if "handoff-unacked" in (r.get("flags") or []):  # I9: a handoff nobody took
            lines.append(f"  - {agent} handed off {age} ago and nobody acknowledged it: main (not the owner) records\n"
                         f"      ah task dispose --agent {agent} --kind resumed      (someone picked it up)\n"
                         f"      ah task dispose --agent {agent} --kind reassigned --ref <new agent id>\n"
                         f"      ah task dispose --agent {agent} --kind closed --reason <what you verified> --deployed <deploy WAL id> "
                     f"--live-test <live REALLY_TESTED id>\n"
                     f"      ah task dispose --agent {agent} --kind superseded|wontdo --ref <GoodQA ticket> --reason <why>")
            continue
        lines.append(f"  - {agent} DROPPED {age} ticket {r.get('ticket') or 'none'}: run one of\n"
                     f"      ah task dispose --agent {agent} --kind resumed   (after you resume or re-spawn it)\n"
                     f"      ah task dispose --agent {agent} --kind reassigned --ref <new agent id>\n"
                     f"      ah task dispose --agent {agent} --kind waiting --ref <ask id or GoodQA ticket> --until <ISO>\n"
                     f"      ah task dispose --agent {agent} --kind closed --reason <what you verified> --deployed <deploy WAL id> "
                     f"--live-test <live REALLY_TESTED id>\n"
                     f"      ah task dispose --agent {agent} --kind superseded|wontdo --ref <GoodQA ticket> --reason <why>")
    return ("Dropped owners need a decision before this turn ends (goodqa#14791):\n" + "\n".join(lines) +
            "\nA dropped owner is a defect: resume it, reassign it, name what it waits on, or close it with evidence.")


GRANDFATHER_MAX = 50  # legacy rows one Stop may write


def grandfather(session: str, data: dict, now=None) -> list:
    """One-time grandfather (main's request, goodqa#14791): an undisposed owner whose last activity predates this
    host's gate install time is recorded as `legacy` through ah, which re-checks the epoch and writes the audit row.
    Owners that went quiet after the install are never touched. Returns the ids recorded."""
    try:
        import ah  # noqa: PLC0415
        home = Path(os.environ.get("AH_HOME") or Path.home())
        epoch = ah.gate_epoch(home)
    except Exception:  # noqa: BLE001
        return []
    if not epoch:
        return []
    rows = {r["agent_id"]: r for r in data.get("owners") or []}
    done = []
    scope = getattr(ah, "owner_view_scope", None)  # a half-updated install falls back to one view per owner
    with (scope(home, session, data) if scope else contextlib.nullcontext()):  # ah re-checks each owner, view read once
        for agent in list(data.get("undisposed") or [])[:GRANDFATHER_MAX]:
            last = ah.parse_ts((rows.get(agent) or {}).get("last_activity"))
            if not last or last >= epoch:
                continue
            try:
                ah.write(home, "task.dispose", {"agent": agent, "session": session, "kind": "legacy"}, session)
                done.append(agent)
            except Exception:  # noqa: BLE001 - a refused legacy row leaves the owner gated, which is the safe side
                continue
    return done


def cmd_stop(payload: dict, now: float | None = None) -> dict:
    session = str(payload.get("session_id") or "")
    if not session or "/" in session or session in (".", ".."):
        return {}
    if os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk") or payload.get("agent_id"):
        return {}  # headless or sub-agent sessions are owners themselves; only the interactive main is gated (review M1)
    try:
        import ah  # noqa: PLC0415 - installed beside this hook
        data = ah.owners(Path(os.environ.get("AH_HOME") or Path.home()), session, now=now)
    except Exception:  # noqa: BLE001 - no WAL, a partial install or an ah bug: fail open, never trap the turn
        return {}
    undisposed = list(data.get("undisposed") or [])
    legacy = grandfather(session, data, now)
    if legacy:
        try:
            data = ah.owners(Path(os.environ.get("AH_HOME") or Path.home()), session, now=now)
        except Exception:  # noqa: BLE001
            return {}
        undisposed = list(data.get("undisposed") or [])
    note = (f"dropped-owner gate: {len(legacy)} owner(s) quiet since before the gate was installed were recorded as "
            "unverified-legacy (each has an audit row; `ah owners` lists them until someone follows up): "
            + ", ".join(legacy)) if legacy else ""
    if not undisposed:
        return {"systemMessage": note} if note else {}
    rows = {r["agent_id"]: r for r in data.get("owners") or []}
    text = message(undisposed, rows)
    sig = hashlib.sha256(",".join(undisposed).encode()).hexdigest()[:16]
    state = load_state(session)
    count = int((state.get("blocks") or {}).get(sig, 0))
    if payload.get("stop_hook_active") or count >= MAX_STOP_BLOCKS:
        return {"systemMessage": f"dropped-owner gate: {len(undisposed)} owner(s) still undisposed after {count} block(s): "
                                 + ", ".join(undisposed) + ". " + text}
    state.setdefault("blocks", {})[sig] = count + 1
    state["last"] = now or time.time()
    save_state(session, state)
    return {"decision": "block", "reason": text}


PENDING_EVENTS = ("intent", "scope", "status", "check", "risk", "decision", "commit", "blocker")
LIFECYCLE_EVENTS = ("pretool", "subagent", "subagent_stop", "prompt", "session", "pending_stop")  # wal.py metadata (review Part 3 #8)


def pending_work(home: Path, session: str, agent: str) -> str | None:
    """Why the agent's own WAL says its work is unfinished, or None (handoff/result/named wait/empty)."""
    import ah  # noqa: PLC0415
    import liveness  # noqa: PLC0415
    path = ah.session_dir(home, session) / f"agent-{agent}.jsonl"  # either WAL root
    if not path.is_file():
        return None
    last = None
    with open(path, "rb") as fh:
        for raw in fh:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if (isinstance(rec, dict) and rec.get("event") and not rec.get("by")
                    and rec.get("event") not in LIFECYCLE_EVENTS):  # hook metadata rows are not the owner's own entries
                last = rec
    if not last:
        return None
    event, note = str(last.get("event")), str(last.get("note") or "")
    if event in ("handoff", "result") or liveness.waiting_on(note):
        return None
    if event in PENDING_EVENTS:
        return f"last WAL entry is an open {event}"
    return None


def armed_waiter(agent: str, home: Path | None = None) -> bool:
    """A live ah-run job attributed to the agent counts as an armed waiter: its completion record will notify.
    Read from the launcher's ledger directory (~/.agent-harness/reserve/ledger/<run>.json, one row per run, `agent`
    attribution, `end` set when the run finished; docs/observer.md). No ledger dir, or no live row: not armed."""
    import safe_input  # noqa: PLC0415
    home = home or Path(os.environ.get("AH_HOME") or Path.home())
    ledger = home / ".agent-harness" / "reserve" / "ledger"
    try:
        entries = sorted(os.scandir(ledger), key=lambda e: e.name)[-500:]
    except OSError:
        return False
    for entry in entries:
        if not entry.name.endswith(".json") or not entry.is_file(follow_symlinks=False):
            continue
        try:
            row = safe_input.safe_json_loads(safe_input.read_bounded(Path(entry.path), 65536).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - a torn row is not a waiter
            continue
        if isinstance(row, dict) and row.get("agent") == agent and not row.get("end"):
            return True
    return False


def cmd_subagent_stop(payload: dict, now: float | None = None) -> dict:
    session = str(payload.get("session_id") or "")
    agent = str(payload.get("agent_id") or "")
    if not session or not agent or "/" in session or "/" in agent:
        return {}
    home = Path(os.environ.get("AH_HOME") or Path.home())
    try:
        why = pending_work(home, session, agent)
    except Exception:  # noqa: BLE001
        return {}
    if not why or armed_waiter(agent, home):
        return {}
    state = load_state(session)
    seen = state.setdefault("subagent_blocks", {})
    text = (f"Sub-agent {agent} is ending its turn with pending work ({why}) and no armed waiter (goodqa#14791 I7). "
            f"Before stopping: write a handoff or result WAL entry, or name the wait with `ah task dispose --agent {agent} "
            f"--kind waiting --ref <ask id or GoodQA ticket> --until <ISO>`, or arm a waiter with `ah job wait`.")
    if not payload.get("stop_hook_active") and not seen.get(agent):
        seen[agent] = (now or time.time())
        save_state(session, state)
        return {"decision": "block", "reason": text}
    try:  # second stop: let it end, but the owner is DROPPED now, not after the finishing grace
        import ah  # noqa: PLC0415
        import datetime as dt  # noqa: PLC0415
        ts = dt.datetime.fromtimestamp(now or time.time(), dt.timezone.utc).isoformat()  # microseconds, like wal.py
        ah.write(home, "task.pending", {"agent": agent, "session": session, "at": ts}, session,
                 f"pending:{session[:16]}:{agent}:{int((now or time.time()) // 600)}")
    except Exception:  # noqa: BLE001 - the marker is best effort; the message still says what happened
        pass
    return {"systemMessage": "dropped-owner gate: " + text + " It is now DROPPED and needs a disposition."}


ACK_KINDS = ("resumed", "reassigned", "closed", "legacy", "superseded", "wontdo")
PRETOOL_MAX = 100_000  # larger commands are judged by a cheap substring test (round 5, minor 2: no regex backtracking)
_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_WRAPPERS = {"env", "nice", "command", "exec", "time", "nohup", "timeout", "sudo", "stdbuf", "builtin"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
_RUNS_TEXT = re.compile(r"(?:^|[\s;&|(])(?:(?:ba|z|da|k)?sh|fish|python[0-9.]*|eval|source|\.)(?:\s|$)")
_KIND_WORD = re.compile(r"\b(?:" + "|".join(ACK_KINDS) + r")\b")


def _strip_heredocs(cmd: str) -> str:
    """Drop heredoc bodies: text fed to cat or a file is data, not a command (round 5, minor 3)."""
    out, pos, at = [], 0, 0
    for _ in range(64):
        m = _HEREDOC.search(cmd, at)
        if not m:
            break
        at = m.end()
        head = cmd[cmd.rfind("\n", 0, m.start()) + 1:m.start()]
        if _RUNS_TEXT.search(head):  # `bash <<EOF` runs its body: keep it
            continue
        body = cmd.find("\n", m.end())
        if body < 0:
            break
        out.append(cmd[pos:body + 1])
        end = re.compile(r"^[ \t]*" + re.escape(m.group(2)) + r"[ \t]*$", re.M).search(cmd, body + 1)
        pos = at = end.end() if end else len(cmd)
    out.append(cmd[pos:])
    return "".join(out)


def _segments(cmd: str):
    """Shell words split into simple commands at ; & | && || ( ) and newlines. None when it does not tokenize."""
    import shlex  # noqa: PLC0415
    lex = shlex.shlex(cmd.replace("\\\n", " ").replace("\n", " ; "), posix=True, punctuation_chars=";&|()<>")
    lex.whitespace_split = True
    lex.commenters = ""
    segs, cur = [], []
    try:
        for tok in lex:
            if tok and set(tok) <= set(";&|()"):
                segs.append(cur)
                cur = []
            else:
                cur.append(tok)
    except ValueError:  # an unbalanced quote
        return None
    segs.append(cur)
    return segs


def _acks(seg: list, depth: int = 0) -> bool:
    """Whether one simple command is `[wrappers] [python] .../ah[.py] [global opts] task dispose ... --kind <ack>`."""
    i = 0
    while i < len(seg) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]) or seg[i] in _WRAPPERS
                            or (i and seg[i - 1] in _WRAPPERS and (seg[i].startswith("-") or seg[i].isdigit()))
                            or (i and seg[i - 1] in ("-n", "-u") and seg[i].lstrip("-").isdigit())):
        i += 1
    if i < len(seg) and (seg[i] == "eval" or (os.path.basename(seg[i]) in _SHELLS and "-c" in seg[i + 1:])):
        rest = seg[i + 1:]
        code = " ".join(rest[rest.index("-c") + 1:] if "-c" in rest else rest)
        return acknowledges(code, depth + 1) if depth < 3 else ("dispose" in code and bool(_KIND_WORD.search(code)))
    if i < len(seg) and os.path.basename(seg[i]).startswith("python"):
        rest = seg[i + 1:]
        if "-c" in rest:  # inline code: judged by what it says
            code = " ".join(rest[rest.index("-c") + 1:])
            return "dispose" in code and bool(_KIND_WORD.search(code))
        i += 1
        while i < len(seg) and seg[i].startswith("-"):
            i += 1
    if i >= len(seg) or os.path.basename(seg[i]) not in ("ah", "ah.py"):
        return False
    rest = [t for t in seg[i + 1:]]
    words = [t for t in rest if not t.startswith("-")]
    if words[:2] != ["task", "dispose"]:
        return False
    for j, tok in enumerate(rest):
        name, eq, val = tok.partition("=")
        if len(name) >= 3 and "--kind".startswith(name) and name.startswith("--"):
            value = val if eq else (rest[j + 1] if j + 1 < len(rest) else "")
            if value in ACK_KINDS or "$" in value or "`" in value:  # an expansion cannot be judged: deny
                return True
    return False


def acknowledges(cmd: str, depth: int = 0) -> bool:
    """Whether a Bash command runs an `ah task dispose` that resumes, reassigns, closes, supersedes, wontdoes or legacies
    an owner."""
    if len(cmd) > PRETOOL_MAX:
        return "dispose" in cmd and bool(_KIND_WORD.search(cmd))
    segs = _segments(_strip_heredocs(cmd))
    if segs is None:
        return "dispose" in cmd and bool(_KIND_WORD.search(cmd))
    return any(_acks(s, depth) for s in segs if s)


def cmd_pretool(payload: dict) -> dict:
    """PreToolUse(Bash): a sub-agent (the payload carries its agent_id) may not resume, reassign or close an owner;
    main records those. A wait (`--kind waiting`) stays open to everyone. The identity is the hook's, not the
    shell's: main's shell carries the same environment as a sub-agent's (review round 3, B1). The text match is
    advisory against an agent that hides the call; the dispose guard's evidence and burst rules do not rely on it."""
    if not payload.get("agent_id") or payload.get("tool_name") != "Bash":
        return {}
    tool_input = payload.get("tool_input")
    cmd = str((tool_input if isinstance(tool_input, dict) else {}).get("command") or "")
    if not acknowledges(cmd):
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": "dropped-owner gate (goodqa#14791): a sub-agent cannot "
                                   "resume, reassign or close an owner, its own or another's; main records that. "
                                   "Record what you wait on with `ah task dispose --kind waiting`, or write a handoff."}}


def main(argv=None) -> int:
    mode = (argv or sys.argv[1:] or ["stop"])[0]
    try:
        import safe_input  # noqa: PLC0415
        limit = (16 << 20) if mode == "pretool" else (1 << 20)  # a 2 MB command must not skip the pretool check
        payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(limit).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - oversized or malformed hook input: gate nothing, never block on garbage
        payload = {}
    try:
        payload = payload if isinstance(payload, dict) else {}
        out = (cmd_subagent_stop(payload) if mode == "subagent-stop" else cmd_pretool(payload) if mode == "pretool"
               else cmd_stop(payload))
    except Exception as exc:  # noqa: BLE001 - a gate crash must not block the turn silently
        out = {"systemMessage": f"dropped-owner gate failed open ({type(exc).__name__})"}
    if out:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
