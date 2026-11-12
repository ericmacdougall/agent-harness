#!/usr/bin/env python3
"""Status answers come from the goal ledger, not memory (GoodQA goodqa#15754).

  status_truth.py prompt          UserPromptSubmit: a status question ("whats left", "where are we") gets the
                                  `ah goals` text as additional context
  status_truth.py stop            Stop (main): the final message states goal status without `ah goals` (or the
                                  injection) this turn, or contradicts the ledger -> block once (enforce) or warn
  status_truth.py session-start   SessionStart: after a compaction (source "compact") the goals text is re-injected
  status_truth.py calibrate <transcript> [--uuid U ...] [--limit N]
                                  replay the lint over a transcript, each message judged against the ledger as of
                                  its own timestamp; JSON lines, no hook payload

Why: on 2026-11-12 main answered "whats left" from memory: it said prod move could not be called done, nobody worked
on the 1000 leads and self-update had no work, while the WALs held live proofs of all three (w16dc0f5dd6b,
w53ff16565a1, wa6c1d52d985). None of the six Stop hooks looked at a status answer, and compaction had dropped the
finished goals from main's context.

Contradiction rules (only DONE_LIVE is done; see CLAIMS and POSITIVE): per clause that names a goal, "not done" is
false only for DONE_LIVE, "not live" for a goal with a live record, "no work / not started" for a goal with counted
evidence or a live owner, "nobody is working" for a goal a live owner holds; "done" attached to the goal name is an
over-claim below DONE_LIVE, "live / shipped" for a goal with no live record. Skip rule: the answer states goal status (two or more goals, or any goal in reply to a status question)
with no `ah goals` call and no goals injection since the human prompt that opened the turn (a typed prompt or a queued
one; task notifications and peer messages do not open a turn).
Mode: provenance_policy.json `status_lint` (off | warn | enforce). In warn mode (shipped) the finding is a
systemMessage the user sees and the model does not, so a wrong answer still goes out; the prompt injection is the
control until enforce. In enforce mode stop_blocks.allow bounds blocks per human turn (once for this hook), independent
of stop_hook_active. Limits: only the last assistant text of the turn is linted, so a status answer followed by a
short closing message escapes. Every command fails open on its own errors (stderr note, exit 0). Output is capped at
4 KB and redacted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

TAIL_BYTES = 4 << 20
WALL_LIMIT_S = 8.0
LIMIT = 4096

# A status question. Text inside backticks, code fences and shell-looking lines is removed first (NEG-12: `git status`).
STATUS_Q = re.compile(
    r"(?i)\b(?:what'?s|whats|what is|what are|what'?re) (?:left|remaining|outstanding|still open|the status|done|"
    r"the state|pending)\b|\bwhat (?:remains|is still|still needs)\b|\bwhere (?:are|do) (?:we|things) stand\b|"
    r"\bwhere are we\b|\bstatus (?:update|report|check)\b|\b(?:give|show|tell) me (?:the |a )?(?:status|progress)\b|"
    r"^\W*(?:status|progress|update)\W*$|\bhow (?:are|is) (?:we|things|it|everything) (?:doing|going)\b|"
    r"\bhow far (?:along )?(?:are|is)\b|\bany progress\b|\bis (?:it|that|everything) done\b")
SHELLISH = re.compile(r"^\s*(?:\$|python3?\b|git\b|ah\b|cd\b|ls\b|cat\b).*$", re.M)
STATUS_WORD = re.compile(
    r"(?i)\b(?:done|live|finished|complete[d]?|blocked|waiting|nobody|no one|in progress|started|tested|met|gap|"
    r"left|remaining|parked|not (?:yet )?(?:done|live)|no work)\b")
# Claim classes and the states each contradicts (main's rev-3 ruling on red-team M2: only DONE_LIVE is done, so "not
# done" is true for every state below it; "not live" is false once a live test passed or a deploy is recorded; "no
# work / not started" is false once any counted evidence exists; "nobody is working" is false while a live owner holds
# the goal). Positive claims ("done", "live", "shipped") must attach to the goal name (_attached), so a task that
# merely mentions a goal ("ParentProof test servers: done") is not a goal claim (NEG-17).
NOT_DONE = re.compile(
    r"(?i)\b(?:not (?:yet )?(?:done|met|complete[d]?|finished)|(?:isn'?t|is not|aren'?t|are not|wasn'?t) (?:yet )?"
    r"(?:done|finished|complete[d]?)|(?:can'?t|cannot|couldn'?t|could not) (?:yet )?(?:call|say|claim|mark)\b"
    r"[^.\n]{0,40}\b(?:done|finished|complete))")
NOT_LIVE = re.compile(
    r"(?i)\b(?:not (?:yet )?(?:live|deployed|shipped)|(?:isn'?t|is not|aren'?t|are not) (?:yet )?(?:live|deployed)|"
    r"(?:hasn'?t|has not|haven'?t|have not) (?:yet )?(?:been )?(?:shipped|deployed|gone live))")
NO_WORK = re.compile(
    r"(?i)\b(?:ha(?:s|ve) had no work|no work (?:has|on|this|yet)|not (?:yet )?(?:started|built|tested)|"
    r"(?:hasn'?t|has not|haven'?t|have not) (?:yet )?(?:been )?(?:started|begun|built|tested|touched)|"
    r"not been (?:started|tested|built)|never (?:began|started)|nothing (?:has been|was) done)")
NOBODY = re.compile(r"(?i)\b(?:nobody|no one|no-one) (?:is )?(?:working|on it|owns it)")
DONE_CLAIM = re.compile(r"(?i)(?:\b(?:is|are|now|all|fully) (?:done|complete|finished)\b|:\s*\**\s*done\b|"
                        r"\bdone and (?:tested|live)\b|\bdone,? (?:deployed|live)\b|\bcomplete and tested\b)")
LIVE_CLAIM = re.compile(r"(?i)(?:\b(?:is|are|now) live\b|\b(?:has |have )?shipped\b|:\s*\**\s*live\b)")
EVIDENCED = ("DONE_LIVE", "LIVE_TESTED", "LIVE_UNTESTED", "VERIFIED", "FAILING", "IN_PROGRESS")
CLAIMS = (  # (name, regex, states it contradicts); negative claims first, a clause matching one is never a done claim
    ("not-done", NOT_DONE, ("DONE_LIVE",)),
    ("not-live", NOT_LIVE, ("DONE_LIVE", "LIVE_TESTED", "LIVE_UNTESTED")),
    ("no-work", NO_WORK, EVIDENCED),
    ("nobody-working", NOBODY, ("IN_PROGRESS",)),
)
POSITIVE = (
    ("done", DONE_CLAIM, lambda st: st != "DONE_LIVE"),
    ("live", LIVE_CLAIM, lambda st: st not in ("DONE_LIVE", "LIVE_TESTED", "LIVE_UNTESTED")),
)
GLUE = re.compile(r"(?i)\b(?:the|goal|goals|itself|stream|work|now|also|both|and|or|all|of|is|are|has|have|been|"
                  r"fully|really)\b")
CLAUSE_SPLIT = re.compile(r";|\.\s|\s(?:but|while|whereas|although)\s|\s[-\u2013\u2014]\s", re.I)
UNAVAILABLE = "GOALS UNAVAILABLE ({}): goal status is unknown; do not answer status from memory. Say it is unknown."
# only a command that runs `ah goals` counts as consulting the ledger (red-team L2): the command word itself, after an
# optional `cd ... &&`; a quote of the goals text in a file or peer message does not count
GOALS_CALL = re.compile(r"^\s*(?:cd\s+[^;&|]+(?:&&|;)\s*)?(?:python3?\s+)?\S*\bah(?:\.py)?\s+goals\b")


def _policy_mode() -> str:
    try:
        import provenance  # noqa: PLC0415
        mode = provenance.load_policy().get("status_lint", "warn")
        return mode if mode in ("off", "warn", "enforce") else "warn"
    except Exception:  # noqa: BLE001 - no policy: warn, never enforce blind
        return "warn"


def _home() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def strip_code(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text or "", flags=re.S)
    text = re.sub(r"`[^`\n]*`", " ", text)
    return SHELLISH.sub(" ", text)


def is_status_question(prompt: str) -> bool:
    text = strip_code(prompt)
    return bool(text.strip()) and len(text) <= 2000 and bool(STATUS_Q.search(text))


def goals_doc(as_of=None, home=None):
    import goals_view  # noqa: PLC0415
    return goals_view.goals_report(home or _home(), as_of=as_of, scan_budget_s=3.0)


def goals_text(doc) -> str:
    """Hook text: ids, check names, verdicts and ages only, never agent-written note text (spec delta M3)."""
    import goals_view  # noqa: PLC0415
    if doc.get("state") != "ok":
        return UNAVAILABLE.format(doc.get("state"))
    return goals_view.goals_text(doc, limit=LIMIT - 300, notes=False)


def mission_session(doc: dict) -> str:
    """The mission session, decided independently of the ledger's health (main's rev-3 ruling M1): the ledger's own
    mission_session when it is readable (remembered for later), else the remembered id, else none."""
    if doc.get("state") == "ok":
        mission = str(doc.get("mission_session") or "").lower()
        _remember_mission(mission)
        return mission
    return _remembered_mission()


def in_scope(payload: dict, doc: dict) -> bool:
    """Inject and lint only in the mission session (main's ruling). A missing or broken ledger never widens it: outside
    the mission session nothing is ever injected, and with no known mission session nothing is injected at all."""
    mission = mission_session(doc)
    if not mission:
        return False
    sid = str(payload.get("session_id") or "").lower()
    stem = Path(str(payload.get("transcript_path") or "")).stem.lower()
    return mission in (sid, stem)


def _names(goal: dict) -> list:
    names = {a.lower() for a in goal.get("aliases") or []}
    names.add(goal["id"].replace("-", " ").replace("_", " ").lower())
    title = str(goal.get("title") or "").lower().strip()
    if title and len(title.split()) <= 3:
        names.add(title)
    return sorted((n for n in names if len(n) >= 3), key=len, reverse=True)


def _mentions(line: str, goals: list) -> list:
    low = line.lower()
    hits = []
    for g in goals:
        for n in _names(g):
            if re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", low):
                hits.append(g["id"])
                break
    return hits


def _spans(line: str, goals: list) -> list:
    """[(goal id, start, end)] for each goal name in the line (the longest name per goal, first occurrence)."""
    low, out = line.lower(), []
    for g in goals:
        for n in _names(g):
            m = re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", low)
            if m:
                out.append((g["id"], m.start(), m.end()))
                break
    return out


def _attached(clause: str, spans: list, gid: str, claim_start: int) -> bool:
    """The positive claim belongs to the goal: between the goal name and the claim there is only markup, glue words
    and other goal names ("User tokens and ParentProof are done", "**Prod move:** done")."""
    start, end = next((st, en) for g, st, en in spans if g == gid)
    if end > claim_start:  # the claim starts before or inside the name ("Shipped: prod move"): not attached
        return False
    gap = clause[end:claim_start]
    for _, st, en in sorted(spans, key=lambda x: -x[1]):
        if end <= st and en <= claim_start:
            gap = gap[:st - end] + " " + gap[en - end:]
    return not re.search(r"[A-Za-z0-9]", GLUE.sub(" ", gap))


def classify(text: str, doc: dict) -> dict:
    """{status_answer, goals, contradictions[{goal, state, rule, claim, line}]} for one assistant message. Each line is
    split into clauses; a negative claim contradicts the states in CLAIMS; a positive claim attached to a goal name
    over-claims any state below it (POSITIVE)."""
    goals = doc.get("goals") or [] if doc.get("state") == "ok" else []
    states = {g["id"]: g["state"] for g in goals}
    named, contradictions = set(), []
    for line in strip_code(text).splitlines():
        if not line.strip():
            continue
        line_hits = _mentions(line, goals)
        if not line_hits:
            continue
        if STATUS_WORD.search(line):
            named.update(line_hits)
        for clause in CLAUSE_SPLIT.split(line):
            spans = _spans(clause, goals)
            if not spans:
                continue
            negative = False
            for rule, rx, bad in CLAIMS:
                m = rx.search(clause)
                if not m:
                    continue
                negative = True
                for gid, _, _ in spans:
                    if states.get(gid) in bad:
                        contradictions.append({"goal": gid, "state": states[gid], "rule": rule, "claim": m.group(0),
                                               "line": line.strip()[:200]})
            if negative:
                continue
            for rule, rx, over in POSITIVE:
                m = rx.search(clause)
                if not m:
                    continue
                for gid, _, _ in spans:
                    if over(states.get(gid)) and _attached(clause, spans, gid, m.start()):
                        contradictions.append({"goal": gid, "state": states.get(gid), "rule": "over-claim-" + rule,
                                               "claim": m.group(0), "line": line.strip()[:200]})
                break
    seen, unique = set(), []
    for c in contradictions:
        if (c["goal"], c["line"]) not in seen:
            seen.add((c["goal"], c["line"]))
            unique.append(c)
    return {"status_answer": len(named) >= 2, "goals": sorted(named), "contradictions": unique}


# ------------------------------------------------------------------ transcript reading

def _read_tail(path: str) -> bytes:
    import provenance  # noqa: PLC0415
    return provenance.read_tail(path, TAIL_BYTES, root=provenance.claude_home() / "projects")


def _text_of(record) -> str:
    content = (record.get("message") or {}).get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


MACHINE_PREFIX = ("<task-notification>", "<agent-message")


def _human_origin(origin) -> bool:
    """A record's `origin` names who wrote it; absent (older Claude Code) means unknown, judged by text instead."""
    return origin is None or (isinstance(origin, dict) and origin.get("kind") == "human")


def _human_turn(record) -> bool:
    if record.get("type") != "user" or record.get("isSidechain") or "toolUseResult" in record:
        return False
    if record.get("isMeta") or record.get("isCompactSummary") or not _human_origin(record.get("origin")):
        return False
    content = (record.get("message") or {}).get("content")
    if isinstance(content, list) and content and all(isinstance(b, dict) and b.get("type") == "tool_result"
                                                      for b in content):
        return False
    return not _text_of(record).lstrip().startswith(MACHINE_PREFIX)  # a task notification or peer message


def _opener(record):
    """(prompt, prompt_id) when the record is a human prompt that opens a turn, else None. A prompt typed while main
    was busy arrives as an `attachment` of type queued_command (the 2026-11-12 "whats left" was one, origin human);
    queued task notifications and peer messages are not human prompts (spec delta C1)."""
    if _human_turn(record):
        return _text_of(record), str(record.get("uuid") or record.get("timestamp") or "")
    att = record.get("attachment") if record.get("type") == "attachment" else None
    if isinstance(att, dict) and att.get("type") == "queued_command" and isinstance(att.get("prompt"), str):
        origin = att.get("origin")
        human = (isinstance(origin, dict) and origin.get("kind") == "human") or (origin is None and att.get("humanTurn"))
        if human and not att["prompt"].lstrip().startswith(MACHINE_PREFIX):
            return att["prompt"], str(att.get("source_uuid") or record.get("uuid") or att.get("timestamp") or "")
    return None


def current_turn(payload: dict) -> dict:
    """{answer, prompt, consulted}: the final assistant text of this turn, the user prompt that opened it, and whether
    `ah goals` ran (or a goals injection landed) in the turn. Only assistant text is linted (NEG-8)."""
    out = {"answer": "", "prompt": "", "prompt_id": "", "consulted": False}
    direct = payload.get("last_assistant_message")
    path = payload.get("transcript_path")
    records = []
    if isinstance(path, str) and path:
        try:
            for raw in _read_tail(path).split(b"\n"):
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
        except Exception:  # noqa: BLE001 - unreadable transcript: lint the direct message only
            records = []
    for rec in reversed(records):
        if rec.get("isSidechain"):
            continue
        if rec.get("type") == "assistant":
            content = (rec.get("message") or {}).get("content")
            for b in content if isinstance(content, list) else []:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    cmd = str((b.get("input") or {}).get("command") or "")
                    if GOALS_CALL.search(cmd):
                        out["consulted"] = True
            if not out["answer"]:
                out["answer"] = _text_of(rec).strip()
                out["answer_id"] = str(rec.get("uuid") or "")
        elif _opener(rec) is not None:
            out["prompt"], out["prompt_id"] = _opener(rec)
            break
    if isinstance(direct, str) and direct.strip():
        out["answer"] = direct
    if is_status_question(out["prompt"]):
        # the injection counts only when this hook injected for this very prompt (the marker holds its hash), never
        # because some record quotes the goals text (red-team L2)
        out["consulted"] = out["consulted"] or _injected_marker(payload, out["prompt"])
    if not out["prompt_id"]:  # no opener in the tail (red-team L1): key on the answer, so turns still differ
        out["prompt_id"] = "answer:" + hashlib.sha256(out["answer"].encode()).hexdigest()[:16]
    return out


def _state_dir() -> Path:
    return _home() / ".agent-harness" / "state" / "status-truth"


def _marker_path(session: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", session)[:120]
    return _state_dir() / f"injected-{safe}"


def _prompt_key(prompt: str) -> str:
    return hashlib.sha256(str(prompt or "").strip().encode()).hexdigest()[:32]


def _injected_marker(payload: dict, prompt: str) -> bool:
    try:
        path = _marker_path(str(payload.get("session_id") or ""))
        return time.time() - path.stat().st_mtime < 6 * 3600 and path.read_text().strip() == _prompt_key(prompt)
    except OSError:
        return False


def _write_private(path: Path, text: str, append: bool = False) -> None:
    """0600 file in a 0700 dir, never through a symlink."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.islink(path.parent):
        raise OSError("state dir is a symlink")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "a" if append else "w") as fh:
        fh.write(text)


def _mark_injected(session: str, prompt: str) -> None:
    try:
        _write_private(_marker_path(session), _prompt_key(prompt))
    except OSError:
        pass


SESSION_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _pointer_path() -> Path:
    return _state_dir() / "mission-session"


def _remember_mission(mission: str) -> None:
    """Keep the mission session id readable when the ledger is not (red-team M1): written whenever a hook reads an ok
    ledger, read when the ledger is absent, unreadable or tampered."""
    try:
        if SESSION_ID_RE.match(mission):
            try:
                if _pointer_path().read_text().strip() == mission:
                    return
            except OSError:
                pass
            _write_private(_pointer_path(), mission)
    except OSError:
        pass


def _remembered_mission() -> str:
    try:
        text = _pointer_path().read_text().strip().lower()
        return text if SESSION_ID_RE.match(text) else ""
    except OSError:
        return ""


FLAG_LOG_MAX = 1 << 20


def _log_flags(payload: dict, turn: dict, mode: str, rules: list) -> None:
    """Every flag (warn or enforce) to a local log: ids and rule names only, never message text (main's rev-3 ruling
    M4); the data for the enforce decision (a Wilson lower bound of at least 0.8 over at least 30 flags). At 1 MiB the
    log stops growing and says so in stderr; it is never rotated or truncated by this hook."""
    try:
        path = _state_dir() / "flags.jsonl"
        try:
            if path.stat().st_size > FLAG_LOG_MAX:
                print("status_truth: flag log full (1 MiB); not logging", file=sys.stderr)
                return
        except OSError:
            pass
        row = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "session": str(payload.get("session_id") or "")[:64],
               "prompt_id": str(turn.get("prompt_id") or "")[:80], "answer_id": str(turn.get("answer_id") or "")[:64],
               "mode": mode, "rules": rules[:12]}
        _write_private(path, json.dumps(row) + "\n", append=True)
    except Exception:  # noqa: BLE001 - logging never breaks the hook
        pass


# ------------------------------------------------------------------ hook commands

def _redactor_ok() -> bool:
    try:
        import redact  # noqa: PLC0415
        return callable(getattr(redact, "redact", None))
    except Exception:  # noqa: BLE001
        return False


def _context(event: str, text: str) -> dict:
    import goals_view  # noqa: PLC0415
    if not _redactor_ok():  # red-team M6: a fixed line with no free text, never a blank "[withheld]" context
        lead = PROMPT_LEAD if event == "UserPromptSubmit" else COMPACT_LEAD
        return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": lead + UNAVAILABLE.format("redactor")}}
    text = goals_view._redact(text)
    if len(text.encode()) > LIMIT:
        text = text.encode()[:LIMIT - 20].decode("utf-8", "ignore") + "\n(truncated)"
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}


PROMPT_LEAD = "Status question: answer from the goal ledger below (ah goals), never from memory; report each goal's " \
              "state as given.\n"
COMPACT_LEAD = "After compaction: the mission goals and their evidence (ah goals). Answer status questions from this, " \
               "not from the summary.\n"


def _safe_doc():
    try:
        return goals_doc()
    except Exception as error:  # noqa: BLE001 - the injection side never fails silent (spec delta H3)
        return {"state": f"error {type(error).__name__}"}


def cmd_prompt(payload: dict) -> dict:
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not is_status_question(prompt) or _policy_mode() == "off":
        return {}
    doc = _safe_doc()
    if not in_scope(payload, doc):
        return {}
    _mark_injected(str(payload.get("session_id") or ""), prompt)
    return _context("UserPromptSubmit", PROMPT_LEAD + goals_text(doc))


def cmd_session_start(payload: dict) -> dict:
    if payload.get("source") != "compact" or _policy_mode() == "off":
        return {}
    doc = _safe_doc()
    if not in_scope(payload, doc):
        return {}
    return _context("SessionStart", COMPACT_LEAD + goals_text(doc))


def cmd_stop(payload: dict) -> dict:
    mode = _policy_mode()
    if mode == "off":
        return {}
    turn = current_turn(payload)
    if not turn["answer"]:
        return {}
    if not STATUS_WORD.search(turn["answer"]):
        return {}  # cheap gate before reading the ledger
    doc = goals_doc()
    if not in_scope(payload, doc):
        return {}
    asked = is_status_question(turn["prompt"])
    if doc.get("state") != "ok":
        if asked:
            return {"systemMessage": "status-truth: " + UNAVAILABLE.format(doc.get("state"))}
        return {}
    verdict = classify(turn["answer"], doc)
    states_status = verdict["status_answer"] or (asked and bool(verdict["goals"]))
    problems, rules = [], []
    for c in verdict["contradictions"][:6]:
        problems.append(f"- {c['goal']}: you wrote \"{c['claim']}\" but ah goals shows {c['state']}")
        rules.append({"rule": c["rule"], "goal": c["goal"], "state": c["state"]})
    if states_status and not turn["consulted"]:
        problems.append("- this answer states goal status but `ah goals` was not run this turn")
        rules.append({"rule": "skip", "goal": "", "state": ""})
    if not problems:
        return {}
    _log_flags(payload, turn, mode, rules)
    text = ("Status-truth: your answer disagrees with or skipped the goal ledger. Run `python3 ~/.claude/hooks/ah.py "
            "goals` and restate from it. Only DONE_LIVE is done; for anything below it say the state and name the "
            "unmet part of the target:\n" + "\n".join(problems))
    if mode == "enforce":
        import stop_blocks  # noqa: PLC0415
        if stop_blocks.allow(str(payload.get("session_id") or ""), turn["prompt_id"], "status_truth"):
            return {"decision": "block", "reason": text[:LIMIT]}
    return {"systemMessage": ("status-truth (already blocked once): " if mode == "enforce" else "status-truth warning: ")
            + text[:1500]}


# ------------------------------------------------------------------ calibration

def calibrate(path: str, uuids=(), limit: int = 200, simulate_injection: bool = True) -> list:
    """Replay both Stop rules over a transcript (spec delta C2): `contradicted` (the answer disagrees with the ledger
    as of its own timestamp) and `skipped` (it states goal status with no `ah goals` call and no injection since the
    prompt that opened its turn). `flagged` is either. With simulate_injection a status question counts as consulted,
    because the installed prompt hook injects the goals for it; historical transcripts predate the hook."""
    import safe_input  # noqa: PLC0415
    import mission_coverage as mc  # noqa: PLC0415
    messages = []
    prompt, consulted = "", False
    for _, raw in safe_input.iter_jsonl_lines(path, 16 << 20):
        if raw is None:  # offline replay: parse every record, the 16 MB read cap bounds it
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("isSidechain"):
            continue
        opened = _opener(rec)
        if opened is not None:
            prompt, consulted = opened[0], False
            continue
        if rec.get("type") != "assistant":
            continue
        content = (rec.get("message") or {}).get("content")
        for blk in content if isinstance(content, list) else []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use" and \
                    GOALS_CALL.search(str((blk.get("input") or {}).get("command") or "")):
                consulted = True
        text = _text_of(rec).strip()
        if text:
            messages.append({"uuid": rec.get("uuid"), "at": rec.get("timestamp"), "text": text, "prompt": prompt,
                             "consulted": consulted})
    if uuids:
        messages = [m for m in messages if m["uuid"] in uuids]
    else:
        messages = messages[-limit:]
    out, cache = [], {}
    for m in messages:
        at = mc.parse_ts(m["at"]) or time.time()
        day = int(at // 600)
        if day not in cache:
            cache[day] = goals_doc(as_of=at)
        v = classify(m["text"], cache[day])
        asked = is_status_question(m["prompt"])
        gate = bool(STATUS_WORD.search(m["text"]))  # the same cheap gate cmd_stop applies first
        states = gate and (v["status_answer"] or (asked and bool(v["goals"])))
        consulted = m["consulted"] or (simulate_injection and asked)
        contradicted = gate and bool(v["contradictions"])
        skipped = states and not consulted
        out.append({"uuid": m["uuid"], "at": m["at"], "status_answer": states, "asked": asked, "goals": v["goals"],
                    "consulted": consulted, "contradicted": contradicted, "skipped": skipped,
                    "flagged": contradicted or skipped, "contradictions": v["contradictions"] if gate else []})
    return out


def _fallback(command: str, reason: str) -> None:
    """On a timeout or crash the injection hooks still say status is unknown (spec delta H3); Stop stays silent."""
    event = {"prompt": "UserPromptSubmit", "session-start": "SessionStart"}.get(command)
    if event:
        lead = PROMPT_LEAD if command == "prompt" else COMPACT_LEAD
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event,
                                                 "additionalContext": lead + UNAVAILABLE.format(reason)}}), flush=True)


_RELEVANT = {"value": False}  # set once the prompt is a status question (or a compact start): only then fall back


def _watchdog(command: str) -> None:
    import threading  # noqa: PLC0415
    started = time.monotonic()

    def watch():
        while time.monotonic() - started < WALL_LIMIT_S:
            time.sleep(0.05)
        print("status_truth: time limit; skipped", file=sys.stderr, flush=True)
        if _RELEVANT["value"]:
            _fallback(command, "timeout")
        os._exit(0)
    threading.Thread(target=watch, daemon=True).start()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("prompt", "stop", "session-start", "calibrate"):
        print(__doc__, file=sys.stderr)
        return 3
    if argv[0] == "calibrate":
        import argparse  # noqa: PLC0415
        p = argparse.ArgumentParser(prog="status_truth.py calibrate")
        p.add_argument("transcript")
        p.add_argument("--uuid", action="append", default=[])
        p.add_argument("--limit", type=int, default=200)
        p.add_argument("--no-simulate-injection", action="store_true",
                       help="do not count a status question as consulted (as if the prompt hook were absent)")
        a = p.parse_args(argv[1:])
        for row in calibrate(a.transcript, tuple(a.uuid), a.limit, not a.no_simulate_injection):
            print(json.dumps(row))
        return 0
    _watchdog(argv[0])
    try:
        import safe_input  # noqa: PLC0415
        raw = safe_input.read_stdin_bounded(4 << 20)
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            return 0
        # the timeout/crash fallback is scoped like everything else (red-team M1): only the remembered mission session
        wants = (argv[0] == "prompt" and is_status_question(str(payload.get("prompt") or ""))) or \
            (argv[0] == "session-start" and payload.get("source") == "compact")
        _RELEVANT["value"] = wants and in_scope(payload, {"state": "unchecked"})
        handler = {"prompt": cmd_prompt, "stop": cmd_stop, "session-start": cmd_session_start}[argv[0]]
        result = handler(payload)
    except Exception as error:  # noqa: BLE001 - fail open: a lint bug must not trap the agent
        print(f"status_truth {argv[0]}: skipped ({type(error).__name__})", file=sys.stderr)
        if _RELEVANT["value"]:
            _fallback(argv[0], f"error {type(error).__name__}")
        return 0
    if result:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
