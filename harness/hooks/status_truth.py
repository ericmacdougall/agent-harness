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

Contradiction rule (deliberately narrow, so ordinary "done" talk is never flagged): a line that names a goal (its
aliases, its id as words) and says it is not done / not live / nobody working / no work, while the ledger shows that
goal DONE_LIVE or VERIFIED; or a line that says a goal is done while the ledger shows it FAILING or UNKNOWN.
Mode: provenance_policy.json `status_lint` (off | warn | enforce). Every command fails open on its own errors (stderr
note, exit 0), and a second Stop in a row (stop_hook_active) is never blocked. Output is capped at 4 KB and redacted.
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
NEG_CLAIM = re.compile(
    r"(?i)\b(?:not (?:yet )?(?:done|live|started|built|deployed|working|met|complete[d]?|finished)|"
    r"(?:isn'?t|is not|aren'?t|are not|wasn'?t) (?:yet )?(?:done|live|built|started|finished|complete[d]?)|"
    r"(?:nobody|no one|no-one) (?:is )?(?:working|on it|owns it)|ha(?:s|ve) had no work|no work (?:has|on|this)|"
    r"(?:can'?t|cannot|couldn'?t|could not) (?:yet )?(?:call|say|claim|mark)\b[^.\n]{0,40}\b(?:done|finished|complete)|"
    r"(?:hasn'?t|has not|haven'?t|have not) (?:been )?(?:started|done|tested|finished)|not been (?:started|done|tested))")
DONE_CLAIM = re.compile(r"(?i)(?:\b(?:is|are|now|all|fully) (?:done|complete|finished)\b|:\s*\**\s*done\b|"
                        r"\bdone and (?:tested|live)\b|\bdone,? (?:deployed|live)\b)")
BACKED = ("DONE_LIVE", "LIVE_TESTED")                          # "not done / nobody working" contradicts these
UNBACKED = ("FAILING", "UNKNOWN", "VERIFIED", "LIVE_UNTESTED")  # "is done" over-claims these
UNAVAILABLE = "GOALS UNAVAILABLE ({}): goal status is unknown; do not answer status from memory. Say it is unknown."
GOALS_CALL = re.compile(r"\bah(?:\.py)?\s+goals\b")


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


def in_scope(payload: dict, doc: dict) -> bool:
    """Inject and lint only in the mission session (main's ruling). With no readable ledger there is no mission session
    to compare, so a status question anywhere gets the short GOALS UNAVAILABLE line (the 2026-11-12 state)."""
    if doc.get("state") != "ok":
        return True
    mission = str(doc.get("mission_session") or "").lower()
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


def classify(text: str, doc: dict) -> dict:
    """{status_answer, goals, contradictions[{goal, state, claim, line}]} for one assistant message."""
    goals = doc.get("goals") or [] if doc.get("state") == "ok" else []
    states = {g["id"]: g["state"] for g in goals}
    named, contradictions = set(), []
    for line in strip_code(text).splitlines():
        if not line.strip():
            continue
        hits = _mentions(line, goals)
        if not hits:
            continue
        if STATUS_WORD.search(line):
            named.update(hits)
        for gid in hits:
            st = states.get(gid)
            m = NEG_CLAIM.search(line)
            if m and st in BACKED:
                contradictions.append({"goal": gid, "state": st, "claim": m.group(0), "line": line.strip()[:200]})
                continue
            d = DONE_CLAIM.search(line)
            if d and not m and st in UNBACKED and len(hits) == 1:
                contradictions.append({"goal": gid, "state": st, "claim": d.group(0), "line": line.strip()[:200]})
    return {"status_answer": len(named) >= 2, "goals": sorted(named), "contradictions": contradictions}


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


def _human_turn(record) -> bool:
    if record.get("type") != "user" or record.get("isSidechain") or "toolUseResult" in record:
        return False
    if record.get("isMeta") or record.get("isCompactSummary"):
        return False
    content = (record.get("message") or {}).get("content")
    if isinstance(content, list) and content and all(isinstance(b, dict) and b.get("type") == "tool_result"
                                                      for b in content):
        return False
    return True


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
        elif rec.get("type") == "attachment" or rec.get("type") == "system":
            if "Goals from the mission ledger" in json.dumps(rec)[:200000]:
                out["consulted"] = True
        elif _human_turn(rec):
            out["prompt"] = _text_of(rec)
            out["prompt_id"] = str(rec.get("uuid") or rec.get("timestamp") or "")
            break
        elif rec.get("type") == "user" and "Goals from the mission ledger" in json.dumps(rec)[:200000]:
            out["consulted"] = True
    if isinstance(direct, str) and direct.strip():
        out["answer"] = direct
    if is_status_question(out["prompt"]):
        out["consulted"] = out["consulted"] or _injected_marker(payload)
    return out


def _marker_path(session: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", session)[:120]
    return _home() / ".agent-harness" / "state" / "status-truth" / f"injected-{safe}"


def _injected_marker(payload: dict) -> bool:
    try:
        return time.time() - _marker_path(str(payload.get("session_id") or "")).stat().st_mtime < 3600
    except OSError:
        return False


def _mark_injected(session: str) -> None:
    try:
        p = _marker_path(session)
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        p.write_text(str(time.time()))
    except OSError:
        pass


# ------------------------------------------------------------------ hook commands

def _context(event: str, text: str) -> dict:
    import goals_view  # noqa: PLC0415
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
    _mark_injected(str(payload.get("session_id") or ""))
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
    problems = []
    for c in verdict["contradictions"][:6]:
        problems.append(f"- {c['goal']}: you wrote \"{c['claim']}\" but ah goals shows {c['state']}")
    if states_status and not turn["consulted"]:
        problems.append("- this answer states goal status but `ah goals` was not run this turn")
    if not problems:
        return {}
    text = ("Status-truth: your answer disagrees with or skipped the goal ledger. Run `python3 ~/.claude/hooks/ah.py "
            "goals` and restate from it:\n" + "\n".join(problems))
    if mode == "enforce":
        import stop_blocks  # noqa: PLC0415
        key = turn["prompt_id"] or hashlib.sha256(turn["prompt"].encode()).hexdigest()[:16]
        if stop_blocks.allow(str(payload.get("session_id") or ""), key, "status_truth"):
            return {"decision": "block", "reason": text[:LIMIT]}
    return {"systemMessage": ("status-truth (already blocked once): " if mode == "enforce" else "status-truth warning: ")
            + text[:1500]}


# ------------------------------------------------------------------ calibration

def calibrate(path: str, uuids=(), limit: int = 200) -> list:
    import safe_input  # noqa: PLC0415
    import mission_coverage as mc  # noqa: PLC0415
    messages = []
    prompt = ""
    for _, raw in safe_input.iter_jsonl_lines(path, 16 << 20):
        if raw is None or (b'"type":"assistant"' not in raw and b'"type":"user"' not in raw):
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("isSidechain"):
            continue
        if _human_turn(rec):
            prompt = _text_of(rec)
            continue
        if rec.get("type") != "assistant":
            continue
        text = _text_of(rec).strip()
        if text:
            messages.append({"uuid": rec.get("uuid"), "at": rec.get("timestamp"), "text": text, "prompt": prompt})
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
        out.append({"uuid": m["uuid"], "at": m["at"], "status_answer": v["status_answer"] or (asked and bool(v["goals"])),
                    "asked": asked, "goals": v["goals"], "flagged": bool(v["contradictions"]),
                    "contradictions": v["contradictions"]})
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
        a = p.parse_args(argv[1:])
        for row in calibrate(a.transcript, tuple(a.uuid), a.limit):
            print(json.dumps(row))
        return 0
    _watchdog(argv[0])
    try:
        import safe_input  # noqa: PLC0415
        raw = safe_input.read_stdin_bounded(4 << 20)
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            return 0
        _RELEVANT["value"] = (argv[0] == "prompt" and is_status_question(str(payload.get("prompt") or ""))) or \
            (argv[0] == "session-start" and payload.get("source") == "compact")
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
