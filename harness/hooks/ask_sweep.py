#!/usr/bin/env python3
"""ask-sweep: close the asks the user already answered, and list the stale ones (GoodQA #15565, never-drop upgrade 5).

The audit and Mission Control's "Needs you" queue (goodqa#15612) showed 55 alerting asks, 13 of them already answered. The
user answers through AskUserQuestion, and every answer turn carries the ask ids it answers:

    The user answered: "[ask:w0be7fc1bb92] Is FrameBright your own product ..."="My own product", "[ask:w...] ..."="..."

So an open ask (a main-WAL `ask` row with no `ask_resolved`) whose id appears in a LATER user answer turn is answered, and the
answer is the proof. `ask_sweep.py` lists those (default) or closes them (`--apply`) with
`wal_note.py --event ask_resolved --source answer:<session>/<turn uuid> "<the answer text>"`: the same record `provenance.py`
already trusts as the user's own words. Nothing is closed without the id in the answer turn.

`--stale` lists open asks older than 7 days with no answer turn: candidates for main to close as obsolete or not-the-user's
(wal_note ask_resolved --outcome obsolete|not_user with wal:/file: evidence) or to re-ask in plain words. It never closes them.
Stdlib only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANSWER_HEAD = ("The user answered", "Your questions have been answered")
ASK_SEGMENT = re.compile(r'\[ask:(w[0-9a-f]{11})\](.*?)"="(.*?)"(?=,\s*"\[ask:|\.\s|\s*$)', re.S)
STALE_S = 7 * 86400


def find_transcript(home: Path, session: str):
    hits = glob.glob(str(home / ".claude" / "projects" / "*" / f"{session}.jsonl"))
    return Path(hits[0]) if hits else None


def parse_ts(value):
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


ASK_KEY = re.compile(r"^\[ask:(w[0-9a-f]{11})\]")


def answer_turns(transcript: Path) -> dict:
    """{ask id: {"uuid", "ts", "answer", "excerpt"}}: the newest AskUserQuestion answer record per ask id.

    Uses the structured toolUseResult.answers (question -> answer), the only text provenance accepts as the user's words.
    The excerpt is the answer, padded with the neighbouring answer when under 12 characters (provenance's floor)."""
    found = {}
    with open(transcript, "rb") as handle:
        for raw in handle:
            if b"[ask:w" not in raw or b"toolUseResult" not in raw:
                continue
            try:
                rec = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            result = rec.get("toolUseResult") if isinstance(rec, dict) else None
            answers = result.get("answers") if isinstance(result, dict) else None
            if rec.get("type") != "user" or not isinstance(answers, dict) or not isinstance(rec.get("uuid"), str):
                continue
            items = [(k, v.strip()) for k, v in answers.items() if isinstance(k, str) and isinstance(v, str) and v.strip()]
            for i, (key, value) in enumerate(items):
                m = ASK_KEY.match(key)
                if not m:
                    continue
                excerpt = value
                if len(excerpt) < 12 and len(items) > 1:  # excerpts match across the newline-joined answers
                    excerpt = f"{items[i - 1][1]} {value}" if i else f"{value} {items[1][1]}"
                excerpt = " ".join(excerpt.replace('"', "'").split())[:200] if '"' in excerpt else " ".join(excerpt.split())[:200]
                found[m.group(1)] = {"uuid": rec["uuid"], "ts": parse_ts(rec.get("timestamp")) or 0.0, "answer": value,
                                     "excerpt": excerpt if len(excerpt) >= 12 else ""}
    return found


def open_asks(main_wal: Path) -> list:
    sys.path.insert(0, str(HERE))
    import ask_reminders
    return ask_reminders.open_asks(main_wal, parse_ts)


def excerpt_for(turn: dict) -> str:
    """A verbatim piece of the answer turn to cite: the answer text (a quoted excerpt must occur in the turn)."""
    return turn.get("excerpt") or ""


def plan(main_wal: Path, transcript: Path, now: float | None = None) -> dict:
    """{"answered": [...], "stale": [...]} for the open asks of one session."""
    now = time.time() if now is None else now
    turns = answer_turns(transcript)
    answered, stale = [], []
    for ask in open_asks(main_wal):
        turn = turns.get(ask["id"])
        if turn and turn["ts"] >= float(ask["opened"] or 0) - 60 and excerpt_for(turn):
            answered.append({"ask": ask["id"], "turn": turn["uuid"], "at": turn["ts"], "answer": excerpt_for(turn),
                             "question": ask["note"][:120]})
        elif now - float(ask["opened"] or 0) >= STALE_S:
            stale.append({"ask": ask["id"], "age_days": int((now - float(ask["opened"] or 0)) // 86400),
                          "question": ask["note"][:120]})
    return {"answered": answered, "stale": stale}


def close_answered(session: str, main_wal: Path, items: list, runner=None) -> list:
    """ask_resolved for each answered ask, through wal_note.py (which re-verifies the answer source). Returns [(ask, rc)]."""
    out = []
    for item in items:
        argv = [sys.executable, str(HERE / "wal_note.py"), "--wal", str(main_wal), "--event", "ask_resolved", "--ref", item["ask"],
                "--decision", "approved", "--source", f'answer:{session}/{item["turn"]} "{item["answer"]}"',
                "--note", f"ask-sweep: the user answered [ask:{item['ask']}] in their answer turn {item['turn'][:8]}: "
                          f"{item['answer'][:80]}"]
        run = runner or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=60).returncode)
        out.append((item["ask"], run(argv)))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Close answered asks and list stale ones.")
    parser.add_argument("--session", required=True)
    parser.add_argument("--apply", action="store_true", help="close the answered asks (default: list only)")
    parser.add_argument("--stale", action="store_true", help="also list open asks older than 7 days with no answer")
    parser.add_argument("--only", nargs="+", metavar="ASK", help="act only on these ask ids (a free-text reply may not settle a decision)")
    args = parser.parse_args(argv)
    home = Path(os.environ.get("AH_HOME") or Path.home())
    main_wal = home / ".claude" / "wals" / args.session / "main.jsonl"
    transcript = find_transcript(home, args.session)
    if not main_wal.is_file() or transcript is None:
        print(json.dumps({"ok": False, "problem": "no main WAL or transcript for this session"}))
        return 3
    result = plan(main_wal, transcript)
    if args.only:  # a free-text reply ("examine it") may not settle a decision: main picks what to close
        result["answered"] = [a for a in result["answered"] if a["ask"] in args.only]
    if args.apply:
        result["closed"] = [{"ask": a, "rc": rc} for a, rc in close_answered(args.session, main_wal, result["answered"])]
    if not args.stale:
        result.pop("stale")
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
