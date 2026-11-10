#!/usr/bin/env python3
"""ask-sweep: list the asks the user already answered, close the ones main picks, and list the stale ones (GoodQA #15565).

The audit and Mission Control's "Needs you" queue (goodqa#15612) showed 55 alerting asks, 13 of them already answered. The
user answers through AskUserQuestion, whose structured result maps each question (it starts with `[ask:<id>]`) to the
selected answer. An open ask (a main-WAL `ask` row with no `ask_resolved`) whose id is a key of a LATER answer record, and
whose answer provenance verifies as the user's own selection, is ANSWERED.

    ask_sweep.py --session S                    list answered asks (and `short`: answers under 12 characters, which cannot be cited)
    ask_sweep.py --session S --apply --only A.. close exactly those asks; --apply needs --only: main reads each answer first
    ask_sweep.py --session S --stale            also list asks older than 7 days with no answer (never closed here)

A close is bookkeeping: it writes `ask_resolved` with the `answer:` source and `closed_by=ask-sweep` and NO decision, so it is
never an approval for a stop, a grant or a top-rung request (a "No" answer is closed the same way as a "Yes"). The answer text
is cited as the whole answer only; it is never padded with another question's answer. Stdlib only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASK_KEY = re.compile(r"^\[ask:(w[0-9a-f]{11})\]")
SESSION_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
STALE_S = 7 * 86400
SLACK_S = 60
MIN_EXCERPT = 12


def find_transcript(home: Path, session: str):
    hits = sorted((home / ".claude" / "projects").glob(f"*/{session}.jsonl"))
    return hits[0] if hits else None


def parse_ts(value):
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def answer_turns(transcript: Path) -> dict:
    """{ask id: {"uuid", "ts", "answer"}}: the newest user AskUserQuestion answer record per ask id (structured answers only)."""
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
            if rec.get("type") != "user" or rec.get("isSidechain") or not isinstance(answers, dict) \
                    or not isinstance(rec.get("uuid"), str):
                continue
            for key, value in answers.items():
                m = ASK_KEY.match(key) if isinstance(key, str) else None
                if m and isinstance(value, str) and value.strip():
                    found[m.group(1)] = {"uuid": rec["uuid"], "ts": parse_ts(rec.get("timestamp")) or 0.0,
                                         "answer": " ".join(value.split())[:300]}
    return found


def open_asks(main_wal: Path) -> list:
    sys.path.insert(0, str(HERE))
    import ask_reminders
    return ask_reminders.open_asks(main_wal, parse_ts)


def verified(session: str, uuid: str, home: Path) -> bool:
    """provenance accepts this record as an AskUserQuestion answer of the user (bound tool_use, no sidechain, no error)."""
    try:
        sys.path.insert(0, str(HERE))
        import provenance
        provenance.answer_turn(session, uuid, home / ".claude")
        return True
    except Exception:  # noqa: BLE001 - anything provenance rejects is not an answer
        return False


def plan(main_wal: Path, transcript: Path, now: float | None = None, check=None) -> dict:
    """{"answered": [...], "short": [...], "stale": [...]} for the open asks of one session."""
    now = time.time() if now is None else now
    turns = answer_turns(transcript)
    answered, short, stale = [], [], []
    for ask in open_asks(main_wal):
        opened = float(ask["opened"] or 0)
        turn = turns.get(ask["id"])
        if turn and opened and turn["ts"] >= opened - SLACK_S and (check is None or check(turn["uuid"])):
            row = {"ask": ask["id"], "turn": turn["uuid"], "at": turn["ts"], "answer": turn["answer"],
                   "question": ask["note"][:120]}
            (answered if len(turn["answer"]) >= MIN_EXCERPT else short).append(row)
        elif opened and now - opened >= STALE_S:
            stale.append({"ask": ask["id"], "age_days": int((now - opened) // 86400), "question": ask["note"][:120]})
    return {"answered": answered, "short": short, "stale": stale}


def close_answered(session: str, main_wal: Path, items: list, runner=None) -> list:
    """ask_resolved for each answered ask, through wal_note.py (which re-verifies the answer source). Returns [(ask, rc)].
    No --decision: the close is not an approval whatever the answer was."""
    out = []
    for item in items:
        quoted = item["answer"].replace(chr(34), chr(39))
        argv = [sys.executable, str(HERE / "wal_note.py"), "--wal", str(main_wal), "--event", "ask_resolved", "--ref", item["ask"],
                "--by", "ask-sweep", "--source", f'answer:{session}/{item["turn"]} "{quoted}"',
                "--note", f"ask-sweep: the user answered [ask:{item['ask']}] in answer turn {item['turn'][:8]} (bookkeeping, "
                          "not an approval; read the answer before relying on it)"]
        run = runner or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=60).returncode)
        out.append((item["ask"], run(argv)))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="List answered asks, close the ones you pick, list stale ones.")
    parser.add_argument("--session", required=True)
    parser.add_argument("--apply", action="store_true", help="close the asks named by --only")
    parser.add_argument("--only", nargs="+", metavar="ASK", help="the ask ids to act on")
    parser.add_argument("--stale", action="store_true", help="also list open asks older than 7 days with no answer")
    args = parser.parse_args(argv)
    if not SESSION_ID.match(args.session):
        print(json.dumps({"ok": False, "problem": "--session must be a session id"}))
        return 2
    if args.apply and not args.only:
        print(json.dumps({"ok": False, "problem": "--apply needs --only: read each answer, then name the asks to close"}))
        return 2
    home = Path(os.environ.get("AH_HOME") or Path.home())
    main_wal = home / ".claude" / "wals" / args.session / "main.jsonl"
    transcript = find_transcript(home, args.session)
    if not main_wal.is_file() or transcript is None:
        print(json.dumps({"ok": False, "problem": "no main WAL or transcript for this session"}))
        return 3
    result = plan(main_wal, transcript, check=lambda u: verified(args.session, u, home))
    if args.only:
        result["answered"] = [a for a in result["answered"] if a["ask"] in args.only]
    if args.apply:
        result["closed"] = [{"ask": a, "rc": rc} for a, rc in close_answered(args.session, main_wal, result["answered"])]
    if not args.stale:
        result.pop("stale")
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
