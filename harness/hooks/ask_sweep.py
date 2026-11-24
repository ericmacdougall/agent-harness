#!/usr/bin/env python3
"""ask-sweep: list the asks the user already answered, close the ones main picks, and list the stale ones (GoodQA #15565).

The audit and Mission Control's "Needs you" queue (goodqa#15612) showed 55 alerting asks, 13 of them already answered. The
user answers through AskUserQuestion, whose structured result maps each question (it starts with `[ask:<id>]`) to the
selected answer. An open ask (a main-WAL `ask` row with no `ask_resolved`) whose id is a key of a LATER answer record, and
whose answer provenance verifies as the user's own selection, is ANSWERED.

    ask_sweep.py --session S [--related S2 ..]           list answered asks, WAL evidence and `short` answers (read only)
    ask_sweep.py --session S --apply --only A=REF ..     close exactly those asks, each on the evidence REF it was listed with
    ask_sweep.py --session S --stale                     also list asks older than 7 days with no answer (never closed here)

Evidence kinds, best first (GoodQA goodqa#16944): a structured `[ask:<id>]` answer card; `resolved-elsewhere` (an
ask_resolved row for this ask in a related session); `answer` (a later WAL row that names the ask and cites the user's own
words); `superseded` (a later ask whose note says `SUPERSEDES <id>`); `terminal` (the user ran the step himself). Terminal
evidence is listed for MANUAL action only and is never closed here: provenance does not take a `<bash-input>` turn as the
user's words, so no source exists that wal_note would accept, and no row is ever written for it.

Every listed item carries `pin` (ASK=REF) and `apply`, the exact ask_sweep command that closes it, plus `close`, the exact
wal_note.py command that command runs. --apply refuses an ask named without its pin, or whose best evidence is no longer the
one that was listed (a row written after the listing). wal_note.py re-verifies every source; a refused close is reported
with wal_note's own message and the run exits 1.

A close is bookkeeping: `ask_resolved` with `closed_by=ask-sweep` and NO decision, so it is never an approval for a stop, a
grant or a top-rung request (a "No" answer is closed the same way as a "Yes"). The answer text is cited as the whole answer
only. The file reading and the SUPERSEDES and human-turn rules are ask_evidence.py's, shared with wal_note.py. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
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


def answer_turns(transcript: Path, unread=None) -> dict:
    """{ask id: {"uuid", "ts", "answer"}}: the newest user AskUserQuestion answer record per ask id (structured answers only)."""
    found = {}
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    for rec in ask_evidence.jsonl_records(transcript, unread, needle=b"toolUseResult"):
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
    unread = []
    turns = answer_turns(transcript, unread)
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
    return {"answered": answered, "short": short, "stale": stale, "unread": unread}


# --------------------------------------------------------------------------- WAL evidence (GoodQA goodqa#16944)
# Most answers do not come back as a structured `[ask:<id>]` card in the same session. They land as a decision row that
# names the ask and cites the user's own words, as an ask_resolved row in a successor session, as a later ask that
# SUPERSEDES this one, or as the user running the step himself in a terminal. These kinds are listed for main to read;
# a close is still bookkeeping only (no decision), and a terminal match is always marked CONFIRM.

ANSWER_PREFIXES = ("answer:", "user:", "uuid:")
EVIDENCE_EVENTS = ("decision", "ask_resolved", "result", "status", "check", "handoff")
ANSWER_WORDS = re.compile(r"\b(answer(s|ed)?|approved|chose|decided|confirmed)\b", re.I)
WAITING = re.compile(r"\b(pending|awaiting|awaits|waiting|waits|still open|until|blocked on|needs)\b[^.;]{0,40}$", re.I)
TOKEN = re.compile(r"[~\w.\-/]*[/_][~\w.\-/]*")
MIN_TOKEN = 10
GENERIC_TOKENS = {"/home/eric", "/Users/eric", "~/.claude/hooks", "~/.agent-harness/work",
                  "/home/eric/.agent-harness/work", "/Users/eric/.agent-harness/work"}
MAX_LINE = 4 * 1024 * 1024
MAX_TRANSCRIPT = 512 * 1024 * 1024
KIND_ORDER = {"resolved-elsewhere": 0, "answer": 1, "superseded": 2, "terminal": 3}
CLOSE_OUTCOMES = ("obsolete", "not_user")


def _clip(text, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _rows(path: Path, unread: list) -> list:
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    return ask_evidence.jsonl_records(path, unread)


def session_rows(home: Path, session: str, unread: list) -> list:
    """Every row of the session's main and agent WALs, tagged with its file and session. A missing folder is unread."""
    folder = home / ".claude" / "wals" / session
    try:
        names = sorted(n for n in os.listdir(folder) if n == "main.jsonl" or (n.startswith("agent-") and n.endswith(".jsonl")))
    except OSError as error:
        unread.append({"source": f"{session} WAL folder", "reason": type(error).__name__})
        return []
    out = []
    for name in names:
        for rec in _rows(folder / name, unread):
            rec["_wal"], rec["_session"] = str(folder / name), session
            out.append(rec)
    return out


def bash_inputs(home: Path, session: str, unread: list) -> list:
    """The user's own `<bash-input>` commands in the session transcript: (uuid, ts, command)."""
    transcript = find_transcript(home, session)
    if transcript is None:
        unread.append({"source": f"{session} transcript", "reason": "missing"})
        return []
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    found = []
    for rec in ask_evidence.jsonl_records(transcript, unread, needle=b"<bash-input>", max_file=MAX_TRANSCRIPT):
        if not isinstance(rec, dict) or rec.get("type") != "user" or rec.get("isSidechain") or rec.get("isMeta"):
            continue
        content = (rec.get("message") or {}).get("content")
        if isinstance(content, list):
            content = " ".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
        if not isinstance(content, str) or not content.lstrip().startswith("<bash-input>"):
            continue
        m = re.search(r"<bash-input>(.*?)</bash-input>", content, re.S)
        if m and isinstance(rec.get("uuid"), str):
            found.append((rec["uuid"], parse_ts(rec.get("timestamp")) or 0.0, m.group(1)))
    return found


def distinctive_tokens(note: str) -> set:
    tokens = set()
    for token in TOKEN.findall(note or ""):
        token = token.strip(".,;:()'\"`")
        if len(token) >= MIN_TOKEN and token not in GENERIC_TOKENS and not token.endswith("/"):
            tokens.add(token)
    return tokens


def still_waiting(note: str, ident: str) -> bool:
    """True when every mention of the ask reads as still waiting ("pending ask X", "awaiting X"): not an answer."""
    starts = [m.start() for m in re.finditer(re.escape(ident), note)]
    return bool(starts) and all(WAITING.search(note[max(0, s - 60):s]) for s in starts)


def wal_evidence(home: Path, session: str, related=(), unread=None) -> dict:
    """{"items": [...], "unread": [...]}: open main-WAL asks of SESSION with WAL or terminal evidence from SESSION and
    the RELATED sessions (its successors or its coordinator). Read-only."""
    unread = [] if unread is None else unread
    sessions = [session] + [s for s in related if s != session]
    rows = []
    for s in sessions:
        rows.extend(session_rows(home, s, unread))
    inputs = {s: bash_inputs(home, s, unread) for s in sessions}
    main_wal = home / ".claude" / "wals" / session / "main.jsonl"
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    resolutions = {}
    for r in rows:
        if r.get("event") == "ask_resolved" and isinstance(r.get("ref"), str):
            resolutions.setdefault(r["ref"], r)
    items = []
    for ask in (open_asks(main_wal) if main_wal.is_file() else []):
        ident, opened = ask["id"], float(ask["opened"] or 0)
        found = []
        other = resolutions.get(ident)
        if other is not None:
            found.append({"kind": "resolved-elsewhere", "ref": str(other.get("id")), "session": other["_session"],
                          "at": parse_ts(other.get("at")) or 0.0, "summary": str(other.get("note") or ""),
                          "source": str(other.get("source") or ""),
                          "outcome": other.get("outcome") if other.get("outcome") in CLOSE_OUTCOMES else None})
        for r in rows:
            note = str(r.get("note") or "")
            when = parse_ts(r.get("at")) or 0.0
            if r.get("id") == ident or when <= opened or ident not in note:
                continue
            source = str(r.get("source") or "")
            if ask_evidence.supersedes(r, ident):
                found.append({"kind": "superseded", "ref": str(r.get("id")), "session": r["_session"], "at": when,
                              "summary": note, "source": f"wal:{r['_wal']}#{r.get('id')}", "outcome": "obsolete"})
            elif (source.startswith(ANSWER_PREFIXES) and r.get("event") in EVIDENCE_EVENTS
                  and not still_waiting(note, ident)):
                found.append({"kind": "answer", "ref": str(r.get("id")), "session": r["_session"], "at": when,
                              "summary": note, "source": source, "outcome": None})
        tokens = distinctive_tokens(ask["note"])
        for s in sessions:
            for uuid, ts, command in inputs[s]:
                hit = sorted(t for t in tokens if t in command) if ts > opened else []
                if hit:
                    excerpt = _clip(command, 58).replace(chr(34), chr(39))
                    found.append({"kind": "terminal", "ref": f"{s}/{uuid}", "session": s, "at": ts, "manual": True,
                                  "summary": f"the user ran in a terminal: {_clip(command, 70)} (matched {hit[0]})",
                                  "source": f'user:{s}/{uuid} "{excerpt}"', "outcome": None})
        if not found:
            continue
        found.sort(key=lambda e: (KIND_ORDER[e["kind"]], not e["source"].startswith("answer:"),
                                  not ANSWER_WORDS.search(e["summary"]), e["at"]))
        best = found[0]
        items.append({"ask": ident, "kind": best["kind"], "manual": bool(best.get("manual")),
                      "question": ask["note"][:120], "wal": str(main_wal), "evidence": found})
    return {"items": items, "unread": unread}


def close_argv(item: dict):
    """The wal_note.py argv that closes one evidence item (bookkeeping, never --decision), or None for terminal evidence,
    which is listed for manual action only."""
    best = item["evidence"][0]
    if best.get("manual"):
        return None
    source, outcome = best["source"], best.get("outcome")
    argv = [sys.executable, str(HERE / "wal_note.py"), "--wal", item["wal"], "--event", "ask_resolved", "--ref", item["ask"],
            "--by", "ask-sweep", "--source", source,
            "--note", f"ask-sweep: {best['kind']} evidence {best['ref']} resolves [ask:{item['ask']}]: "
                      f"{_clip(best['summary'], 90)} (bookkeeping, not an approval)"]
    if outcome:
        argv += ["--outcome", outcome]
    return argv


def _default_runner(argv):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout, done.stderr


def answered_argv(session: str, main_wal: Path, item: dict) -> list:
    quoted = item["answer"].replace(chr(34), chr(39))
    return [sys.executable, str(HERE / "wal_note.py"), "--wal", str(main_wal), "--event", "ask_resolved", "--ref", item["ask"],
            "--by", "ask-sweep", "--source", f'answer:{session}/{item["turn"]} "{quoted}"',
            "--note", f"ask-sweep: the user answered [ask:{item['ask']}] in answer turn {item['turn'][:8]} (bookkeeping, "
                      "not an approval; read the answer before relying on it)"]


def run_close(ask: str, argv, runner=None) -> dict:
    """{"ask", "rc", "refused"?}: one wal_note.py run. A refusal carries wal_note's own message, never a silent rc."""
    if argv is None:
        return {"ask": ask, "rc": 3, "refused": "terminal evidence is listed for manual action only; nothing was written"}
    rc, stdout, stderr = (runner or _default_runner)(argv)
    return {"ask": ask, "rc": rc, **({"refused": _clip(stderr or stdout or "refused with no message", 400)} if rc else {})}


def pin_of(item: dict) -> str:
    ref = item.get("turn") or item["evidence"][0]["ref"]
    return f"{item['ask']}={ref}"


def apply_command(session: str, related, pin: str) -> str:
    argv = [sys.executable, str(HERE / "ask_sweep.py"), "--session", session]
    for other in related:
        argv += ["--related", other]
    return " ".join(shlex.quote(a) for a in argv + ["--apply", "--only", pin])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="List answered asks, close the ones you pick, list stale ones.")
    parser.add_argument("--session", required=True)
    parser.add_argument("--apply", action="store_true", help="close the asks named by --only")
    parser.add_argument("--only", nargs="+", metavar="ASK=REF",
                        help="the asks to act on; with --apply each needs the pin (ASK=REF) it was listed with")
    parser.add_argument("--stale", action="store_true", help="also list open asks older than 7 days with no answer")
    parser.add_argument("--related", action="append", default=[], metavar="SESSION",
                        help="also search this session's WALs and transcript for evidence (a successor or the coordinator)")
    args = parser.parse_args(argv)
    if not SESSION_ID.match(args.session) or not all(SESSION_ID.match(s) for s in args.related):
        print(json.dumps({"ok": False, "problem": "--session and --related must be session ids"}))
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
    structured = {a["ask"] for a in result["answered"] + result["short"]}
    found = wal_evidence(home, args.session, args.related)
    result["evidence"] = [i for i in found["items"] if i["ask"] not in structured]
    result["unread"] = result["unread"] + found["unread"]
    for item in result["answered"]:
        item["pin"] = pin_of(item)
        item["close"] = " ".join(shlex.quote(a) for a in answered_argv(args.session, main_wal, item))
        item["apply"] = apply_command(args.session, args.related, item["pin"])
    for item in result["evidence"]:
        argv = close_argv(item)
        item["pin"] = pin_of(item)
        if argv is None:
            item["close"] = None
            item["apply"] = None
            item["action"] = "manual: the user ran this step himself; main decides how to close the ask"
        else:
            item["close"] = " ".join(shlex.quote(a) for a in argv)
            item["apply"] = apply_command(args.session, args.related, item["pin"])
    if args.only:
        wanted = {}
        for entry in args.only:
            ask, _, ref = entry.partition("=")
            wanted[ask] = ref
        result["answered"] = [a for a in result["answered"] if a["ask"] in wanted]
        result["evidence"] = [i for i in result["evidence"] if i["ask"] in wanted]
    if args.apply:
        closed = []
        listed = {i["ask"]: i for i in result["answered"] + result["evidence"]}
        for ask, ref in wanted.items():
            item = listed.get(ask)
            if item is None:
                closed.append({"ask": ask, "rc": 3, "refused": "no answer or evidence is listed for this ask now"})
            elif not ref:
                closed.append({"ask": ask, "rc": 3, "refused": "name the ask with the pin it was listed with: --only " + item["pin"]})
            elif item["pin"] != f"{ask}={ref}":
                closed.append({"ask": ask, "rc": 3, "refused": "the best evidence changed since it was listed (now "
                               + item["pin"] + "); read it again before closing"})
            elif ask in {a["ask"] for a in result["answered"]}:
                closed.append(run_close(ask, answered_argv(args.session, main_wal, item)))
            else:
                closed.append(run_close(ask, close_argv(item)))
        result["closed"] = closed
        if not args.stale:
            result.pop("stale")
        print(json.dumps(result, indent=1))
        return 1 if any(c["rc"] for c in closed) else 0
    if not args.stale:
        result.pop("stale")
    print(json.dumps(result, indent=1))
    return 2 if result["unread"] else 0


if __name__ == "__main__":
    sys.exit(main())
