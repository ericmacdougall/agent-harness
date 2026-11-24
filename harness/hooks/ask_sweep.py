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

A human answer always outranks other evidence: a structured card, an answer row, or a related-session close that cites
the user comes before a related-session close that does not (one carrying an outcome) and before a SUPERSEDES ask (#170
F6).

Every listed item carries `pin` (ASK=REF) and `apply`, the exact ask_sweep command that closes it, plus `close`, the exact
wal_note.py command that command runs. --apply refuses an ask named without its pin, or whose best evidence is no longer the
one that was listed (a row written after the listing), and refuses every close while anything is unread (the listing is
incomplete). An ask that is already closed is reported as resolved, with the row that closed it, and nothing is written.
wal_note.py re-verifies every source. A refused close, a timeout or a wal_note that cannot start is reported with its own
message, the JSON report is always printed, and the run exits 1; after a timeout the ledger is read again, and a close
that was written after all is reported as written.

A close is bookkeeping with NO decision, so it is never an approval for a stop, a grant or a top-rung request (a "No"
answer is closed the same way as a "Yes"). Every close carries `by=ask-sweep`. An answer close (card, answer row, or a
user-sourced close copied from a related session) also gets `closed_by=ask-sweep`. An obsolete close (superseded, or an
outcome close copied from a related session) passes `--outcome`, so wal_note writes `outcome=obsolete|not_user` and
`closed_by=agent` (#170 F8).

The cited answer is quoted exactly as provenance reads it back (ask_evidence.cite): an inner `"` is written `\\"`, and a
literal ellipsis is kept as an elision. Only an answer cited whole (the excerpt equals the normalized answer) gets a
close. An answer that can be cited only with words left out (a piece too short to cite, more pieces than provenance
takes, or an over-long answer) is listed under `short` with `elided: true` and no printed close, because leaving words
out can invert it ("Don't... stop the worker"; #170 triage, CRITICAL). An answer that provenance would accept in no form
is listed under `short` too. Every `short` item is closed by hand, after reading the whole `answer`.

WAL evidence follows the same rule (#170 round 4). An answer row or a related-session close copies the source another
row wrote, so a close is offered from it only when that source cites one human turn and its excerpt is the whole turn
(whole_citation; ask_evidence.cites_whole is the one test for both paths). A source that quotes the turn in part, with an
ellipsis or without ("Do not stop the worker now" cited as "stop the worker now"), or that cannot be checked against the
whole turn, is listed with `manual: true`, `partial: true` and no close; --apply refuses it and writes nothing. A source
that quotes no human words (a wal: pointer, an outcome close) is offered as before.

Listing exits 0 when every file was read in full, and 2 when anything is listed in `unread` (a refused file, a budget
stop, a skipped over-long or unparseable line). ask_sweep reads every WAL and transcript through
ask_evidence.jsonl_records. It refuses to run when AH_HOME or CLAUDE_CONFIG_DIR names another home than the one wal_note.py
and provenance use (Path.home()), because every printed close would then be refused (#170 F7). Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat
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


def home_problem():
    """Why this run cannot use one home, else None. wal_note.py and wal.append write under Path.home(), and provenance
    reads transcripts and WALs under CLAUDE_CONFIG_DIR or Path.home()/.claude. When AH_HOME or CLAUDE_CONFIG_DIR names
    another place, every printed close would be refused or land in another ledger (#170 F7)."""
    home = Path.home().resolve()
    configured = os.environ.get("AH_HOME")
    if configured and Path(configured).expanduser().resolve() != home:
        return "AH_HOME names another home than HOME, which wal_note.py and provenance use: unset it or set HOME to it"
    config = os.environ.get("CLAUDE_CONFIG_DIR")
    if config and Path(config).expanduser().resolve() != home / ".claude":
        return "CLAUDE_CONFIG_DIR is not $HOME/.claude, where wal_note.py writes WALs: unset it for this run"
    return None


def find_transcript(home: Path, session: str):
    """The session transcript exactly as provenance finds it (the same folder walk), so the listing and the check that
    wal_note runs read the same file; None when there is none."""
    sys.path.insert(0, str(HERE))
    import provenance  # noqa: PLC0415
    try:
        return provenance.find_transcript(session, home / ".claude")
    except provenance.Problem:
        return None


def parse_ts(value):
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def answer_turns(transcript: Path, unread=None) -> dict:
    """{ask id: {"uuid", "ts", "answer", "text"}}: the newest user AskUserQuestion answer record per ask id (structured
    answers only). `text` is the whole turn as provenance extracts it (ask_answers_text): the text a cited excerpt is
    checked against."""
    found = {}
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    import provenance  # noqa: PLC0415
    for rec in ask_evidence.jsonl_records(transcript, unread, needle=b"toolUseResult", max_file=MAX_TRANSCRIPT):
        result = rec.get("toolUseResult") if isinstance(rec, dict) else None
        answers = result.get("answers") if isinstance(result, dict) else None
        if rec.get("type") != "user" or rec.get("isSidechain") or not isinstance(answers, dict) \
                or not isinstance(rec.get("uuid"), str):
            continue
        for key, value in answers.items():
            m = ASK_KEY.match(key) if isinstance(key, str) else None
            if m and isinstance(value, str) and value.strip():
                found[m.group(1)] = {"uuid": rec["uuid"], "ts": parse_ts(rec.get("timestamp")) or 0.0,
                                     "answer": " ".join(value.split())[:MAX_ANSWER],
                                     "text": provenance.ask_answers_text(result) or ""}
    return found


def read_asks(main_wal: Path, unread=None) -> dict:
    """{"open": [...], "resolved": {ask id: row}} of the main WAL, through ask_evidence's bounded reader."""
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    return ask_evidence.read_asks(main_wal, parse_ts, unread)


def verified(session: str, uuid: str, home: Path):
    """The answer turn's text when provenance accepts this record as an AskUserQuestion answer of the user (bound
    tool_use, no sidechain, no error), else None."""
    try:
        sys.path.insert(0, str(HERE))
        import provenance  # noqa: PLC0415
        return provenance.answer_turn(session, uuid, home / ".claude")["text"]
    except Exception:  # noqa: BLE001 - anything provenance rejects is not an answer
        return None


def plan(main_wal: Path, transcript: Path, now: float | None = None, check=None, session: str | None = None) -> dict:
    """{"answered", "short", "stale", "unread", "resolved"} for the open asks of one session. `check(uuid)` is the
    provenance check of the answer turn: the turn's text (or True) when provenance accepts it, else falsy. An answered
    item's `source` is the whole answer, cited (ask_evidence.cite) and checked against that text. An answer that can be
    cited only elided, or not at all in a form provenance accepts, goes to `short` with the reason, for a manual close."""
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    now = time.time() if now is None else now
    unread = []
    turns = answer_turns(transcript, unread)
    ledger = read_asks(main_wal, unread)
    session = session or main_wal.parent.name
    answered, short, stale = [], [], []
    for ask in ledger["open"]:
        opened = float(ask["opened"] or 0)
        turn = turns.get(ask["id"])
        checked = (check(turn["uuid"]) if check is not None else True) if turn else None
        if turn and opened and turn["ts"] >= opened - SLACK_S and checked:
            row = {"ask": ask["id"], "turn": turn["uuid"], "at": turn["ts"], "answer": turn["answer"],
                   "question": ask["note"][:120]}
            cited = None
            if len(turn["answer"]) >= MIN_EXCERPT:
                cited = ask_evidence.cite(turn["answer"], checked if isinstance(checked, str) else turn["text"])
            if cited is None:
                row["reason"] = ("too short to cite" if len(turn["answer"]) < MIN_EXCERPT
                                 else "provenance would accept no excerpt of this answer") + ": close it by hand"
                short.append(row)
            elif cited[1]:
                # #170 triage (CRITICAL): an excerpt that leaves words out can invert the answer ("Don't... stop the
                # worker" would be cited as "...stop the worker"), so the tool never closes an elided answer
                row["elided"] = True
                row["reason"] = ("only an excerpt that leaves part of the answer out can be cited, and that can change "
                                 "its meaning: read the whole answer and close it by hand")
                short.append(row)
            else:
                row["source"] = f'answer:{session}/{turn["uuid"]} {cited[0]}'
                answered.append(row)
        elif opened and now - opened >= STALE_S:
            stale.append({"ask": ask["id"], "age_days": int((now - opened) // 86400), "question": ask["note"][:120]})
    return {"answered": answered, "short": short, "stale": stale, "unread": unread, "resolved": ledger["resolved"]}


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
MAX_TRANSCRIPT = 512 * 1024 * 1024
MAX_ANSWER = 1000
CLOSE_OUTCOMES = ("obsolete", "not_user")
CLOSE_TIMEOUT_S = 60


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
        if not stat.S_ISDIR(os.lstat(folder).st_mode):  # a symlinked folder would pull in another session's rows
            unread.append({"source": f"{session} WAL folder", "reason": "folder-not-a-directory"})
            return []
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


def rank(evidence: dict) -> int:
    """Best first. The user's own words come first: a related-session close that cites a human turn (0), then an answer
    row (1). Obsolete evidence comes after every answer: a related-session close that does not cite the user, such as an
    outcome close (2), then a SUPERSEDES ask (3). Terminal evidence, which is manual only, is last (4) (#170 F6)."""
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    if evidence["kind"] == "resolved-elsewhere":
        return 0 if ask_evidence.human_traced(evidence["source"]) and not evidence.get("outcome") else 2
    return {"answer": 1, "superseded": 3, "terminal": 4}[evidence["kind"]]


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


PARTIAL_ACTION = ("manual: this evidence quotes only part of the user's turn, or cannot be checked against the whole "
                  "turn, and leaving words out can change its meaning: read the whole turn and close the ask by hand")
TERMINAL_ACTION = "manual: the user ran this step himself; main decides how to close the ask"


def whole_citation(source: str, home: Path):
    """Whether a WAL-evidence source quotes the user's WHOLE turn (#170 round 4, main's ruling, CRITICAL class).

    - True: it cites one human turn (user:, uuid:, answer:, queue: or pasted:), provenance resolves it, and its excerpt
      is that whole turn, as ask_evidence.cites_whole decides (the rule plan() uses through cite).
    - False: it quotes a human turn in part, or in a form that cannot be checked against the whole turn: an excerpt
      provenance refuses, an `inferred:` chain that quotes the user, an unparseable source that names a human turn.
    - None: it quotes no human words at all (a wal: pointer, a ticket, an outcome close), so no words can be left out.

    Only a False source is held back: listed for a manual close, never offered as one."""
    sys.path.insert(0, str(HERE))
    import ask_evidence  # noqa: PLC0415
    import provenance  # noqa: PLC0415
    try:
        parsed = provenance.parse_source(source)
    except provenance.Problem:
        parsed = {}
    if parsed.get("kind") not in ("user", "pasted"):
        return False if ask_evidence.human_traced(source) else None
    result = provenance.resolve(source, {"home": home / ".claude", "want_text": True})
    node = result["chain"][0] if result.get("ok") and result.get("chain") else {}
    return ask_evidence.cites_whole(node.get("excerpt"), node.get("text"))


def wal_evidence(home: Path, session: str, related=(), unread=None) -> dict:
    """{"items": [...], "unread": [...]}: open main-WAL asks of SESSION with WAL or terminal evidence from SESSION and
    the RELATED sessions (its successors or its coordinator). Read-only. When the best evidence is an answer row or a
    related-session close that quotes the user only in part (whole_citation is False), the item is `manual` and
    `partial`: it is listed for main to read and never offered as a close (#170 round 4)."""
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
            resolutions.setdefault(r["ref"], []).append(r)  # every close of it: one that cites the user must not hide
    items = []
    for ask in read_asks(main_wal, unread)["open"]:
        ident, opened = ask["id"], float(ask["opened"] or 0)
        found = []
        for other in resolutions.get(ident, []):
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
                    # no source: provenance never takes a <bash-input> turn as the user's words, so none would verify
                    found.append({"kind": "terminal", "ref": f"{s}/{uuid}", "session": s, "at": ts, "manual": True,
                                  "summary": f"the user ran in a terminal: {_clip(command, 70)} (matched {hit[0]})",
                                  "source": "", "outcome": None})
        if not found:
            continue
        found.sort(key=lambda e: (rank(e), not e["source"].startswith("answer:"),
                                  not ANSWER_WORDS.search(e["summary"]), e["at"]))
        best = found[0]
        if best["kind"] in ("answer", "resolved-elsewhere") and whole_citation(best["source"], home) is False:
            best["manual"] = best["partial"] = True
        items.append({"ask": ident, "kind": best["kind"], "manual": bool(best.get("manual")),
                      **({"partial": True} if best.get("partial") else {}),
                      "question": ask["note"][:120], "wal": str(main_wal), "evidence": found})
    return {"items": items, "unread": unread}


def close_argv(item: dict):
    """The wal_note.py argv that closes one evidence item (bookkeeping, never --decision), or None for manual evidence:
    terminal evidence, and a citation of only part of the user's turn (#170 round 4). Both are listed for manual action
    only."""
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


RC_TIMEOUT, RC_NOT_RUN = 124, 126


def _default_runner(argv):
    """(rc, stdout, stderr) of one wal_note.py run. A timeout or a wal_note that cannot start is a refused result with
    its own rc, never an exception, so the run's JSON report is always printed (#170 F4)."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=CLOSE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return RC_TIMEOUT, "", (f"wal_note.py did not finish within {CLOSE_TIMEOUT_S} s; the close may or may not have "
                                "been written: run the listing again before retrying")
    except OSError as error:
        return RC_NOT_RUN, "", f"wal_note.py could not be run ({type(error).__name__})"
    return done.returncode, done.stdout, done.stderr


def answered_argv(session: str, main_wal: Path, item: dict) -> list:
    """The wal_note.py argv that closes a structured answer, citing it as `item["source"]` (ask_evidence.cite, already
    checked against provenance's own parse_excerpt and excerpt_in)."""
    return [sys.executable, str(HERE / "wal_note.py"), "--wal", str(main_wal), "--event", "ask_resolved", "--ref", item["ask"],
            "--by", "ask-sweep", "--source", item["source"],
            "--note", f"ask-sweep: the user answered [ask:{item['ask']}] in answer turn {item['turn'][:8]} (bookkeeping, "
                      "not an approval; read the answer before relying on it)"]


def run_close(ask: str, argv, runner=None, manual=None) -> dict:
    """{"ask", "rc", "refused"?}: one wal_note.py run. A refusal carries wal_note's own message, never a silent rc. With
    no argv (manual evidence) nothing runs, and the refusal says why (`manual`, the item's action)."""
    if argv is None:
        return {"ask": ask, "rc": 3, "refused": (manual or "this evidence is listed for manual action only")
                + "; nothing was written"}
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
    problem = home_problem()
    if problem:
        print(json.dumps({"ok": False, "problem": problem}))
        return 2
    home = Path.home()
    main_wal = home / ".claude" / "wals" / args.session / "main.jsonl"
    transcript = find_transcript(home, args.session)
    if not main_wal.is_file() or transcript is None:
        print(json.dumps({"ok": False, "problem": "no main WAL or transcript for this session"}))
        return 3
    result = plan(main_wal, transcript, check=lambda u: verified(args.session, u, home), session=args.session)
    resolved = result.pop("resolved")
    structured = {a["ask"] for a in result["answered"] + result["short"]}
    found = wal_evidence(home, args.session, args.related)
    result["evidence"] = [i for i in found["items"] if i["ask"] not in structured]
    unread, seen = [], set()
    for entry in result["unread"] + found["unread"]:  # the main WAL is read twice; name each gap once
        key = json.dumps(entry, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unread.append(entry)
    result["unread"] = unread
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
            item["action"] = PARTIAL_ACTION if item.get("partial") else TERMINAL_ACTION
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
        closed, ran = [], []
        listed = {i["ask"]: i for i in result["answered"] + result["evidence"]}
        for ask, ref in wanted.items():
            item = listed.get(ask)
            if ask in resolved:
                # a rerun after a timeout or an earlier apply: report the close that is there, write nothing (#170 F4)
                row = resolved[ask]
                closed.append({"ask": ask, "rc": 0, "already_resolved": str(row.get("id")),
                               "closed_by": row.get("closed_by"), "note": "already closed; nothing was written"})
            elif result["unread"]:
                closed.append({"ask": ask, "rc": 3, "refused": "the listing is incomplete (%d item(s) in unread), so the "
                               "best evidence is not known: fix or wait for those files and list again, or run the "
                               "printed close command by hand" % len(result["unread"])})
            elif item is None:
                closed.append({"ask": ask, "rc": 3, "refused": "no answer or evidence is listed for this ask now"})
            elif not ref:
                closed.append({"ask": ask, "rc": 3, "refused": "name the ask with the pin it was listed with: --only " + item["pin"]})
            elif item["pin"] != f"{ask}={ref}":
                closed.append({"ask": ask, "rc": 3, "refused": "the best evidence changed since it was listed (now "
                               + item["pin"] + "); read it again before closing"})
            else:
                argv = (answered_argv(args.session, main_wal, item) if ask in {a["ask"] for a in result["answered"]}
                        else close_argv(item))
                closed.append(run_close(ask, argv, manual=item.get("action")))
                if argv is not None:
                    ran.append((closed[-1], argv[argv.index("--source") + 1]))
        failed = [(entry, source) for entry, source in ran if entry["rc"]]
        if failed:
            # a timeout can fire after wal_note wrote the row: report what the ledger shows, not only the rc
            after = read_asks(main_wal)["resolved"]
            for entry, source in failed:
                row = after.get(entry["ask"])
                if row is None:
                    continue
                if row.get("source") == source and row.get("by") == "ask-sweep":
                    entry.update({"rc": 0, "written": str(row.get("id")),
                                  "note": "wal_note reported rc %d, but the ledger now holds this close" % entry["rc"]})
                else:
                    entry.update({"rc": 0, "already_resolved": str(row.get("id")), "closed_by": row.get("closed_by"),
                                  "note": "wal_note reported rc %d; another row closed the ask meanwhile" % entry["rc"]})
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
