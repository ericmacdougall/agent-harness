"""The one rule for which source may close an ask, in which mode (GoodQA goodqa#16944, #170 round 5).

wal_note.py enforces close_verdict when it writes an ask_resolved row, and ask_sweep.py calls the same function before it
prints a close, so the listing can never offer a close the writer refuses: anything close_verdict refuses is listed for
manual action with its reason. No module on the ask-close path (ask_evidence, ask_sweep, wal_note, ask_reminders) keeps
its own list of source kinds: tests/test_ask_close_contract.py checks every kind and spelling in every mode, and an AST
guard keeps private lists out. Three other hooks still keep a narrower prefix check of their own (goodqa#17058).

- TABLE: one row per source word as written (`user:`, `queue:`, `pasted:`, ...). `kind` is what provenance reads it as
  (provenance.SOURCE_WORDS); `human` marks the user's own words, an answer; `chat` marks words from a chat turn, the
  user's own or text he pasted. Each close mode lists whether a source of that word may back it:
  - `answer`: a close with no outcome and no decision (ask_sweep's bookkeeping close);
  - `decision`: a close with --decision approved|declined (an mc: dashboard decision needs it, and mc_bind);
  - `outcome`: --outcome obsolete|not_user, a close no user words back (closed_by=agent).
- The word must be written exactly as the table spells it (lowercase, no space before the colon). provenance would
  read `USER:` or `user :` as a user turn, but wal_note never wrote those spellings, so they are refused and listed
  manual rather than written in a form other readers may not expect.
- An outcome close needs evidence that traces to no chat turn anywhere in its resolution tree (provenance.source_kinds:
  every hop of wal: and inferred:, also a hop that failed to resolve). A user's answer is never recorded as "not the
  user's" or "obsolete" (#170 round 5 F1). Pasted text counts as a chat turn here: it proves the user supplied it, never
  that he asked for it (main's ruling, 2026-11-24), so it backs neither an answer nor an obsolete close. The one
  exception is a later ask that says SUPERSEDES <this id>, cited directly: its source is the user's words for the new
  ask, which makes the old one obsolete.
- Then provenance must resolve the source as an ask's source must (ok, not weak, tracker reachable).
"""
from __future__ import annotations

import re

MODES = ("answer", "decision", "outcome")
_ANSWERS = {"answer": True, "decision": True, "outcome": False}
TABLE = {
    "user":     {"kind": "user", "human": True, "chat": True, **_ANSWERS},
    "uuid":     {"kind": "user", "human": True, "chat": True, **_ANSWERS},
    "answer":   {"kind": "user", "human": True, "chat": True, "card": True, **_ANSWERS},
    "queue":    {"kind": "user", "human": True, "chat": True, **_ANSWERS},
    "pasted":   {"kind": "pasted", "human": False, "chat": True, "answer": False, "decision": False, "outcome": False},
    "mc":       {"kind": "mc", "human": False, "chat": False, "bind": True, "answer": False, "decision": True,
                 "outcome": False},
    "ticket":   {"kind": "ticket", "human": False, "chat": False, "answer": True, "decision": True, "outcome": True},
    "wal":      {"kind": "wal", "human": False, "chat": False, "answer": False, "decision": False, "outcome": True},
    "file":     {"kind": "file", "human": False, "chat": False, "answer": False, "decision": False, "outcome": True},
    "inferred": {"kind": "inferred", "human": False, "chat": False, "answer": False, "decision": False, "outcome": False},
}
HUMAN_KINDS = frozenset(row["kind"] for row in TABLE.values() if row["human"])
CHAT_KINDS = frozenset(row["kind"] for row in TABLE.values() if row["chat"])
HUMAN_TURN = ("the evidence traces to a human turn (the user's words, or text he pasted): close the ask with the user's "
              "answer (answer:/user:), not as obsolete")


def accepted_words(mode: str) -> list:
    return [word for word, row in TABLE.items() if row.get(mode)]


def _words(mode: str) -> str:
    return ", ".join(word + ":" for word in accepted_words(mode))


def _mode_refusal(word: str, mode: str):
    """(problem, hint) when a source of this word never backs this mode."""
    row = TABLE[word]
    if row["chat"] and not row["human"]:
        return ("pasted: text proves the user supplied it, not that he answered or that the ask is obsolete",
                "cite the user's own words (" + ", ".join(w + ":" for w, r in TABLE.items() if r["human"]) + ")")
    if mode == "outcome":
        return (f"--outcome needs evidence written as one of {_words('outcome')}",
                "cite the entry or commit that shows the ask is obsolete or not the user's; inferred: is not evidence")
    if row.get("bind"):
        return ("an mc: dashboard decision closes only the ask it names, with --decision approved|declined",
                "run wal_note.py with --decision, as the dashboard decision says")
    return (f"ask_resolved source must be the answer: {_words('decision')}",
            "an ask cannot be closed on an inferred: or file: source; use --outcome obsolete|not_user with wal:/file: evidence")


def word_of(source: str):
    """The table row word `source` is written with, or None when it is not spelled exactly as a row."""
    match = re.match(r"^([a-z]+):", source or "")
    return match.group(1) if match and match.group(1) in TABLE else None


def is_card(source: str) -> bool:
    """True for a structured AskUserQuestion answer (answer:), which ask_sweep prefers among equally ranked evidence."""
    return bool(TABLE.get(word_of(source) or "", {}).get("card"))


def trace(source: str, home=None) -> dict:
    """{"kinds", "human", "chat", "result"}: the resolution tree of `source` (provenance.resolve) and what it reaches.
    `human` is True when the user's own words are anywhere in it, `chat` when any chat turn is (his words or pasted
    text). Never raises."""
    import provenance  # noqa: PLC0415
    ctx = {"allow_mc": True}
    if home is not None:
        ctx["home"] = home
    result = provenance.resolve(source or "", ctx)
    kinds = provenance.source_kinds(result)
    return {"kinds": kinds, "human": bool(kinds & HUMAN_KINDS), "chat": bool(kinds & CHAT_KINDS), "result": result}


def _outcome_problem(source: str, ref: str, home):
    """(problem, exempt): why this wal:, file: or ticket: evidence cannot back an outcome close of ask `ref`, and
    whether it is a direct SUPERSEDES ask (which may cite the user). The ask's own entry is not evidence about it."""
    import provenance  # noqa: PLC0415
    if re.search(r"#" + re.escape(ref) + r"\s*$", source):
        return "the evidence is the ask itself", False
    if word_of(source) != "wal":
        return None, False
    # Codex final gate F1/F2: read the cited entry exactly as provenance will (relative and ~ paths beneath
    # ~/.claude/wals, regular files inside that root only, bounded line size, total bytes and scan time).
    try:
        parsed = provenance.parse_source(source)
        record = provenance.wal_entry(provenance.resolve_wal_path(parsed["path"], home), parsed["entry"])
    except Exception as error:  # noqa: BLE001 - unparseable, outside the root, missing, not a regular file, too large
        return f"the wal: evidence cannot be read ({getattr(error, 'code', type(error).__name__)})", False
    if not isinstance(record, dict):
        return "the wal: evidence cannot be read (entry missing, malformed, oversized or beyond the scan budget)", False
    if record.get("id") == ref:
        return ("the evidence is the ask itself (by line number)" if parsed["entry"].startswith("L")
                else "the evidence is the ask itself"), False
    import ask_evidence  # noqa: PLC0415 - the one SUPERSEDES rule, shared with ask_sweep.py
    return None, ask_evidence.supersedes(record, ref)


def close_verdict(source, mode: str, ref: str, home=None) -> dict:
    """{"problem", "hint", "word", "kind", "assumption", "trace"}: whether `source` may close ask `ref` in `mode`.
    `problem` is None when wal_note writes the close; otherwise it says why not. `home` is the ~/.claude folder
    provenance reads (None: its default). Never raises."""
    out = {"problem": None, "hint": None, "word": None, "kind": None, "assumption": False, "trace": None}
    if mode not in MODES:
        out["problem"] = f"unknown close mode {mode!r}"
        return out
    text = (source or "").strip()
    if not text:
        out["problem"], out["hint"] = "ask_resolved needs --source", \
            "cite the answer: user:<session>/<uuid> \"words\", answer:<id> or queue:<id> (ah user-msg)"
        return out
    try:
        import provenance  # noqa: PLC0415
    except ImportError:
        out["problem"] = "provenance.py is not installed"
        return out
    word = out["word"] = word_of(text)
    claimed = provenance.claimed_kind(text)
    if word is None or TABLE[word]["kind"] != claimed:
        out["kind"] = claimed
        if claimed:
            out["problem"] = ("the source kind must be written in lowercase with no space before the colon, as wal_note "
                              "writes it")
            out["hint"] = "write it as " + " or ".join(w + ":" for w, r in TABLE.items() if r["kind"] == claimed)
        else:
            out["problem"] = f"ask_resolved source must be the answer: {_words('decision')}"
            out["hint"] = "an ask cannot be closed on free text; cite the answer or use --outcome with wal:/file: evidence"
        return out
    out["kind"] = TABLE[word]["kind"]
    if not TABLE[word][mode]:
        out["problem"], out["hint"] = _mode_refusal(word, mode)
        return out
    exempt = False
    if mode == "outcome":
        try:
            problem, exempt = _outcome_problem(text, ref or "", home)
        except Exception as error:  # noqa: BLE001 - a reader bug refuses, never crashes the writer
            problem = f"the evidence cannot be checked ({type(error).__name__})"
        if problem:
            out["problem"] = problem
            out["hint"] = "cite a different entry that shows the ask is obsolete; a user answer closes it the normal way"
            return out
    try:
        traced = out["trace"] = trace(text, home)
        result = traced["result"]
        if mode == "outcome" and not exempt and traced["chat"]:
            out["problem"] = HUMAN_TURN
            out["hint"] = "cite a different entry that shows the ask is obsolete; a user answer closes it the normal way"
            return out
        out["assumption"] = bool(result.get("assumption"))
        policy = provenance.load_policy()["wal"].get("ask", "warn")
        if policy == "off":
            return out
        problem = None
        if not result.get("ok"):
            first = result["problems"][0] if result.get("problems") else {"code": "rejected", "message": "rejected"}
            problem = f"source rejected ({first['code']}): {first['message']}"
        else:
            problem = provenance.weak_problem(result) or provenance.unreachable_warning(result)
        if problem:
            out["problem"] = problem[:300]
            out["hint"] = "the resolution source must resolve: " + _words("answer" if mode != "outcome" else "outcome")
    except Exception as error:  # noqa: BLE001 - a resolver failure is a refusal, not a crash
        out["problem"] = f"provenance check failed ({type(error).__name__})"
    return out
