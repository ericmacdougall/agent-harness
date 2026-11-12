#!/usr/bin/env python3
"""Mission coverage (GoodQA goodqa#15565): every active mission goal is held by someone, waits on something named,
or is done with evidence. Anything else is UNCOVERED.

Why: on 2026-11-10 the leads goal (goodqa#15095) had no owner all night and nothing said so. The dropped-owner scan
(`ah owners`, dropped_gate.py) sees owners that existed and stopped; a goal that never had an owner is invisible to it.

Goals live in ONE canonical file, ~/.agent-harness/mission/goals.json (dir 0700, file 0600):
  {"mission_session": <session id of the main that owns the mission>, "goals": [
    {id, title, ticket ('goodqa#N' or 'Project#N'), priority (1 = most important .. 9),
     status ('imported'|'active'|'done'|'deferred'|'retired'), deferral {by: 'user'|'ask'|'ticket', ref, until (ISO),
     source, renewal}, wait_count, bound [full agent ids main bound to the goal], retire {source},
     done_evidence [{kind: 'deploy'|'really_tested', ref, session}], repos [paths], dashboard {...informational},
     target {text, source} (main-only; the source resolves to the user's own words), aliases [words the status lint
     matches], evidence [{id, session, wal, kind: 'deploy'|'live_test'|'test', at, by, row_sha, row_verdict, row_at}]
     (row_*: the row as attach saw it, so a later rewrite reads TAMPERED, red-team F2) (goodqa#15754: WAL rows that
     `ah goals` reads with no time window; `attach` checks each id exists)}]}
Every write goes through this tool and appends a hash-chained row to ~/.agent-harness/state/mission-goals-audit.jsonl
(rotated into chained segments past MAX_AUDIT_BYTES); a goals file that no longer matches the chain head is tampered.

Main-only commands (set --ticket/--repo, defer --user-source/--ticket, import-initiatives, reseal, activate,
set-session, bind, retire) need a one-shot stamp that main's own PreToolUse hook (mission_gate.py pretool,
caller_identity.is_main) writes for that exact argument list (argv_key) when the script runs at shell command
position; the command consumes it first, before parsing (claim_main). A sub-agent's shell, a copied script, a cron job,
an echoed or here-document line, and a leftover stamp from a different command find none. The stamp is bound to main's
tool call (goodqa#15754 red-team F1): it carries main's tool_use_id and is honoured only while that call is still running
and at most MAIN_STAMP_TTL_SECONDS old, so a stamp of a call that never ran (denied by another hook, rejected, or
`cd /nonexistent && ...`) is dead for every later process. Once goals.json names a
mission session, only that session's main passes (require_main; set_session has the hand-over rule). Each of them
raises a high `mission:goals:changed` ops alert, as does every ask or ticket wait. Stamps are not signed: a same-user
process can write one (the documented threat model, see caller_identity.py and docs/operations.md).

A goal is covered by
  (a) a LIVE OWNER: an `ah owners` row of an owner type (never a helper) in a running state whose stream ticket (the
      first GoodQA ticket in its WAL) is the goal's ticket, or whose exact full agent id main bound to the goal;
  (b) a LIVE DISPOSITION: an `ah task dispose` waiting/resumed/reassigned disposition that ah reports live, on such an
      owner; a wait on an open ask that names the goal, or (main) on another ticket that is still open when checked,
      with `until` at most WAIT_MAX_S ahead and at most MAX_RENEWALS waits in a row; or a deferral whose `user:`/
      `answer:` one-segment source resolves through provenance.py to the user's own words saying defer right next to
      the goal, with no condition, refusal or negation anywhere in the user's sentence;
  (c) DONE EVIDENCE: status 'done' with a deploy record and a later live REALLY_TESTED entry from the mission session
      that name the goal's ticket (ah's own evidence resolvers, the DONE_LIVE rule).
'imported' goals are not enforced until main activates them; 'retired' needs the user's words naming the goal.
STALLED: covered by owners but no own WAL entry by any of them and no commit naming the ticket for more than STALL_S.

Owner lists: the full `ah owners` scan takes 10-25 s on a large session. ops-watch (every 10 min) writes it as a
signed snapshot (HMAC-SHA256, key in a 0600 file, `by: ops_watch`, monotone seq); the Stop gate uses that snapshot
when it is under SNAPSHOT_MAX_S old, else scans live within its budget, and never treats a missing, forged, replayed
or overrun scan as coverage. Limit: the key is readable by every process of the same user, so the signature stops a
careless agent or a stray write, not a same-user agent that sets out to forge it (the hooks themselves are editable
by such an agent too; see caller_identity.py).

Commands: add, set, defer, done, activate, retire, bind, set-session, import-initiatives, reseal, verify,
report [--json], check. Exit 0 ok, 1 uncovered (check), 2 refused or unreadable. Stdlib only.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time
import unicodedata
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import safe_input  # noqa: E402

STALL_S = 45 * 60
WAIT_MAX_S = 7 * 86400  # an ask or ticket wait is renewed at least weekly, never parked (same bound as ah dispositions)
MAX_RENEWALS = 2        # waits in a row without the user's word; the third makes the goal UNCOVERED again
MAX_GOALS_BYTES = 1 << 20
MAX_GOALS = 500
MAX_DEPTH = 8
MAX_AUDIT_BYTES = 16 << 20
FIELD_MAX = 80
STATUSES = ("imported", "active", "done", "deferred", "retired")
DEFER_BY = ("user", "ask", "ticket")
EVIDENCE_KINDS = ("deploy", "really_tested")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ASK_ID_RE = re.compile(r"^w[0-9a-f]{11}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:#-]{0,79}$")
AGENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")  # a full agent id, never an 8-character prefix
SESSION_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TICKET_RE = re.compile(r"\s*(?:GoodQA\s+)?(?:([A-Za-z][A-Za-z0-9-]{0,62})\s*)?#\s*([1-9][0-9]{0,9})\s*", re.I)
BIND_SOURCE_RE = re.compile(r"^(user|answer|queue|ticket):\S")
LIFECYCLE_EVENTS = ("pretool", "subagent", "subagent_stop", "prompt", "session", "pending_stop")
RUNNING = ("live", "working", "quiet")  # plus SILENT / SILENT-HIGH unless main disposed of the owner (tier_gate F4)
LIVE_DISPOSITIONS = ("waiting", "resumed", "reassigned")
HELPERS_DEFAULT = ("red-team", "click-tester", "reviewer", "fixer", "Explore", "Plan", "claude-code-guide",
                   "statusline-setup")
DONE_LIKE = ("done", "live", "complete", "completed", "shipped", "retire", "retired")
SCRIPT = "python3 ~/.claude/hooks/mission_coverage.py"
GENESIS = "0" * 64
MAIN_ONLY = ("set", "defer", "import-initiatives", "reseal", "activate", "set-session", "bind", "retire", "attach")
# attach is open to an owner whose evidence row (or its WAL) names the goal; main's stamp lifts that and allows --remove
ATTACH_KINDS = ("deploy", "live_test", "test")
PIN_VERDICTS = ("DEPLOY", "PASS", "FAIL", "UNSTATED")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ATTACHED = 50
MAX_ALIASES = 12
WAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.jsonl$")
ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9 ./#+-]{1,39}$")
STAMP_PURPOSE = "mission-main"
MAIN_STAMP_TTL_SECONDS = 60  # F1: the stamp lives only as long as main's own call (bound to its tool_use_id)
# Every user quote (defer, retire, takeover) is judged by user_words_ok on the whole sentence, as written: no word
# is ever removed to make a phrase pass (r14 F3: eade6bd deleted "not now" before the refusal check).
REFUSAL_WORDS = re.compile(r"\b(?:don't|dont|do not|never|not|no|nor|neither|if|unless|maybe|perhaps|whether|should|"
                           r"could|would|might|won't|can't|cannot|"
                           r"(?:does|did|is|are|was|were|wo|ca|should|would|could|must|have|has|had|need)n'?t)\b|"
                           r"n't\b|\?")
# words that undo, retract or redirect the verb ("stop parking leads", "park X instead of leads", "never mind")
NEGATING_WORDS = re.compile(r"\b(?:stop\w*|quit\w*|resum\w*|restart\w*|unpark\w*|unpaus\w*|undo\w*|except|instead|"
                            r"abort\w*|halt\w*|revert\w*|refus\w*|reject\w*|veto\w*|never ?mind|scratch that|"
                            r"forget (?:it|that)|belay)\b")
# The verb sits right next to the goal (<g> stands for its id or #ticket, with "the", "goal", "work" and the like
# folded in); "wait", "later", "hold" and "stop" alone are not a decision (H1, delta red-team of PR 179).
_G = "<g>"
DEFER_PHRASES = re.compile(
    r"(?:^| )(?:(?:defer|defers|deferred|deferring|park|parks|parked|parking|pause|pauses|paused|pausing|postpone|"
    r"postpones|postponed|postponing|shelve|shelves|shelved|shelving) <g>|hold off on <g>|put <g> on hold|"
    r"<g> (?:can wait|on hold)|<g> (?:is|are) (?:deferred|parked|paused|postponed|shelved|on hold))(?: |$)")
RETIRE_PHRASES = re.compile(
    r"(?:^| )(?:(?:drop|drops|dropped|dropping|cancel|cancels|cancelled|canceled|cancelling|canceling|retire|retires|"
    r"retired|retiring|kill|kills|killed|killing|abandon|abandons|abandoned|abandoning|scrap|scraps|scrapped|"
    r"scrapping) <g>|<g> (?:is|are|was|has been) (?:dropped|cancelled|canceled|retired|killed|abandoned|scrapped|"
    r"dead))(?: |$)")
# A takeover names the mission right after its verb (<g> stands for "the mission") and says where it goes: this
# session ("here", "this session", "you"), or the sentence is an imperative to this session ("take over the
# mission."). Cancelling words and another destination refuse it (r14 F2: "stop the mission takeover").
TAKEOVER_PHRASES = re.compile(
    r"(?:^| )(?:(?:take|takes|taking|took) over <g>|(?:take|takes|taking|took) <g> over|"
    r"(?:hand|hands|handed|handing|move|moves|moved|moving|transfer|transfers|transferred|transferring|pass|passes|"
    r"passed|passing|bring|brings|brought|bringing) (?:over )?<g> (?:over )?(?:here|to you|to this session|"
    r"into this session|in this session))(?: |$)")
TAKEOVER_DESTINATION = re.compile(r"\b(?:here|this session|you|yourself)\b")
TAKEOVER_IMPERATIVE = re.compile(r"^(?:(?:please|ok|okay|yes|right|alright|now|so|and|then|go ahead and) )*$")
TAKEOVER_UNDO = re.compile(r"\b(?:cancel\w*|drop\w*|abandon\w*|kill\w*|scrap\w*|block\w*|prevent\w*|avoid\w*|"
                           r"keep|leave|hold off|give (?:it )?back|other|another|previous)\b|"
                           r"\bto (?:the |that |a |old |original |first )*(?:session|main|agent|owner|chat|window)\b|"
                           r"\b(?:to|for) (?:session )?[0-9a-f]{8}\b")
MISSION_GOAL = {"id": "mission", "ticket": ""}
LEAD_FILLER = {"the", "this", "that", "our", "my", "goodqa"}
TRAIL_FILLER = {"goal", "goals", "work", "stream", "ticket", "initiative", "project", "effort"}


class MissionError(ValueError):
    """A request this tool refuses; the message says why and what to do instead."""


# ------------------------------------------------------------------ paths and small helpers

def home_dir() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def goals_path(home: Path) -> Path:
    return Path(home) / ".agent-harness" / "mission" / "goals.json"


def state_root(home: Path) -> Path:
    return Path(home) / ".agent-harness" / "state"


def audit_path(home: Path) -> Path:
    return state_root(home) / "mission-goals-audit.jsonl"


def head_path(home: Path) -> Path:
    return state_root(home) / "mission-goals-audit.head"


def private_dir(home: Path) -> Path:
    """state/mission: the signed owner snapshots, the verification cache and their key."""
    return state_root(home) / "mission"


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


def row_digest(rec) -> str:
    """sha256 of a WAL row as canonical JSON (sorted keys, no spaces, ASCII escapes): what attach pins and ah goals
    re-checks (F2). Canonical rather than the raw line, so re-serialising an unchanged row (key order, spacing) is not
    a change. ensure_ascii=True (PR 226 review L2): every character, a lone surrogate included, has its own escape, so
    no two different rows share one serialisation (ensure_ascii=False with utf-8 "replace" mapped lone surrogates and
    "?" to the same bytes)."""
    return hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                          .encode("ascii")).hexdigest()


def legacy_row_digest(rec):
    """The first pinning digest (ensure_ascii=False, utf-8), for pins written before row_digest changed; None for a
    row the old digest cannot tell apart from another (one holding a lone surrogate, which "replace" turned into
    "?"). For an ASCII-only row both digests are equal."""
    try:
        data = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return None
    return hashlib.sha256(data).hexdigest()


def row_matches(pin_sha, rec) -> bool:
    """Whether a pinned row_sha still matches the WAL row: the current digest, or the legacy one where it is
    collision-free (pins made by the first PR 226 build stay valid rather than all reading TAMPERED)."""
    if not isinstance(pin_sha, str) or not pin_sha:
        return False
    return pin_sha == row_digest(rec) or pin_sha == legacy_row_digest(rec)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean(value, cap: int = FIELD_MAX) -> str:
    """One line of plain text: control, format and separator characters become spaces; at most `cap` characters.
    Every value from the goals file, a WAL or a ticket goes through this before it reaches main."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    out = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in text[:cap * 4])
    return out[:cap]


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


# ------------------------------------------------------------------ the user's words

def _norm_words(text) -> str:
    return (text if isinstance(text, str) else "").lower().replace("’", "'")[:2000]


def names_goal(text, goal: dict) -> bool:
    """True when the text names the goal: its id as a word (also written with spaces or hyphens, e.g. 'self-update'
    for selfupdate) or its ticket number after '#'."""
    low = _norm_words(text)
    if not low:
        return False
    words = re.findall(r"[a-z0-9]+", low)
    grams = set(words) | {a + b for a, b in zip(words, words[1:])} | {a + b + c for a, b, c in zip(words, words[1:], words[2:])}
    gid = re.sub(r"[^a-z0-9]", "", str(goal.get("id") or "").lower())
    if gid and gid in grams:
        return True
    key = ticket_key(goal.get("ticket"))
    return bool(key) and re.search(r"#\s*%s(?![0-9])" % key.split("#")[1], low) is not None


def goal_tokens(text, goal: dict) -> str:
    """The text as space-separated words with each mention of the goal (its id, also spelt with spaces or hyphens,
    or '#<ticket number>') replaced by <g>, and filler next to it ("the leads goal", "goodqa#15095") folded in."""
    low = _norm_words(text)
    words = [re.sub(r"\s+", "", w) for w in re.findall(r"#\s*[0-9]+|[a-z0-9]+(?:'[a-z]+)?", low)]
    gid = re.sub(r"[^a-z0-9]", "", str(goal.get("id") or "").lower())
    key = ticket_key(goal.get("ticket")) or ""
    number = "#" + key.split("#")[1] if key else None
    lead = LEAD_FILLER | ({key.split("#")[0]} if key else set())
    out, i = [], 0
    while i < len(words):
        for n in (3, 2, 1):
            span = words[i:i + n]
            if len(span) == n and ((gid and "".join(span) == gid) or (n == 1 and number and span[0] == number)):
                while out and out[-1] in lead:
                    out.pop()
                if not out or out[-1] != _G:
                    out.append(_G)
                i += n
                while i < len(words) and words[i] in TRAIL_FILLER:
                    i += 1
                break
        else:
            out.append(words[i])
            i += 1
    return " ".join(out)


def _takeover_tokens_ok(tokens: str) -> bool:
    m = TAKEOVER_PHRASES.search(tokens)
    if m is None:
        return False
    lead = tokens[:m.start()].strip()
    imperative = TAKEOVER_IMPERATIVE.match(lead + " " if lead else "") is not None
    return TAKEOVER_DESTINATION.search(tokens) is not None or imperative


WORD_RULES = {  # kind: (phrase test on goal_tokens of one sentence, extra undoing words for that kind)
    "defer": (lambda tokens: DEFER_PHRASES.search(tokens) is not None, None),
    "retire": (lambda tokens: RETIRE_PHRASES.search(tokens) is not None, None),
    "takeover": (_takeover_tokens_ok, TAKEOVER_UNDO),
}


def user_words_ok(text, kind: str, goal: dict = None) -> bool:
    """The one negation-aware check of the user's words, shared by defer, retire and takeover (r14 F2/F3). The text
    (a quote, or every sentence around it joined by ' | ') must hold no refusal, condition, question or undoing word
    anywhere, judged on the full text as written, and each sentence must hold the kind's phrase next to the goal
    (the mission for 'takeover')."""
    phrase_ok, undo = WORD_RULES[kind]
    low = _norm_words(text)
    if not low or REFUSAL_WORDS.search(low) or NEGATING_WORDS.search(low) or (undo and undo.search(low)):
        return False
    target = MISSION_GOAL if kind == "takeover" else goal
    sentences = [part for part in low.split(" | ") if part.strip()]
    return bool(sentences) and all(phrase_ok(goal_tokens(part, target)) for part in sentences)


def deferral_words_ok(text, goal: dict) -> bool:
    """The user's words say defer/park/pause/postpone/shelve right next to the goal ("park leads", "put #15095 on
    hold", "leads can wait"), with no refusal, condition or negation anywhere in them ("don't", "if", "maybe", a
    question, "stop parking", "instead"). Callers pass the whole sentence around the quote (user_context)."""
    return user_words_ok(text, "defer", goal)


def retire_words_ok(text, goal: dict) -> bool:
    """The user's words say drop/cancel/retire/abandon/scrap (or kill) right next to the goal, with no refusal,
    condition or negation anywhere in them."""
    return user_words_ok(text, "retire", goal)


def source_excerpt(source) -> str:
    try:
        import provenance  # noqa: PLC0415
        return str(provenance.parse_source(source).get("excerpt") or "")
    except Exception:  # noqa: BLE001 - an unparseable source has no words
        return ""


def _one_segment(excerpt: str) -> bool:
    return "..." not in excerpt.replace("…", "...")


def excerpt_words_ok(source, goal: dict, kind: str) -> bool:
    """Pure check of a stored source (no transcript read): one quoted segment whose words pass the check for kind
    ('defer' or 'retire'). assess() adds the whole-sentence check (context_words_ok)."""
    words = source_excerpt(source)
    if not words or not _one_segment(words):
        return False
    return (deferral_words_ok if kind == "defer" else retire_words_ok)(words, goal)


def sentences_around(text: str, excerpt: str) -> str:
    """Every sentence of text that holds an occurrence of excerpt (both whitespace-normalised), joined; '' when the
    excerpt is not in text. A sentence ends at . ! ? or ; followed by a space, or at a removed non-user block."""
    if not excerpt:
        return ""
    found, start = [], 0
    while True:
        at = text.find(excerpt, start)
        if at < 0:
            break
        heads = [m.end() for m in re.finditer(r"[.!?;](?= )|￼", text[:at])]
        tail = re.search(r"[.!?;](?= |$)|￼", text[at + len(excerpt):])
        end = at + len(excerpt) + (tail.end() if tail else len(text))
        found.append(text[heads[-1] if heads else 0:end].strip())
        start = at + 1
    return " | ".join(dict.fromkeys(found))


def user_context(source) -> str:
    """The sentence(s) of the user's own turn that hold the quoted words: '' unless the source is a user: or answer:
    source that provenance.py resolves to a human-authored turn and its excerpt is one segment (no '...')."""
    try:
        import provenance  # noqa: PLC0415
        parsed = provenance.parse_source(source)
        if parsed.get("kind") != "user" or parsed.get("variant", "user") not in ("user", "answer"):
            return ""
        excerpt = provenance.norm(parsed.get("excerpt") or "")
        if not excerpt or not _one_segment(excerpt):
            return ""
        result = provenance.resolve(source, {"home": claude_dir(), "want_text": True})
        if not (result.get("ok") and result.get("origin") == "user" and not result.get("weak")):
            return ""
        text = next((n.get("text") for n in result.get("chain") or [] if n.get("kind") == "user"), None)
        return sentences_around(provenance.norm(text), excerpt) if isinstance(text, str) else ""
    except Exception:  # noqa: BLE001 - an unresolvable source has no words
        return ""


def context_words_ok(source, goal: dict, kind: str) -> bool:
    """The whole sentence around the user's quote passes the check for kind, not only the quoted fragment (a
    faithful partial quote of "please do not defer leads until friday" is refused)."""
    if not excerpt_words_ok(source, goal, kind):
        return False
    context = user_context(source)
    return bool(context) and (deferral_words_ok if kind == "defer" else retire_words_ok)(context, goal)


# ------------------------------------------------------------------ goals file: read and validate

def _check_deferral(d, where: str) -> None:
    if not isinstance(d, dict) or d.get("by") not in DEFER_BY:
        raise ValueError(f"{where}: deferral must be an object with by user, ask or ticket")
    by = d["by"]
    ref = d.get("ref")
    if by == "ask" and not (isinstance(ref, str) and ASK_ID_RE.match(ref)):
        raise ValueError(f"{where}: an ask deferral needs ref = an ask id (w + 11 hex digits)")
    if by == "ticket" and not (isinstance(ref, str) and ticket_key(ref)):
        raise ValueError(f"{where}: a ticket deferral needs ref like goodqa#123")
    if by == "user" and ref is not None:
        raise ValueError(f"{where}: a user deferral has a source, not a ref")
    until = d.get("until")
    if until is not None and not (isinstance(until, str) and parse_ts(until)):
        raise ValueError(f"{where}: deferral.until must be an ISO time")
    src = d.get("source")
    if src is not None and (not isinstance(src, str) or len(src) > 4000):
        raise ValueError(f"{where}: deferral.source must be text")
    if by == "user" and not isinstance(src, str):
        raise ValueError(f"{where}: a user deferral needs its user: or answer: source")
    ren = d.get("renewal", 0)
    if isinstance(ren, bool) or not isinstance(ren, int) or not 0 <= ren <= 1000:
        raise ValueError(f"{where}: deferral.renewal must be a small integer")


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
    if g.get("deferral") is not None:
        _check_deferral(g["deferral"], where)
    wc = g.get("wait_count", 0)
    if isinstance(wc, bool) or not isinstance(wc, int) or not 0 <= wc <= 1000:
        raise ValueError(f"{where}: wait_count must be a small integer")
    bound = g.get("bound")
    if bound is not None and (not isinstance(bound, list) or len(bound) > 20
                              or not all(isinstance(a, str) and AGENT_RE.match(a) for a in bound)):
        raise ValueError(f"{where}: bound must be a list of full agent ids")
    ret = g.get("retire")
    if ret is not None and (not isinstance(ret, dict) or not isinstance(ret.get("source"), str)
                            or len(ret["source"]) > 4000):
        raise ValueError(f"{where}: retire must be {{source}}")
    ev = g.get("done_evidence")
    if ev is not None:
        rows = [ev] if isinstance(ev, dict) else ev
        if not isinstance(rows, list) or len(rows) > 10:
            raise ValueError(f"{where}: done_evidence must be a list of {{kind, ref, session}}")
        for r in rows:
            if not isinstance(r, dict) or r.get("kind") not in EVIDENCE_KINDS or not isinstance(r.get("ref"), str) \
                    or not REF_RE.match(r["ref"]) or not isinstance(r.get("session", ""), str) \
                    or (r.get("session") and not SESSION_RE.match(r["session"])):
                raise ValueError(f"{where}: done_evidence rows need kind deploy|really_tested, a ref and a session id")
    repos = g.get("repos")
    if repos is not None and (not isinstance(repos, list) or len(repos) > 10
                              or not all(isinstance(p, str) and 0 < len(p) < 1024 and "\x00" not in p for p in repos)):
        raise ValueError(f"{where}: repos must be a list of paths")
    if g.get("dashboard") is not None and not isinstance(g["dashboard"], dict):
        raise ValueError(f"{where}: dashboard must be an object")
    tgt = g.get("target")
    if tgt is not None and (not isinstance(tgt, dict) or not isinstance(tgt.get("text"), str)
                            or not 0 < len(tgt["text"]) <= 300 or not isinstance(tgt.get("source"), str)
                            or not 0 < len(tgt["source"]) <= 2000):
        raise ValueError(f"{where}: target must be {{text, source}}")
    aliases = g.get("aliases")
    if aliases is not None and (not isinstance(aliases, list) or len(aliases) > MAX_ALIASES
                                or not all(isinstance(a, str) and ALIAS_RE.match(a) for a in aliases)):
        raise ValueError(f"{where}: aliases must be up to {MAX_ALIASES} short lower-case words")
    attached = g.get("evidence")
    if attached is not None:
        if not isinstance(attached, list) or len(attached) > MAX_ATTACHED:
            raise ValueError(f"{where}: evidence must be a list of up to {MAX_ATTACHED} rows")
        for r in attached:
            if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not ASK_ID_RE.match(r["id"]) \
                    or not isinstance(r.get("session"), str) or not SESSION_RE.match(r["session"]) \
                    or not isinstance(r.get("wal"), str) or not WAL_NAME_RE.match(r["wal"]) \
                    or r.get("kind") not in ATTACH_KINDS:
                raise ValueError(f"{where}: evidence rows need id (w + 11 hex), session, wal and kind "
                                 f"{'|'.join(ATTACH_KINDS)}")
            pinned = [k for k in ("row_sha", "row_verdict", "row_at") if k in r]
            if pinned and (len(pinned) != 3 or not isinstance(r["row_sha"], str) or not SHA256_RE.match(r["row_sha"])
                           or r["row_verdict"] not in PIN_VERDICTS or not isinstance(r["row_at"], str)
                           or len(r["row_at"]) > 64):
                raise ValueError(f"{where}: an evidence pin needs row_sha (sha256 hex), row_verdict "
                                 f"{'|'.join(PIN_VERDICTS)} and row_at (a timestamp string)")
    return g


def validate_goals(data) -> list:
    if not isinstance(data, list):
        raise ValueError("goals must be a JSON list")
    if len(data) > MAX_GOALS:
        raise ValueError(f"more than {MAX_GOALS} goals")
    seen = set()
    for i, g in enumerate(data):
        _check_goal(g, i)
        if g["id"] in seen:
            raise ValueError(f"goal id {g['id']} appears twice")
        seen.add(g["id"])
    return data


def validate_doc(data) -> dict:
    """{"mission_session", "goals"}; a bare list (the first format) has no mission session."""
    if isinstance(data, list):
        return {"mission_session": "", "goals": validate_goals(data)}
    if not isinstance(data, dict):
        raise ValueError("goals file must be an object {mission_session, goals}")
    session = data.get("mission_session") or ""
    if not isinstance(session, str) or (session and not SESSION_RE.match(session)):
        raise ValueError("mission_session must be a session id")
    return {"mission_session": session.lower(), "goals": validate_goals(data.get("goals", []))}


def _safe_dir(path: Path) -> None:
    if os.path.islink(path):
        raise ValueError(f"{path.name} directory is a symlink")


def _read_goals_bytes(home: Path):
    """Raw bytes of the goals file, None when absent; ValueError when it is not a small regular file."""
    path = goals_path(home)
    _safe_dir(path.parent)
    if not os.path.lexists(path):
        return None
    if os.path.islink(path):
        raise ValueError("goals file is a symlink")
    try:
        return safe_input.read_bounded(path, MAX_GOALS_BYTES)
    except safe_input.InputRejected as rejected:
        raise ValueError(rejected.message) from None


def load_goals(home: Path) -> dict:
    """{"state": "absent"} | {"state": "ok", "goals", "mission_session", "sha"} | {"state": "error", "error"}."""
    try:
        raw = _read_goals_bytes(home)
        if raw is None:
            return {"state": "absent", "goals": [], "mission_session": ""}
        doc = validate_doc(safe_input.safe_json_loads(raw, max_depth=MAX_DEPTH, max_bytes=MAX_GOALS_BYTES))
        return {"state": "ok", "goals": doc["goals"], "mission_session": doc["mission_session"], "sha": sha(raw)}
    except (ValueError, UnicodeError, RecursionError) as error:
        return {"state": "error", "goals": [], "mission_session": "", "error": clean(str(error), 200)}


# ------------------------------------------------------------------ audit chain (segmented)

def _file_sha(home: Path) -> str:
    raw = _read_goals_bytes(home)
    return "absent" if raw is None else sha(raw)


def audit_segments(home: Path) -> list:
    """Rotated audit segments, oldest first, then the current file."""
    folder = state_root(home)
    olds = sorted(p for p in folder.glob("mission-goals-audit.[0-9]*.jsonl")
                  if re.fullmatch(r"mission-goals-audit\.\d{6}\.jsonl", p.name))
    return olds + ([audit_path(home)] if os.path.lexists(audit_path(home)) else [])


def _last_row(home: Path):
    try:
        line = _last_line(audit_path(home))
        rec = json.loads(line) if line else None
        return rec if isinstance(rec, dict) else None
    except (ValueError, OSError, safe_input.InputRejected):
        return None


def verify_audit(home: Path) -> dict:
    """{"ok": bool, "problem": str, "rows": n}: every row's prev is the sha256 of the row before it (across rotated
    segments), the head file names the last row, and the goals file is the one the last row wrote."""
    try:
        current = _file_sha(home)
    except ValueError as error:
        return {"ok": False, "problem": f"goals file unreadable: {clean(str(error), 120)}", "rows": 0}
    segments = audit_segments(home)
    if not segments:
        if current == "absent":
            return {"ok": True, "problem": "", "rows": 0}
        return {"ok": False, "problem": "goals file changed outside mission_coverage.py: it has no audit trail", "rows": 0}
    prev, last, n = GENESIS, None, 0
    try:
        for seg in segments:
            if os.path.islink(seg):
                return {"ok": False, "problem": "an audit segment is a symlink", "rows": n}
            for number, line in safe_input.iter_jsonl_lines(seg, max_line=1 << 20,
                                                            max_total_bytes=MAX_AUDIT_BYTES + (1 << 20)):
                if line is None:
                    return {"ok": False, "problem": f"audit row {number} is oversized", "rows": n}
                if not line.strip():
                    continue
                rec = safe_input.safe_json_loads(line, max_depth=MAX_DEPTH)
                if not isinstance(rec, dict) or rec.get("prev") != prev:
                    return {"ok": False, "problem": f"audit chain broken at row {n + 1} (edited, removed or reordered)",
                            "rows": n}
                prev, last, n = sha(line + b"\n"), rec, n + 1
    except (safe_input.InputRejected, ValueError) as error:
        return {"ok": False, "problem": f"audit trail unreadable: {clean(str(error), 120)}", "rows": n}
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
            gone = sorted(i for i in set(last.get("ids") or []) - now_ids if isinstance(i, str) and ID_RE.match(i))
            removed = f"; goals no longer in the file: {', '.join(gone[:10])}" if gone else ""
        return {"ok": False, "problem": "goals file changed outside mission_coverage.py since the last audit row"
                                        + removed, "rows": n}
    return {"ok": True, "problem": "", "rows": n}


def _actor(stamp=None) -> dict:
    return {"session": (os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or "")[:80],
            "agent": (os.environ.get("AH_AGENT_ID") or os.environ.get("CLAUDE_AGENT_ID") or "")[:80],
            "pid": os.getpid(), "main_stamp": bool(stamp),
            "main_session": str((stamp or {}).get("session") or "")[:80]}


@contextlib.contextmanager
def _locked(home: Path, shared: bool = False):
    import fcntl  # noqa: PLC0415 - POSIX only, like the rest of the harness state
    state = state_root(home)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(state / "mission-goals.lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def read_consistent(home: Path) -> dict:
    """Goals plus audit verdict under a shared lock, so a concurrent write is never read half-done as tampered:
    {"state": absent|ok|error|tampered, "goals", "mission_session", "error"}."""
    if not os.path.lexists(goals_path(home)) and not audit_segments(home):
        return {"state": "absent", "goals": [], "mission_session": ""}
    with _locked(home, shared=True):
        loaded = load_goals(home)
        if loaded["state"] == "absent" and not audit_segments(home):
            return loaded
        audit = verify_audit(home)
        last = _last_row(home) or {}
    sealed = str(last.get("session") or "")
    if loaded["state"] == "error":
        return dict(loaded, error=f"goals file unreadable: {loaded['error']}", mission_session=sealed)
    if not audit["ok"]:
        # the session comes from the chain, never from a file that may have been edited to escape the gate
        return {"state": "tampered", "goals": [], "mission_session": sealed or loaded.get("mission_session") or "",
                "error": audit["problem"]}
    return loaded


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_dir(path.parent)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
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


def _append_audit(home: Path, line: bytes) -> None:
    path = audit_path(home)
    if os.path.lexists(path) and os.lstat(path).st_size + len(line) > MAX_AUDIT_BYTES:
        olds = [p for p in audit_segments(home) if p != path]
        index = 1 + max([int(p.name.split(".")[1]) for p in olds] or [0])
        os.rename(path, path.with_name(f"mission-goals-audit.{index:06d}.jsonl"))
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def _mutate(home: Path, action: str, goal_id: str, change, detail: dict, allow_broken: bool = False,
            stamp=None) -> dict:
    """Load, apply change(doc) -> doc ({mission_session, goals}), write goals.json and one chained audit row, under
    one exclusive lock. Returns the new doc."""
    with _locked(home):
        audit = verify_audit(home)
        if not audit["ok"] and not allow_broken:
            raise MissionError(f"{audit['problem']}. Inspect it with `{SCRIPT} verify`, restore the file, or have main "
                               f"record the current file with `{SCRIPT} reseal --reason <what changed and why>`")
        state = load_goals(home)
        if state["state"] == "error":
            raise MissionError(f"goals file unreadable ({state['error']}); fix or restore it before writing")
        prev_line = _last_line(audit_path(home))
        before = state.get("sha") or "absent"
        doc = change({"mission_session": state.get("mission_session") or "",
                      "goals": [dict(g) for g in state["goals"]]})
        doc = validate_doc(doc)
        data = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()
        if len(data) > MAX_GOALS_BYTES:
            raise MissionError("goals file would exceed 1 MiB")
        _atomic(goals_path(home), data)
        row = {"at": iso(time.time()), "action": action, "goal": goal_id, "detail": detail, "before_sha": before,
               "after_sha": sha(data), "ids": [g["id"] for g in doc["goals"]], "session": doc["mission_session"],
               "actor": _actor(stamp), "prev": sha(prev_line) if prev_line else GENESIS}
        line = (json.dumps(row, sort_keys=True) + "\n").encode()
        _append_audit(home, line)
        _atomic(head_path(home), (sha(line) + "\n").encode())
        return doc


def _find(goals: list, goal_id: str) -> dict:
    for g in goals:
        if g["id"] == goal_id:
            return g
    raise MissionError(f"no goal {clean(goal_id)!r}; list them with `{SCRIPT} report`")


# ------------------------------------------------------------------ main-only proof and change alerts

_PROOF: dict = {}  # the stamp claim_main took for this process's own argv: {"cmd", "stamp"}; used at most once


def argv_key(argv) -> str:
    """Digest of the exact argument list after the script (subcommand first; `--flag=value` read as `--flag value`).
    main's PreToolUse hook and the command it runs compute it from the same words (M2, delta red-team of PR 179)."""
    words = []
    for a in argv:
        a = str(a)
        words.extend(a.split("=", 1) if a.startswith("--") and "=" in a else [a])
    return hashlib.sha256(json.dumps(words, separators=(",", ":")).encode("utf-8", "replace")).hexdigest()


def claim_main(argv, home: Path) -> None:
    """Take (consume) the one-shot stamp main's hook wrote for exactly this argument list, before anything parses or
    validates it: a command that then fails, prints --help or exits on an argparse error leaves no stamp behind."""
    _PROOF.clear()
    argv = [str(a) for a in argv or []]
    if not argv or argv[0] not in MAIN_ONLY:
        return
    import caller_identity  # noqa: PLC0415
    stamp = caller_identity.take_stamp(STAMP_PURPOSE, [argv[0], argv_key(argv)], home=home, bound=True,
                                       ttl=MAIN_STAMP_TTL_SECONDS)
    if stamp is not None:
        _PROOF.update(cmd=argv[0], stamp=stamp)


def require_main(home: Path, cmd: str, handover: bool = False) -> dict:
    """The stamp claim_main took for this command (single use, bound to main's still-running call, at most 60 s old) from the main session that
    owns the mission; MissionError otherwise. Once goals.json names a mission session, another top-level session
    (another main, or a sub-agent's own `claude -p`) is refused even with a stamp of its own (M1). handover=True
    (set-session only) returns a foreign stamp so set_session can apply its hand-over rule."""
    stamp = _PROOF.get("stamp") if _PROOF.get("cmd") == cmd else None
    _PROOF.clear()
    if stamp is None:
        raise MissionError(f"`{cmd}` is main-only: only the main agent may run it, and main's PreToolUse hook saw no "
                           f"main command `{SCRIPT} {cmd} ...` with exactly these arguments in this still-running call (run "
                           "it as a plain foreground command, not inside echo, a here-document, bash -c or a script). A sub-agent "
                           "asks main to run it.")
    mission = mission_session_of(home)
    caller = str(stamp.get("session") or "").lower()
    if mission and caller != mission and not handover:
        raise MissionError(f"`{cmd}` is refused: the mission belongs to main session {mission}, and this is another "
                           f"top-level session ({clean(caller, 40) or 'unknown'}). Ask that main to run it; to move the "
                           f"mission here, that main runs `{SCRIPT} set-session --session <this session>`, or this "
                           f"main cites the user's words in this session: `{SCRIPT} set-session --user-source \"user:...\"`")
    return stamp


def _ring(home: Path, key: str, event: str, severity: str, message: str, detail: dict,
          source: str = "mission-coverage") -> None:
    """One ops-ring event; a clear only when the key's latest event from this source is a raise. Best effort."""
    try:
        import ops_watch  # noqa: PLC0415
        ring = ops_watch.ring_path(home)
        if event == "clear":
            latest = None
            for e in ops_watch.read_ring(ring):
                if e.get("source") == source and e.get("key") == key:
                    latest = e
            if latest is None or latest.get("event") != "raise":
                return
        ops_watch.emit({"host": ops_watch.default_host(), "source": source, "event": event, "severity": severity,
                        "key": key, "message": clean(message, 300), "detail": detail}, path=ring)
    except Exception:  # noqa: BLE001 - best effort; the audit row stands
        pass


def changed_alert(home: Path, message: str, detail: dict) -> None:
    _ring(home, "mission:goals:changed", "raise", "high", message, dict(detail, stop_block=False))


# ------------------------------------------------------------------ write commands

def add_goal(home: Path, goal_id: str, title: str, ticket: str = "", priority: int = 3) -> dict:
    """Open to every caller: a new goal can only add work to cover."""
    if not ID_RE.match(goal_id or ""):
        raise MissionError("goal id: lower-case letters, digits, - and _, up to 64 characters")
    if ticket and not ticket_key(ticket):
        raise MissionError("ticket must look like goodqa#123 or Project#123")

    def change(doc):
        if any(g["id"] == goal_id for g in doc["goals"]):
            raise MissionError(f"goal {goal_id} already exists; change it with `{SCRIPT} set`")
        doc["goals"].append({"id": goal_id, "title": (title or goal_id)[:300], "priority": int(priority),
                             "ticket": (ticket_key(ticket) or "") if ticket else "", "status": "active"})
        return doc
    return _mutate(home, "add", goal_id, change, {"title": clean(title, 120), "ticket": ticket_key(ticket) or "",
                                                  "priority": priority})


def set_goal(home: Path, goal_id: str, *, title=None, ticket=None, priority=None, status=None, repos=None,
             clear_deferral: bool = False, target=None, target_source=None, aliases=None, verify_source=None) -> dict:
    """Title, priority, clearing a deferral and setting a goal active again are open (they never hide work);
    a ticket, repos, target or aliases change is main-only and alerts. A target needs a user: or answer: source that
    resolves to the user's own words (goodqa#15754: a target is the user's, never an agent's)."""
    main_fields = (ticket, repos, target, target_source, aliases)
    stamp = require_main(home, "set") if any(v is not None for v in main_fields) else None
    if (target is None) != (target_source is None):
        raise MissionError("--target and --target-source go together: the target is the user's, cite their words")
    if target is not None:
        if not isinstance(target, str) or not 0 < len(target.strip()) <= 300:
            raise MissionError("--target: 1 to 300 characters")
        if not (verify_source or verify_user_source)(target_source):
            raise MissionError("--target-source must be a user: or answer: source that resolves to the user's own "
                               "words (ah user-msg prints it); an agent cannot set or move a target")
    if aliases is not None:
        aliases = [a.strip().lower() for a in aliases if a and a.strip()]
        if len(aliases) > MAX_ALIASES or not all(ALIAS_RE.match(a) for a in aliases):
            raise MissionError(f"--alias: up to {MAX_ALIASES} short lower-case words (2-40 characters)")
    if status == "done":
        raise MissionError(f"a goal is marked done only with evidence: `{SCRIPT} done --goal {goal_id} --deploy <deploy "
                           f"WAL id> --live-test <REALLY_TESTED id>`")
    if status in ("deferred", "retired", "imported"):
        raise MissionError(f"status {status} has its own command (defer, retire; imported comes from import-initiatives)")
    if status not in (None, "active"):
        raise MissionError("status: set only accepts active")
    if ticket is not None and ticket and not ticket_key(ticket):
        raise MissionError("ticket must look like goodqa#123 or Project#123")
    detail ={k: v for k, v in (("title", clean(title, 120) if title is not None else None),
                                ("ticket", (ticket_key(ticket) or "") if ticket is not None else None),
                                ("priority", priority), ("status", status), ("repos", repos),
                                ("clear_deferral", clear_deferral or None),
                                ("target", clean(target, 120) if target is not None else None),
                                ("aliases", aliases)) if v is not None}
    old = {}

    def change(doc):
        g = _find(doc["goals"], goal_id)
        old["ticket"] = g.get("ticket") or ""
        if title is not None:
            g["title"] = title[:300]
        if ticket is not None:
            g["ticket"] = ticket_key(ticket) or ""
        if priority is not None:
            g["priority"] = int(priority)
        if repos is not None:
            g["repos"] = list(repos)
        if target is not None:
            old["target"] = (g.get("target") or {}).get("text") or ""
            g["target"] = {"text": target.strip()[:300], "source": target_source.strip()[:2000]}
        if aliases is not None:
            g["aliases"] = aliases
        if status == "active":
            if g.get("status") == "imported":
                raise MissionError(f"an imported goal is activated by main: `{SCRIPT} activate --goal {goal_id}`")
            g["status"] = "active"
            g.pop("done_evidence", None)
            g.pop("retire", None)
        if clear_deferral or status == "active":
            g.pop("deferral", None)
        return doc
    doc = _mutate(home, "set", goal_id, change, detail, stamp=stamp)
    if ticket is not None and (ticket_key(ticket) or "") != old.get("ticket"):
        changed_alert(home, f"mission goal {goal_id} ticket changed {old.get('ticket') or 'none'} -> "
                            f"{ticket_key(ticket) or 'none'} by main", {"goal": goal_id, "old": old.get("ticket"),
                                                                         "new": ticket_key(ticket) or ""})
    elif repos is not None:
        changed_alert(home, f"mission goal {goal_id} repos changed by main", {"goal": goal_id})
    if target is not None:
        changed_alert(home, f"mission goal {goal_id} target set by main from the user's words",
                      {"goal": goal_id, "old": clean(old.get("target"), 120), "new": clean(target, 120)})
    return doc


def find_wal_row(home: Path, session: str, wid: str, wal_name=None):
    """(wal file name, record) of WAL entry `wid` in `session`'s WAL folder, or (None, None). Reads lines that hold the
    id only; no time window (goodqa#15754)."""
    if not SESSION_RE.match(session or "") or not ASK_ID_RE.match(wid or ""):
        return None, None
    folder = claude_dir() / "wals" / session
    if not folder.is_dir() or folder.is_symlink():
        return None, None
    names = [wal_name] if wal_name else sorted(p.name for p in folder.glob("*.jsonl"))
    needle = wid.encode()
    for name in names:
        if not WAL_NAME_RE.match(name or ""):
            continue
        path = folder / name
        if path.is_symlink() or not path.is_file():
            continue
        try:
            for _, raw in safe_input.iter_jsonl_lines(path, 1 << 20, max_total_bytes=256 << 20, max_seconds=10):
                if raw is None or needle not in raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("id") == wid:
                    return name, rec
        except (OSError, safe_input.InputRejected):
            continue
    return None, None


RT_NOTE = re.compile(r"^\s*REALLY_TESTED\s+[A-Za-z0-9._-]+")


def _row_names_goal(home: Path, session: str, wal_name: str, rec: dict, goal: dict) -> bool:
    """The evidence row names the goal (goal field, or the goal's ticket in its ticket field or note), or its WAL
    names the goal's ticket or id anywhere: an owner attaches only evidence from its own stream."""
    if rec.get("goal") == goal["id"]:
        return True
    key = ticket_key(goal.get("ticket"))
    if key and (same_ticket(rec.get("ticket"), key) or any(same_ticket(t, key) for t in
                                                           re.findall(r"[A-Za-z][A-Za-z0-9-]*\s*#\s*\d+|#\d+",
                                                                      str(rec.get("note") or "")))):
        return True
    try:
        text = safe_input.read_bounded(claude_dir() / "wals" / session / wal_name, 64 << 20).decode("utf-8", "replace")
    except (OSError, safe_input.InputRejected):
        return False
    if re.search(r'"goal":\s*"' + re.escape(goal["id"]) + '"', text):
        return True
    if key:
        slug, number = key.split("#")
        return bool(re.search(r"(?i)\b" + re.escape(slug) + r"\s*#\s*" + number + r"\b", text))
    return False


def attach_evidence(home: Path, goal_id: str, wid: str, *, kind: str = "", session=None, remove: bool = False) -> dict:
    """Attach WAL entry `wid` (a REALLY_TESTED row or a deploy event) to a goal, so `ah goals` shows it whatever its age.
    Open to an owner whose row or WAL names the goal; main (stamp) may attach any row and --remove one."""
    stamp = _PROOF.get("stamp") if _PROOF.get("cmd") == "attach" else None
    _PROOF.clear()
    by = "main" if stamp is not None else "owner"
    mission = mission_session_of(home)
    if stamp is not None and mission and str(stamp.get("session") or "").lower() != mission:
        raise MissionError(f"attach is refused: the mission belongs to main session {mission}")
    if remove and stamp is None:
        raise MissionError("attach --remove is main-only (main's PreToolUse hook saw no such command)")
    session = (session or mission or main_session(home) or "").lower()
    if not SESSION_RE.match(session):
        raise MissionError("attach needs --session (the session whose WALs hold the row)")
    if not ASK_ID_RE.match(wid or ""):
        raise MissionError("--evidence takes a WAL entry id (w + 11 hex digits)")
    if remove:
        def drop(doc):
            g = _find(doc["goals"], goal_id)
            g["evidence"] = [r for r in g.get("evidence") or [] if r.get("id") != wid]
            return doc
        return _mutate(home, "detach", goal_id, drop, {"id": wid}, stamp=stamp)
    wal_name, rec = find_wal_row(home, session, wid)
    if rec is None:
        raise MissionError(f"no WAL entry {wid} in session {session}: attach only rows that exist")
    note = str(rec.get("note") or "")
    import goals_view  # noqa: PLC0415 - one deploy-record rule, shared with ah goals
    if goals_view.is_deploy_record(rec):
        found_kind = "deploy"
    elif RT_NOTE.match(note):
        found_kind = "live_test" if rec.get("live") is True else "test"
    else:
        raise MissionError(f"{wid} is a {clean(rec.get('event'), 20)} row: only REALLY_TESTED rows and deploy records "
                           "(event deploy/release/install or a DEPLOYED/INSTALLED/RELEASED note naming a sha or "
                           "version) are evidence")
    kind = kind or found_kind
    pin_verdict = goals_view.verdict(rec) or ("DEPLOY" if found_kind == "deploy" else "UNSTATED")
    if kind not in ATTACH_KINDS or (found_kind == "deploy") != (kind == "deploy"):
        raise MissionError(f"--kind {clean(kind, 20)} does not fit a {found_kind} row")
    loaded = load_goals(home)
    goal = next((g for g in loaded.get("goals") or [] if g["id"] == goal_id), None)
    if goal is None:
        raise MissionError(f"no goal {clean(goal_id)!r}; list them with `{SCRIPT} report`")
    if stamp is None and not _row_names_goal(home, session, wal_name, rec, goal):
        raise MissionError(f"{wid} comes from {wal_name}, which never names goal {goal_id} or its ticket "
                           f"{goal.get('ticket') or '(none)'}; tag your row with `--goal {goal_id}` or ask main")

    def change(doc):
        g = _find(doc["goals"], goal_id)
        if stamp is None and any(r.get("id") == wid and r.get("by") == "main" for r in g.get("evidence") or []):
            # spec rev 3 NEG-4 (red-team H3): a re-attach would rewrite main's row (by, kind); only main changes it
            raise MissionError(f"{wid} is already attached to {goal_id} by main; only main can change or remove it")
        if stamp is None and any(r.get("id") == wid and r.get("row_sha") and not row_matches(r["row_sha"], rec)
                                 for r in g.get("evidence") or []):
            # PR 226 review H1 (probe_b3): an owner who rewrote its own attached row must not re-pin it; the changed
            # row keeps scoring by its pinned verdict until main reads it and re-attaches (or removes) it
            raise MissionError(f"{wid} changed since it was attached to {goal_id}; only main can re-attach it "
                               "(ask main to read the row and re-attach or remove it)")
        rows = [r for r in g.get("evidence") or [] if r.get("id") != wid]
        # F2: pin the row as attach saw it; ah goals marks it TAMPERED when the WAL row changes later (a re-attach
        # re-pins: main's re-attach is how a legacy, unpinned entry gets its pin)
        rows.append({"id": wid, "session": session, "wal": wal_name, "kind": kind, "at": iso(time.time()), "by": by,
                     "row_sha": row_digest(rec), "row_verdict": pin_verdict, "row_at": str(rec.get("at") or "")[:64]})
        if len(rows) > MAX_ATTACHED:
            raise MissionError(f"goal {goal_id} already has {MAX_ATTACHED} evidence rows; main removes stale ones")
        g["evidence"] = rows
        return doc
    return _mutate(home, "attach", goal_id, change, {"id": wid, "kind": kind, "wal": wal_name, "by": by}, stamp=stamp)


def ask_states(home: Path, session: str) -> dict:
    """{ask id: {"state": open|resolved, "note": text}} from the session's main WAL. Read through
    safe_input.open_regular_file (no FIFO, device or symlink swap can hang or redirect the read)."""
    if not session or not SESSION_RE.match(session):
        return {}
    import ah  # noqa: PLC0415
    path = ah.session_dir(home, session) / "main.jsonl"
    out = {}
    try:
        fd = safe_input.open_regular_file(path, max_bytes=512 << 20)
    except safe_input.InputRejected:
        return {}
    with os.fdopen(fd, "rb") as handle:
        for raw in handle:
            if b'"ask' not in raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("event") == "ask" and ASK_ID_RE.match(str(rec.get("id") or "")):
                text = " ".join(str(rec.get(k) or "") for k in ("note", "question", "ref", "ticket"))
                out.setdefault(rec["id"], {"state": "open", "note": text[:600]})
            elif rec.get("event") == "ask_resolved" and ASK_ID_RE.match(str(rec.get("ref") or "")):
                out.setdefault(rec["ref"], {"note": ""})["state"] = "resolved"
    return out


def _ask(asks, ref):
    v = (asks or {}).get(str(ref or ""))
    if isinstance(v, dict):
        return str(v.get("state") or ""), str(v.get("note") or "")
    return (str(v) if v else ""), ""


def ticket_state(ref, timeout: float = 10.0):
    """'open', 'closed' or 'missing' from GoodQA (ah's adapter, quick mode); None when it cannot be told in time."""
    import threading  # noqa: PLC0415
    box = {}

    def work():
        try:
            import ah  # noqa: PLC0415
            adapter, mod = ah.load_adapter(quick=True)
            project, number = ah.ticket_ref(ref, "goodqa")
            t = ah.ticket_issue(adapter, mod, project, number)
            box["state"] = "closed" if getattr(t, "closed", False) else "open"
        except Exception as error:  # noqa: BLE001 - unknown is never "open"
            box["state"] = "missing" if getattr(error, "code", "") == "not_found" else None
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(timeout)
    return box.get("state")


def mission_session_of(home: Path) -> str:
    return read_consistent(home).get("mission_session") or ""


def defer_goal(home: Path, goal_id: str, *, ask=None, ticket=None, user_source=None, until=None, session=None,
               now=None) -> dict:
    """A wait on an open ask that names the goal (open to every caller: the ask is main's own WAL entry), a wait on
    another open ticket (main-only: it parks a goal with no owner for up to 7 days on a relation nothing else
    records, and a ticket that merely mentions the goal is something any agent can create), or the user's own
    deferral (main-only). Every one raises `mission:goals:changed`."""
    stamp = require_main(home, "defer") if (user_source or ticket) else None
    now = time.time() if now is None else now
    given = [x for x in (ask, ticket, user_source) if x]
    if len(given) != 1:
        raise MissionError("name exactly one of --ask ASKID, --ticket TICKET or --user-source SOURCE")
    until_ts = parse_ts(until) if until else 0.0
    if until and not until_ts:
        raise MissionError("--until must be an ISO time such as 2026-11-12T09:00Z")
    if until and until_ts <= now:
        raise MissionError("--until is in the past")
    loaded = load_goals(home)
    current = next((g for g in loaded.get("goals") or [] if g["id"] == goal_id), None)
    if current is None:
        raise MissionError(f"no goal {clean(goal_id)!r}; list them with `{SCRIPT} report`")
    session = loaded.get("mission_session") or session or main_session(home)
    if ask or ticket:
        if not until:
            raise MissionError("a wait on an ask or ticket needs --until (at most 7 days ahead)")
        if until_ts - now > WAIT_MAX_S:
            raise MissionError("--until is more than 7 days ahead; renew the wait instead of parking the goal")
        if int(current.get("wait_count") or 0) >= MAX_RENEWALS:
            raise MissionError(f"goal {goal_id} has waited {MAX_RENEWALS} times in a row without the user's word; it "
                               "cannot renew again. Start an owner, or record the user's own deferral (--user-source)")
    if ask:
        if not ASK_ID_RE.match(ask):
            raise MissionError("--ask takes an ask id from main's WAL (w + 11 hex digits)")
        state, note = _ask(ask_states(home, session), ask)
        if state != "open":
            raise MissionError(f"ask {ask} is not open in main's WAL (answered or unknown); a goal cannot wait on it")
        if not names_goal(note, current):
            raise MissionError(f"ask {ask} does not name goal {goal_id} or its ticket; a goal waits only on an ask "
                               "about it")
        deferral = {"by": "ask", "ref": ask, "until": iso(until_ts)}
    elif ticket:
        if not ticket_key(ticket):
            raise MissionError("--ticket must look like goodqa#123 or Project#123")
        if same_ticket(ticket, current.get("ticket")):
            raise MissionError("a goal cannot wait on its own ticket; name the ticket it is blocked by")
        state = ticket_state(ticket_key(ticket))
        if state != "open":
            raise MissionError(f"ticket {ticket_key(ticket)} is {state or 'unreachable'} in GoodQA; a goal waits only "
                               "on an open ticket")
        deferral = {"by": "ticket", "ref": ticket_key(ticket), "until": iso(until_ts)}
    else:
        if not verify_user_source(user_source):
            raise MissionError("--user-source must be a user: or answer: source that resolves to the user's own words "
                               "(`ah user-msg --recent N` prints it); agent decisions, inferred:, pasted: and tickets "
                               "cannot defer a mission goal")
        if not context_words_ok(user_source, current, "defer"):
            raise MissionError(f"the quote must be one segment (no '...') and the user's whole sentence must say defer, "
                               f"park, pause, postpone or shelve right next to goal {goal_id} (or #its ticket), or "
                               "'<goal> can wait' / 'put <goal> on hold', with no condition, refusal or negation")
        deferral = {"by": "user", "source": user_source, "until": iso(until_ts) if until else None}

    def change(doc):
        g = _find(doc["goals"], goal_id)
        if deferral["by"] == "user":
            g["wait_count"] = 0
            g["status"] = "deferred"
        else:
            count = int(g.get("wait_count") or 0) + 1
            if count > MAX_RENEWALS:
                raise MissionError(f"goal {goal_id} cannot renew its wait a third time without the user's word")
            g["wait_count"] = count
            deferral["renewal"] = count
            if g.get("status") == "deferred":
                g["status"] = "active"
        g["deferral"] = deferral
        return doc
    detail = {k: v for k, v in deferral.items() if k != "source"}
    detail["words"] = clean(source_excerpt(user_source), 200) if user_source else None
    doc = _mutate(home, "defer", goal_id, change, detail, stamp=stamp)
    if user_source:
        changed_alert(home, f"mission goal {goal_id} deferred by main on the user's words", {"goal": goal_id})
    else:
        changed_alert(home, f"mission goal {goal_id} now waits on {deferral['by']} {deferral['ref']} until "
                            f"{deferral['until']} (wait {deferral.get('renewal')} of {MAX_RENEWALS})"
                            + (" by main" if stamp else ""), {"goal": goal_id, "by": deferral["by"],
                                                              "ref": deferral["ref"], "until": deferral["until"]})
    return doc


def done_goal(home: Path, goal_id: str, *, deploy: str, live_test: str, session=None) -> dict:
    loaded = load_goals(home)
    mission = loaded.get("mission_session") or ""
    if mission and session and session.lower() != mission:
        raise MissionError(f"done evidence must come from the mission session's WALs ({mission}); --session points "
                           "elsewhere")
    session = mission or session or main_session(home)
    if not session:
        raise MissionError("no session: pass --session (the session whose WALs hold the evidence)")
    for ref in (deploy, live_test):
        if not isinstance(ref, str) or not REF_RE.match(ref):
            raise MissionError("--deploy and --live-test take WAL ids")
    evidence = [{"kind": "deploy", "ref": deploy, "session": session},
                {"kind": "really_tested", "ref": live_test, "session": session}]
    g = next((x for x in loaded.get("goals") or [] if x["id"] == goal_id), None)
    if g is None:
        raise MissionError(f"no goal {clean(goal_id)!r}")
    why = done_evidence_problem(home, dict(g, done_evidence=evidence))
    if why:
        raise MissionError(f"done refused: {clean(why, 200)}. Done means deployed to live and tested live")

    def change(doc):
        x = _find(doc["goals"], goal_id)
        x["status"], x["done_evidence"] = "done", evidence
        x.pop("deferral", None)
        x["wait_count"] = 0
        return doc
    return _mutate(home, "done", goal_id, change, {"deploy": deploy, "live_test": live_test, "session": session})


def activate_goal(home: Path, goal_id: str) -> dict:
    """Main-only: an imported goal becomes active (enforced)."""
    stamp = require_main(home, "activate")

    def change(doc):
        g = _find(doc["goals"], goal_id)
        if g.get("status") != "imported":
            raise MissionError(f"goal {goal_id} is {g.get('status')}, not imported")
        g["status"] = "active"
        return doc
    doc = _mutate(home, "activate", goal_id, change, {}, stamp=stamp)
    changed_alert(home, f"mission goal {goal_id} activated by main", {"goal": goal_id})
    return doc


def retire_goal(home: Path, goal_id: str, user_source: str) -> dict:
    """Main-only: the user cancelled the goal, in words that name it."""
    stamp = require_main(home, "retire")
    loaded = load_goals(home)
    current = next((g for g in loaded.get("goals") or [] if g["id"] == goal_id), None)
    if current is None:
        raise MissionError(f"no goal {clean(goal_id)!r}")
    if not verify_user_source(user_source):
        raise MissionError("--user-source must be a user: or answer: source that resolves to the user's own words")
    if not context_words_ok(user_source, current, "retire"):
        raise MissionError(f"the quote must be one segment (no '...') and the user's whole sentence must say drop, "
                           f"cancel, retire, abandon or scrap right next to goal {goal_id} (or #its ticket), with no "
                           "condition, refusal or negation")

    def change(doc):
        g = _find(doc["goals"], goal_id)
        g["status"], g["retire"] = "retired", {"source": user_source}
        g.pop("deferral", None)
        return doc
    doc = _mutate(home, "retire", goal_id, change, {"words": clean(source_excerpt(user_source), 200)}, stamp=stamp)
    changed_alert(home, f"mission goal {goal_id} retired by main on the user's words", {"goal": goal_id})
    return doc


def bind_agent(home: Path, goal_id: str, agent: str, source: str, remove: bool = False) -> dict:
    """Main-only: bind (or unbind) an owner's exact full agent id to a goal. It covers only while `ah owners` reports
    that exact id as a live owner-type row."""
    stamp = require_main(home, "bind")
    if not isinstance(agent, str) or not AGENT_RE.match(agent):
        raise MissionError("--agent takes the owner's full agent id as `ah owners` prints it (16+ characters), never a "
                           "prefix")
    if not remove and not (isinstance(source, str) and BIND_SOURCE_RE.match(source) and len(source) <= 4000):
        raise MissionError("--source must be a user:, answer:, queue: or ticket: source (never file: or inferred:)")

    def change(doc):
        g = _find(doc["goals"], goal_id)
        bound = [a for a in g.get("bound") or [] if a != agent]
        if not remove:
            bound.append(agent)
        if len(bound) > 20:
            raise MissionError("at most 20 agents per goal")
        g["bound"] = bound
        return doc
    doc = _mutate(home, "unbind" if remove else "bind", goal_id, change,
                  {"agent": agent, "source": clean(source, 200)}, stamp=stamp)
    changed_alert(home, f"mission goal {goal_id} {'unbound from' if remove else 'bound to'} owner {agent} by main",
                  {"goal": goal_id, "agent": agent})
    return doc


def handover_words_ok(text) -> bool:
    """The user's sentence moves the mission to this session: take over the mission (here / in this session / as an
    imperative), or hand / move / transfer the mission here, with no refusal, condition, cancellation or other
    destination (user_words_ok, kind 'takeover')."""
    return user_words_ok(text, "takeover")


def set_session(home: Path, session: str, user_source=None) -> dict:
    """Main-only: the session whose main the Stop gate holds to the mission. The rule (M1, delta red-team of PR 179):
      - no mission session yet: any main sets it (the first set-session or import claims it);
      - the mission main may move it, to itself or to another session id (a planned hand-over);
      - any other top-level session may take it only for itself, and only with --user-source: a user: or answer:
        source from ITS OWN transcript whose whole sentence says to move the mission ("take over the mission in
        this session"). That is the recovery when the old main died; a sub-agent's own `claude -p` has no such
        words from the user and stays out. Every change raises `mission:goals:changed`."""
    stamp = require_main(home, "set-session", handover=True)
    caller = str(stamp.get("session") or "").lower()
    target = (session or caller).lower()
    if not SESSION_RE.match(target or ""):
        raise MissionError("--session must be a session id")
    mission = mission_session_of(home)
    how = "claimed" if not mission else "moved by the mission main"
    if mission and caller != mission:
        if target != caller:
            raise MissionError(f"the mission belongs to main session {mission}; another session may only take it for "
                               "itself, never move it elsewhere")
        if not user_source:
            raise MissionError(f"the mission belongs to main session {mission}; only that main moves it "
                               f"(`{SCRIPT} set-session --session <id>`). To take it over here, cite the user's words "
                               f"in this session: `{SCRIPT} set-session --user-source \"user:<this session>/<uuid> "
                               "\\\"take over the mission ...\\\"\"`")
        try:
            import provenance  # noqa: PLC0415
            cited = str(provenance.parse_source(user_source).get("session") or "").lower()
        except Exception:  # noqa: BLE001
            cited = ""
        if cited != caller:
            raise MissionError("--user-source must be the user's words in this session's own transcript (a hand-over "
                               "is asked for in the session that takes the mission)")
        if not handover_words_ok(user_context(user_source)):
            raise MissionError("the user's whole sentence must say to move the mission here (for example 'take over "
                               "the mission'), as a one-segment quote, with no condition or refusal")
        how = "taken over on the user's words"

    def change(doc):
        if (doc.get("mission_session") or "") != mission:
            raise MissionError("the mission session changed while this ran; check it with `report` and run it again")
        doc["mission_session"] = target
        return doc
    detail = {"session": target, "from": mission, "how": how}
    if user_source:
        detail["words"] = clean(source_excerpt(user_source), 200)
    doc = _mutate(home, "set-session", "*", change, detail, stamp=stamp)
    changed_alert(home, f"mission session set to {target} ({how}; was {mission or 'none'})",
                  {"session": target, "from": mission})
    return doc


def reseal(home: Path, reason: str, force: bool = False) -> dict:
    """Main-only: record a goals file changed outside this tool. Refused while the chain is intact unless --force."""
    stamp = require_main(home, "reseal")
    if not isinstance(reason, str) or len(reason.strip()) < 20:
        raise MissionError("--reason must say what changed and why (20+ characters)")
    audit = verify_audit(home)
    if audit["ok"] and not force:
        raise MissionError("the audit chain is intact; nothing to reseal (main may pass --force with a reason)")
    last = _last_row(home) or {}
    try:
        hand_sha = _file_sha(home)
    except ValueError as error:
        raise MissionError(f"goals file unreadable: {clean(str(error), 120)}") from None
    now_ids = {g["id"] for g in load_goals(home).get("goals") or []}
    removed = sorted(i for i in set(last.get("ids") or []) - now_ids if isinstance(i, str) and ID_RE.match(i))
    detail = {"reason": clean(reason, 300), "problem": clean(audit["problem"], 300), "forced": bool(force and audit["ok"]),
              "sealed_sha": str(last.get("after_sha") or ""), "hand_sha": hand_sha, "removed": removed}
    doc = _mutate(home, "reseal", "*", lambda d: d, detail, allow_broken=True, stamp=stamp)
    changed_alert(home, f"mission goals resealed by main: {clean(reason, 120)}"
                        + (f"; removed {', '.join(removed[:5])}" if removed else ""), {"removed": removed[:20]})
    return doc


def import_initiatives(home: Path, path) -> dict:
    """Main-only. Merge the dashboard's initiatives.json into goals.json. New ids come in as 'imported' (reported,
    not enforced, until main activates them); dashboard rows that say done/live/retired are marked as needing
    evidence. Existing goals keep every field a person set (status included) and only gain a missing ticket and the
    informational `dashboard` block. The first import sets the mission session to main's session."""
    stamp = require_main(home, "import-initiatives")
    try:
        raw = safe_input.read_bounded(path, MAX_GOALS_BYTES)
        rows = safe_input.safe_json_loads(raw, max_depth=MAX_DEPTH)
    except (safe_input.InputRejected, ValueError) as error:
        raise MissionError(f"initiatives file unreadable: {clean(str(error), 120)}") from None
    if not isinstance(rows, list):
        raise MissionError("initiatives file must be a JSON list")
    counts = {"added": 0, "updated": 0, "skipped": 0, "tickets_filled": 0}

    def info(r):
        keep = ("state", "status", "owner", "pct", "next_step", "updated")
        return {k: clean(r[k], 300) if isinstance(r[k], str) else r[k] for k in keep
                if isinstance(r.get(k), (str, int, float)) and not isinstance(r.get(k), bool)}

    def change(doc):
        by_id = {g["id"]: g for g in doc["goals"]}
        for r in rows[:MAX_GOALS]:
            gid = r.get("id") if isinstance(r, dict) else None
            if not isinstance(gid, str) or not ID_RE.match(gid):
                counts["skipped"] += 1
                continue
            title = r.get("initiative") or r.get("name") or gid
            ticket = ticket_key(r.get("ticket")) or ""
            g = by_id.get(gid)
            if g is None:
                g = {"id": gid, "title": clean(title, 300), "ticket": ticket, "priority": 3, "status": "imported"}
                doc["goals"].append(g)
                by_id[gid] = g
                counts["added"] += 1
            else:
                if not g.get("ticket") and ticket:
                    g["ticket"] = ticket
                    counts["tickets_filled"] += 1
                counts["updated"] += 1
            g["dashboard"] = info(r)
            said = (re.findall(r"[a-z]+", str(r.get("state") or r.get("status") or "").lower()) or [""])[0]
            if said in DONE_LIKE:  # "Done", "Live on goodqa.app": reported as needing evidence, never enforced
                g["dashboard"]["needs_evidence"] = True
        if not doc.get("mission_session") and SESSION_RE.match(str(stamp.get("session") or "")):
            doc["mission_session"] = str(stamp["session"]).lower()
        if len(doc["goals"]) > MAX_GOALS:
            raise MissionError(f"more than {MAX_GOALS} goals")
        return doc
    _mutate(home, "import", "*", change, {"file": clean(os.path.basename(str(path)), 120)}, stamp=stamp)
    changed_alert(home, f"mission goals imported by main: {counts['added']} added (not enforced until activated), "
                        f"{counts['tickets_filled']} tickets filled", dict(counts))
    return counts


# ------------------------------------------------------------------ signing key, signed cache

def _key_path(home: Path) -> Path:
    return private_dir(home) / "hmac.key"


def hmac_key(home: Path, create: bool = False):
    """The 32-byte HMAC key (0600 file, owner only); None when absent and not created, or unsafe (symlink, group- or
    world-readable, another owner). Same-user processes can read it: see the module docstring."""
    path = _key_path(home)
    try:
        folder = path.parent
        if os.path.islink(folder) or os.path.islink(state_root(home)):
            return None
        if not os.path.lexists(path) and create:
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(folder, 0o700)
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(secrets.token_hex(32))
            except FileExistsError:
                pass
        st = os.lstat(path)
        import stat  # noqa: PLC0415
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid():
            return None
        raw = safe_input.read_bounded(path, 256).decode("ascii").strip()
        key = bytes.fromhex(raw)
        return key if len(key) == 32 else None
    except (OSError, ValueError, UnicodeError, safe_input.InputRejected):
        return None


def _mac(key: bytes, obj) -> str:
    return hmac.new(key, json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()


def _signed_read(home: Path, path: Path, max_bytes: int):
    """The document at path when its `mac` verifies, else None."""
    key = hmac_key(home)
    if key is None or os.path.islink(path):
        return None
    try:
        doc = safe_input.safe_json_loads(safe_input.read_bounded(path, max_bytes), max_depth=MAX_DEPTH)
    except (safe_input.InputRejected, ValueError, OSError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("mac"), str):
        return None
    body = {k: v for k, v in doc.items() if k != "mac"}
    return doc if hmac.compare_digest(doc["mac"], _mac(key, body)) else None


def _signed_write(home: Path, path: Path, body: dict) -> None:
    key = hmac_key(home, create=True)
    if key is None:
        raise OSError("mission HMAC key unavailable")
    _atomic(path, json.dumps(dict(body, mac=_mac(key, body))).encode())


CACHE_POS_S = 86400
CACHE_NEG_S = 60


def _cached(home: Path, kind: str, key: str, check, now=None, pos_s: int = CACHE_POS_S):
    """Signed verification cache: a pass is remembered for pos_s (a day by default), a failure for 60 s (so an
    unresolvable source does not rescan a 400 MB transcript on every Stop); both keyed by everything they checked. An
    unsigned or forged cache is ignored. check=None only looks: the fresh cached answer, or None."""
    now = time.time() if now is None else now
    path = private_dir(home) / "verify-cache.json"
    digest = sha(f"{kind}|{key}".encode())
    doc = _signed_read(home, path, 512 * 1024) or {}
    entries = doc.get("entries") if isinstance(doc.get("entries"), dict) else {}
    hit = entries.get(digest)
    if isinstance(hit, list) and len(hit) == 2 and isinstance(hit[0], (int, float)) and isinstance(hit[1], bool):
        age = now - hit[0]
        if 0 <= age < (min(pos_s, CACHE_POS_S) if hit[1] else CACHE_NEG_S):
            return hit[1]
    if check is None:
        return None
    ok = bool(check())
    keep = {k: v for k, v in entries.items() if isinstance(v, list) and len(v) == 2
            and isinstance(v[0], (int, float)) and 0 <= now - v[0] < CACHE_POS_S}
    keep[digest] = [now, ok]
    with contextlib.suppress(OSError, ValueError):
        _signed_write(home, path, {"entries": dict(sorted(keep.items(), key=lambda kv: -kv[1][0])[:2000])})
    return ok


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
        return clean(str(error), 200) or type(error).__name__
    return None


def verify_done_evidence(home: Path, goal: dict, mission: str = "") -> bool:
    rows = goal.get("done_evidence")
    rows = [rows] if isinstance(rows, dict) else (rows or [])
    if mission and any(isinstance(r, dict) and str(r.get("session") or "").lower() != mission for r in rows):
        return False
    return done_evidence_problem(home, goal) is None


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


def owner_type(row, pol=None) -> bool:
    return isinstance(row, dict) and isinstance(row.get("agent_id"), str) \
        and str(row.get("type") or "") not in _helper_types(pol)


def live_owner(row, pol=None) -> bool:
    """An `ah owners` row that holds work now: an owner type (never a helper) in a running state."""
    if not owner_type(row, pol):
        return False
    state = str(row.get("state") or "")
    if state.startswith(RUNNING):
        return True
    return state.startswith("SILENT") and not _slot_freed(row)


def owner_rows(home: Path, session: str, now=None) -> list:
    """The full `ah owners` scan (10-25 s on a large session; ah has no cheaper mode)."""
    import ah  # noqa: PLC0415
    return list(ah.owners(home, session, now=now).get("owners") or [])


class OwnerDeadline(BaseException):
    """The owner scan ran past its budget (BaseException: no `except Exception` inside ah may swallow it)."""


SNAPSHOT_MAX_S = 15 * 60  # ops-watch runs every 10 minutes
SNAPSHOT_FIELDS = ("agent_id", "type", "ticket", "state", "owner", "parent", "last_activity", "idle_s",
                   "disposition", "decision_required")


def owner_snapshot_path(home: Path, session: str) -> Path:
    return private_dir(home) / f"owners-{session}.json"


def _seq_path(home: Path, session: str) -> Path:
    return private_dir(home) / f"owners-{session}.seq.json"


def write_owner_snapshot(home: Path, session: str, rows, by: str, now=None) -> int:
    """ops-watch only: sign the full owner scan (only the fields the rule reads) with a monotone seq."""
    if by != "ops_watch":
        raise MissionError("only ops-watch writes the owner snapshot")
    if not SESSION_RE.match(session or ""):
        raise MissionError("snapshot needs a session id")
    now = time.time() if now is None else now
    seq_doc = _signed_read(home, _seq_path(home, session), 4096) or {}
    seq = int(seq_doc.get("seq") or 0) + 1 if seq_doc.get("session") == session else 1
    slim = [{k: r.get(k) for k in SNAPSHOT_FIELDS} for r in rows or [] if isinstance(r, dict)][:5000]
    _signed_write(home, owner_snapshot_path(home, session),
                  {"at": now, "session": session, "by": "ops_watch", "seq": seq, "rows": slim})
    _signed_write(home, _seq_path(home, session), {"session": session, "seq": seq})
    return seq


def load_owner_snapshot(home: Path, session: str, now=None):
    """The signed ops-watch snapshot of this session when it is the latest seq and at most SNAPSHOT_MAX_S old."""
    now = time.time() if now is None else now
    if not SESSION_RE.match(session or ""):
        return None
    doc = _signed_read(home, owner_snapshot_path(home, session), 16 << 20)
    seq = _signed_read(home, _seq_path(home, session), 4096)
    if doc is None or seq is None or doc.get("session") != session or seq.get("session") != session \
            or doc.get("by") != "ops_watch" or doc.get("seq") != seq.get("seq") or not isinstance(doc.get("rows"), list) \
            or not isinstance(doc.get("at"), (int, float)) or not 0 <= now - doc["at"] <= SNAPSHOT_MAX_S:
        return None
    return doc


def owners_bounded(home: Path, session: str, now=None, deadline_s=None, prefer_snapshot: bool = False,
                   save_snapshot: bool = False) -> tuple:
    """(rows, note). prefer_snapshot: ops-watch's signed snapshot when fresh. Otherwise a live scan abandoned after
    deadline_s seconds (SIGALRM, main thread only); save_snapshot (ops-watch) signs it. Raises OwnerDeadline on
    overrun: a missing or late scan is never coverage."""
    import signal  # noqa: PLC0415
    import threading  # noqa: PLC0415
    if prefer_snapshot:
        snap = load_owner_snapshot(home, session, now)
        if snap is not None:
            age = int((time.time() if now is None else now) - snap["at"])
            return snap["rows"], f"(owners from ops-watch's signed scan {fmt_age(age)} ago)"
    armed = bool(deadline_s) and hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
    previous = None
    if armed:
        def expired(_signum, _frame):
            raise OwnerDeadline()
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, float(deadline_s))
    try:
        rows = owner_rows(home, session, now)
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    if save_snapshot:
        with contextlib.suppress(OSError, MissionError, TypeError, ValueError):
            write_owner_snapshot(home, session, rows, by="ops_watch", now=now)
    return rows, ""


def owner_progress(home: Path, session: str, agent: str) -> float:
    """Time of the owner's last own WAL entry (hook lifecycle rows and rows others wrote for it excluded); its first
    WAL row when it has written nothing yet; 0 when there is no WAL."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", agent or ""):
        return 0.0
    import ah  # noqa: PLC0415
    folder = ah.session_dir(home, session)
    path = folder / f"agent-{agent}.jsonl"
    if not path.is_file():
        path = folder / f"{agent}.jsonl"
    if not path.is_file():
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

def deferral_status(goal: dict, now: float, asks: dict, verify_source, tickets=None, words_ok=None):
    """(state, reason): state WAITING or DEFERRED when the deferral is live, else None with why not.
    tickets: {ticket key: 'open'|'closed'|'missing'|None} from waited_ticket_states (None = GoodQA did not answer in
    time); a waited-on ticket that is closed or missing no longer covers. words_ok(source, goal, kind): the user's
    words check (excerpt_words_ok when not given; assess passes the whole-sentence check)."""
    words_ok = words_ok or excerpt_words_ok
    d = goal.get("deferral")
    if not isinstance(d, dict):
        return None, "no deferral"
    until = parse_ts(d.get("until")) if d.get("until") else 0.0
    by = d.get("by")
    if by in ("ask", "ticket"):
        ref = d.get("ref") if isinstance(d.get("ref"), str) else ""
        shown = clean(ref if (ASK_ID_RE.match(ref) or ticket_key(ref)) else "an invalid ref", 40)
        if max(int(d.get("renewal") or 0), int(goal.get("wait_count") or 0)) > MAX_RENEWALS:
            return None, f"its wait on {shown} was renewed more than {MAX_RENEWALS} times without the user's word"
        if not until or until <= now:
            return None, f"its wait on {shown} expired"
        if until - now > WAIT_MAX_S:
            return None, f"its wait on {shown} runs past 7 days (renew it, never park a goal)"
        if by == "ask":
            state, note = _ask(asks, ref)
            if not ASK_ID_RE.match(ref) or state != "open":
                return None, f"it waits on ask {shown}, which is {clean(state, 12) or 'unknown'} in main's WAL"
            if not names_goal(note, goal):
                return None, f"it waits on ask {shown}, which does not name this goal"
            return "WAITING", f"waits on open ask {shown} until {iso(until)}"
        if not ticket_key(ref) or same_ticket(ref, goal.get("ticket")):
            return None, "a ticket wait must name another ticket"
        if tickets is not None:
            state = tickets.get(ticket_key(ref))
            if state in ("closed", "missing"):
                return None, f"it waits on {ticket_key(ref)}, which is {state} in GoodQA"
            if state != "open":
                return "WAITING", (f"waits on {ticket_key(ref)} until {iso(until)} (GoodQA did not answer in time; "
                                   "open state not confirmed this turn)")
        return "WAITING", f"waits on {ticket_key(ref)} until {iso(until)}"
    if by == "user":
        if d.get("until") and (not until or until <= now):
            return None, "the user's deferral ended"
        words = source_excerpt(d.get("source"))
        if not words_ok(d.get("source"), goal, "defer"):
            return None, ("its deferral words do not say defer right next to this goal in one quoted segment, without "
                          "a condition or refusal in the user's sentence")
        if not verify_source(d.get("source")):
            return None, "its deferral source does not resolve to the user's own words (user: or answer:)"
        return "DEFERRED", f'deferred by the user: "{clean(words)}"' + (f" until {iso(until)}" if until else "")
    return None, "unknown deferral kind"


def _matches(row, goal, key) -> bool:
    if row.get("agent_id") in (goal.get("bound") or []):
        return True
    return bool(key) and same_ticket(row.get("ticket"), key)


def evaluate(goals, rows, now, asks=None, verify_source=None, verify_evidence=None, progress=None, commits=None,
             pol=None, stall_s: int = STALL_S, tickets=None, words_ok=None) -> list:
    """One result per goal: {id, title, ticket, priority, status, state, reason, owners, progress_age_s}. state is
    UNCOVERED, STALLED, COVERED, WAITING, DEFERRED, DONE, RETIRED or IMPORTED. Owners come only from `rows`.
    tickets and words_ok: see deferral_status."""
    verify_source = verify_source or verify_user_source
    words_ok = words_ok or excerpt_words_ok
    verify_evidence = verify_evidence or (lambda g: False)
    progress, commits = progress or {}, commits or {}
    rows = [r for r in rows or [] if isinstance(r, dict)]
    live = [r for r in rows if live_owner(r, pol)]
    out = []
    for g in goals:
        key = ticket_key(g.get("ticket"))
        res = {"id": g["id"], "title": clean(g.get("title") or g["id"], 120), "ticket": key or "",
               "priority": g.get("priority", 3), "status": g.get("status", "active"), "owners": [],
               "progress_age_s": None, "state": "UNCOVERED", "reason": ""}
        out.append(res)
        if res["status"] == "done":
            if verify_evidence(g):
                res["state"], res["reason"] = "DONE", "done with deploy and live-test evidence"
            else:
                res["reason"] = "marked done but its done_evidence does not resolve (deploy record + live REALLY_TESTED)"
            continue
        if res["status"] == "retired":
            src = (g.get("retire") or {}).get("source")
            words = source_excerpt(src)
            if words_ok(src, g, "retire") and verify_source(src):
                res["state"], res["reason"] = "RETIRED", f'retired by the user: "{clean(words)}"'
            else:
                res["reason"] = "marked retired but the user's words naming it do not resolve"
            continue
        if res["status"] == "imported":
            res["state"] = "IMPORTED"
            res["reason"] = ("imported from the dashboard, not enforced until main runs activate"
                             + ("; the dashboard says done, so it needs done evidence"
                                if (g.get("dashboard") or {}).get("needs_evidence") else ""))
            continue
        owners = [r for r in live if _matches(r, g, key)]
        if owners:
            res["owners"] = sorted(r["agent_id"] for r in owners)
            last = max([(progress.get(r["agent_id"]) if progress.get(r["agent_id"])
                         else parse_ts(r.get("last_activity"))) or 0.0 for r in owners] + [commits.get(key) or 0.0])
            res["progress_age_s"] = int(max(0.0, now - last)) if last else None
            stalled = res["progress_age_s"] is None or res["progress_age_s"] > stall_s
            names = ", ".join(clean(a, 40) for a in res["owners"][:5])
            res["state"] = "STALLED" if stalled else "COVERED"
            res["reason"] = (f"owner {names}: no own WAL entry or commit on {key or 'its ticket'} for "
                             f"{fmt_age(res['progress_age_s'])}" if stalled else f"owner {names}")
            continue
        held = [r for r in rows if owner_type(r, pol) and _matches(r, g, key)
                and isinstance(r.get("disposition"), dict) and r["disposition"].get("live") is True
                and r["disposition"].get("kind") in LIVE_DISPOSITIONS]
        if held:
            d = held[0]["disposition"]
            res["state"] = "WAITING"
            res["reason"] = f"ah disposition {clean(d.get('kind'), 12)} on owner {clean(held[0]['agent_id'], 40)} is live"
            continue
        state, why = deferral_status(g, now, asks, verify_source, tickets=tickets, words_ok=words_ok)
        if state:
            res["state"], res["reason"] = state, why
            continue
        if not key:
            why = "it has no ticket, so no owner can be matched to it; " + why
        else:
            why = f"no live owner on {key}; " + why
        res["reason"] = why
    return out


_ORDER = {"UNCOVERED": 0, "STALLED": 1, "COVERED": 2, "WAITING": 3, "DEFERRED": 3, "IMPORTED": 4, "DONE": 5,
          "RETIRED": 5}


def sort_report(results) -> list:
    """Slowest first: UNCOVERED (by priority), STALLED (oldest progress first), covered (least recent progress
    first), then waiting/deferred, imported, then done/retired."""
    def key(r):
        rank = _ORDER.get(r["state"], 0)
        age = r.get("progress_age_s")
        if rank in (1, 2):
            return (rank, -(age if age is not None else 10 ** 9), r["id"])
        return (rank, r.get("priority", 3), r["id"])
    return sorted(results, key=key)


def cap_candidates(results, rows, cap, pol=None, now=None) -> list:
    """When the owner cap is full and a goal is uncovered: the live owners to free or queue, best candidate first.
    Owners on no mission goal go first (most idle first), then owners of the lowest-priority, most stalled goals.
    [] when the cap is not full or nothing is uncovered."""
    uncovered = [r for r in results if r["state"] == "UNCOVERED"]
    live = [r for r in rows or [] if live_owner(r, pol)]
    if not cap or not uncovered or len(live) < cap:
        return []
    now = time.time() if now is None else now
    goal_of = {}
    for res in results:
        for agent in res.get("owners") or []:
            goal_of.setdefault(agent, res)

    def rank(r):
        res = goal_of.get(r["agent_id"])
        idle = r.get("idle_s") if isinstance(r.get("idle_s"), (int, float)) else max(0.0, now - parse_ts(r.get("last_activity")))
        if res is None:
            return (0, 0, -int(idle), r["agent_id"])
        return (1, -int(res.get("priority", 3)), -(res.get("progress_age_s") or 0), r["agent_id"])

    def describe(r):
        res = goal_of.get(r["agent_id"])
        if res is None:
            return f"{clean(r['agent_id'], 40)} ({clean(ticket_key(r.get('ticket')) or 'no ticket', 40)}, on no mission goal)"
        return (f"{clean(r['agent_id'], 40)} (goal {res['id']} priority {res['priority']}, "
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


_STALE_DISPOSITION = ("expired", "ended", "which is", "does not resolve", "past 7 days", "another ticket", "renewed",
                      "does not name", "do not name")


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
            elif r["status"] == "retired":
                reason = "It is marked retired but the user's words naming it do not resolve."
                action = "Have main record the user's words with mission_coverage.py retire, or set it active again."
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
                action = action[:-1] + f"; the owner cap is full, so first free or queue owner {clean(victim, 40)}."
        elif r["state"] == "STALLED":
            who = ", ".join(clean(a, 40) for a in r["owners"][:5])
            status = "stalled"
            reason = f"Owner {who} has made no WAL entry or commit on {t or 'its ticket'} for {fmt_age(r['progress_age_s'])}."
            action = f"Check on {who} and get a progress note or commit, or reassign {t or 'the goal'}."
        else:
            status = "moving"
            reason = {"COVERED": f"Owner {', '.join(clean(a, 40) for a in r['owners'][:5])} is working on it.",
                      "WAITING": f"It {r['reason']}.", "DEFERRED": f"It was {r['reason']}.",
                      "DONE": "It is done with deploy and live-test evidence.",
                      "RETIRED": f"It was {r['reason']}.",
                      "IMPORTED": "It was imported from the dashboard and is not enforced yet."}.get(r["state"],
                                                                                                     f"{r['reason']}.")
            action = {"WAITING": "Follow up when the wait ends.",
                      "IMPORTED": f"Activate it with mission_coverage.py activate --goal {r['id']}, or retire it."}.get(
                r["state"], "No action needed.")
        entry = {"status": status, "reason": reason, "action": action}
        out.setdefault(r["id"], entry)
        if t:
            out.setdefault(t, entry)
    return out


GATE_LIMIT = 5
GATE_MAX_CHARS = 1500


def gate_message(results, advice: str = "", limit: int = GATE_LIMIT) -> str:
    """At most `limit` worst uncovered goals, the count of the rest, the one command that lists all, and the fixes once;
    every interpolated value sanitized; at most GATE_MAX_CHARS characters."""
    unc = sort_report([x for x in results if x["state"] == "UNCOVERED"])
    lines = [f"Mission coverage (goodqa#15565): {len(unc)} active goal(s) UNCOVERED (no live owner, no live wait, "
             "no done evidence):"]
    for r in unc[:limit]:
        g, t = clean(r["id"], 64), clean(r["ticket"], 40)
        if not t:
            lines.append(f"  - {g} (no ticket, p{r['priority']}): give it a ticket with "
                         f"`mission_coverage.py set --goal {g} --ticket goodqa#N` first")
        else:
            lines.append(f"  - {g} ({t}, p{r['priority']}): {clean(r['reason'], 140)}")
    more = len(unc) - limit
    lines.append(f"  ...and {more} more; all of them: {SCRIPT} report" if more > 0 else f"  details: {SCRIPT} report")
    lines.append("Fix each: start an owner whose first WAL ticket is the goal's ticket; or main binds a live owner: "
                 "mission_coverage.py bind --goal ID --agent FULL_AGENT_ID --source ticket:goodqa#N; or a wait: "
                 "defer --goal ID --ask ASKID|--ticket T --until ISO; or the user's own deferral naming the goal: "
                 "defer --goal ID --user-source \"user:SESSION/UUID \\\"words\\\"\"; or "
                 "done --goal ID --deploy WALID --live-test ID.")
    text = "\n".join(lines)
    if advice:
        text += "\n" + clean(advice, max(0, GATE_MAX_CHARS - len(text) - 1))
    return text[:GATE_MAX_CHARS]


def mission_alerts(assessment: dict) -> list:
    """ops-watch alert dicts for an assessment: mission:<goal>:uncovered (high, stop_block) and mission:<goal>:stalled
    (warning); mission:goals:unreadable (high) when the file cannot be trusted."""
    state = assessment.get("state")
    if state in ("error", "tampered"):
        return [{"check": "mission", "key": "mission:goals:unreadable", "severity": "high",
                 "message": f"mission goals file cannot be trusted: {clean(assessment.get('error'), 200)}",
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
                        "detail": {"goal": r["id"], "ticket": r["ticket"], "owners": r["owners"][:10],
                                   "age_min": (r["progress_age_s"] or 0) // 60, "stop_block": False}})
    return out


# ------------------------------------------------------------------ assessment (I/O around the rule)

TICKET_CHECK_S = 2.5        # GoodQA lookups for waited-on tickets at Stop, all in parallel (the hook has 15 s)
TICKET_OPEN_CACHE_S = 600   # an "open" answer is reused for 10 minutes; closed, missing or no answer never is


def waited_ticket_states(home: Path, goals, now=None, budget: float = TICKET_CHECK_S) -> dict:
    """{ticket key: 'open'|'closed'|'missing'|None} for each ticket an active or deferred goal waits on (M3: a
    waited-on ticket that closed stops covering). Lookups run in parallel within budget; None = no answer in time."""
    import threading  # noqa: PLC0415
    refs = sorted({ticket_key(g["deferral"].get("ref")) for g in goals or []
                   if g.get("status") in ("active", "deferred") and isinstance(g.get("deferral"), dict)
                   and g["deferral"].get("by") == "ticket" and ticket_key(g["deferral"].get("ref"))})[:20]
    out, todo = {}, []
    for ref in refs:
        if _cached(home, "ticket-open", ref, None, now, pos_s=TICKET_OPEN_CACHE_S) is True:
            out[ref] = "open"
        else:
            todo.append(ref)
    box, workers = {}, []
    for ref in todo:
        def work(r=ref):
            box[r] = ticket_state(r, timeout=budget)
        t = threading.Thread(target=work, daemon=True)
        t.start()
        workers.append(t)
    end = time.monotonic() + budget
    for t in workers:
        t.join(max(0.0, end - time.monotonic()))
    for ref in todo:
        out[ref] = box.get(ref)
        if out[ref] == "open":
            _cached(home, "ticket-open", ref, lambda: True, now, pos_s=TICKET_OPEN_CACHE_S)
    return out


def assess(home: Path, session: str, now=None, with_commits: bool = False, deadline_s=None,
           prefer_snapshot: bool = False, save_snapshot: bool = False) -> dict:
    """{"state": absent|error|tampered|owners-unavailable|ok, "results", "advice", "error", "mission_session"}."""
    now = time.time() if now is None else now
    loaded = read_consistent(home)
    mission = loaded.get("mission_session") or ""
    if loaded["state"] == "absent":
        return {"state": "absent", "results": [], "mission_session": ""}
    if loaded["state"] in ("error", "tampered"):
        return {"state": loaded["state"], "results": [], "error": loaded.get("error"), "mission_session": mission}
    try:
        rows, owners_note = owners_bounded(home, session, now, deadline_s, prefer_snapshot=prefer_snapshot,
                                           save_snapshot=save_snapshot)
    except OwnerDeadline:
        return {"state": "owners-unavailable", "results": [], "mission_session": mission,
                "error": f"the owner scan overran {deadline_s}s and ops-watch has no signed owner list under "
                         f"{SNAPSHOT_MAX_S // 60} min old"}
    except Exception as error:  # noqa: BLE001 - no main WAL here or an ah defect: say so, never guess coverage
        return {"state": "owners-unavailable", "results": [], "mission_session": mission,
                "error": f"{type(error).__name__}: {clean(str(error), 120)}"}
    pol = policy()
    goals = loaded["goals"]
    covering = [r for r in rows if live_owner(r, pol) and any(_matches(r, g, ticket_key(g.get("ticket"))) for g in goals
                                                               if g.get("status") in ("active", "deferred"))]
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
                           [g.get("ticket"), g.get("done_evidence"), mission], sort_keys=True),
                           lambda: verify_done_evidence(home, g, mission)),
                       progress=progress, commits=commits, pol=pol,
                       tickets=waited_ticket_states(home, goals, now),
                       words_ok=lambda s, g, kind: _cached(home, "words-" + kind, json.dumps(
                           [s, g.get("id"), ticket_key(g.get("ticket"))]), lambda: context_words_ok(s, g, kind)))
    cap = owner_cap()
    ranked = cap_candidates(results, rows, cap, pol, now)
    return {"state": "ok", "results": results, "advice": cap_advice(results, rows, cap, pol), "session": session,
            "mission_session": mission, "victim": ranked[0]["agent_id"] if ranked else None, "owners_note": owners_note}


# ------------------------------------------------------------------ waking main (Mission Control inbox + ring)

def _load_chat():
    try:
        import mc_chat  # noqa: PLC0415 - GoodQA #15585, not on every install yet
        return mc_chat
    except Exception:  # noqa: BLE001
        return None


def notify_main(goal_ids, home=None, session=None, chat=None) -> None:
    """Wake the orchestrator when goals become UNCOVERED: a `mission:notify` ring event always, and a Mission Control
    inbox message through mc_chat when it is installed and main has registered a target. An empty list clears."""
    home = Path(home or home_dir())
    ids = sorted({str(g) for g in goal_ids or [] if isinstance(g, str) and ID_RE.match(g)})
    if not ids:
        _ring(home, "mission:notify", "clear", "warning", "mission goals covered again", {"goals": []})
        return
    text = (f"MISSION-COVERAGE ALERT from the harness (mission_coverage.py), not typed by the user: goal(s) "
            f"{', '.join(ids[:20])} have no live owner, no live disposition and no done evidence. Run `{SCRIPT} report` "
            "and give each an owner, a named wait, or done evidence.")
    _ring(home, "mission:notify", "raise", "warning", text, {"goals": ids[:20], "stop_block": False})
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
    s = sub.add_parser("set", help="change title or priority, clear a deferral, set active; --ticket/--repo main-only")
    s.add_argument("--goal", required=True)
    s.add_argument("--title")
    s.add_argument("--ticket")
    s.add_argument("--priority", type=int)
    s.add_argument("--status", choices=("active",))
    s.add_argument("--repo", action="append", dest="repos")
    s.add_argument("--clear-deferral", action="store_true")
    s.add_argument("--target", help="(main) the user's measurable target, with --target-source")
    s.add_argument("--target-source", help="user:<session>/<uuid> \"words\" (ah user-msg prints it)")
    s.add_argument("--alias", action="append", dest="aliases", help="(main) a word the status lint matches; repeat")
    at = sub.add_parser("attach", help="attach a REALLY_TESTED row or deploy event to a goal (ah goals shows it)")
    at.add_argument("--goal", required=True)
    at.add_argument("--evidence", required=True, help="WAL entry id (w + 11 hex)")
    at.add_argument("--kind", choices=ATTACH_KINDS)
    at.add_argument("--session")
    at.add_argument("--remove", action="store_true", help="(main) detach this id")
    d = sub.add_parser("defer", help="record what a goal waits on, or (main) the user's deferral")
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
    v = sub.add_parser("activate", help="(main) enforce an imported goal")
    v.add_argument("--goal", required=True)
    t = sub.add_parser("retire", help="(main) the user cancelled the goal")
    t.add_argument("--goal", required=True)
    t.add_argument("--user-source", required=True)
    b = sub.add_parser("bind", help="(main) bind an owner's full agent id to a goal")
    b.add_argument("--goal", required=True)
    b.add_argument("--agent", required=True)
    b.add_argument("--source", default="")
    b.add_argument("--remove", action="store_true")
    ss = sub.add_parser("set-session", help="(main) the session whose main the Stop gate holds")
    ss.add_argument("--session", default="")
    ss.add_argument("--user-source", help="another session taking the mission: the user's words in this session")
    i = sub.add_parser("import-initiatives", help="(main) merge the dashboard initiatives.json into goals.json")
    i.add_argument("file")
    r = sub.add_parser("reseal", help="(main) record a goals file changed outside this tool (audited)")
    r.add_argument("--reason", required=True)
    r.add_argument("--force", action="store_true")
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
                 repos=args.repos, clear_deferral=args.clear_deferral, target=args.target,
                 target_source=args.target_source, aliases=args.aliases)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "attach":
        attach_evidence(home, args.goal, args.evidence, kind=args.kind or "", session=args.session, remove=args.remove)
        return {"ok": True, "goal": args.goal, "evidence": args.evidence}, 0
    if args.cmd == "defer":
        defer_goal(home, args.goal, ask=args.ask, ticket=args.ticket, user_source=args.user_source, until=args.until,
                   session=args.session)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "done":
        done_goal(home, args.goal, deploy=args.deploy, live_test=args.live_test, session=args.session)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "activate":
        activate_goal(home, args.goal)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "retire":
        retire_goal(home, args.goal, args.user_source)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "bind":
        bind_agent(home, args.goal, args.agent, args.source, remove=args.remove)
        return {"ok": True, "goal": args.goal}, 0
    if args.cmd == "set-session":
        doc = set_session(home, args.session, user_source=args.user_source)
        return {"ok": True, "mission_session": doc["mission_session"]}, 0
    if args.cmd == "import-initiatives":
        return dict(import_initiatives(home, args.file), ok=True), 0
    if args.cmd == "reseal":
        reseal(home, args.reason, force=args.force)
        return {"ok": True}, 0
    if args.cmd == "verify":
        result = verify_audit(home)
        return result, 0 if result["ok"] else 2
    session = args.session or mission_session_of(home) or main_session(home)
    a = assess(home, session, with_commits=(args.cmd == "report"), prefer_snapshot=(args.cmd == "check"))
    results = sort_report(a.get("results") or [])
    uncovered = [r["id"] for r in results if r["state"] == "UNCOVERED"]
    doc = {"state": a["state"], "error": a.get("error"), "generated": iso(time.time()),
           "mission_session": a.get("mission_session") or "", "session": session, "uncovered": uncovered,
           "goals": results, "advice": a.get("advice") or "", "coverage": coverage_map(results, a.get("victim"))}
    rc = 2 if a["state"] in ("error", "tampered", "owners-unavailable") else (1 if uncovered and args.cmd == "check" else 0)
    return doc, rc


def render(doc: dict) -> str:
    if "goals" not in doc:
        return json.dumps(doc, indent=1)
    if doc.get("error"):
        return f"mission coverage: {doc['state']}: {clean(doc['error'], 300)}"
    lines = [f"Mission coverage, slowest first ({len(doc['uncovered'])} uncovered; mission session "
             f"{doc.get('mission_session') or 'not set'}):"]
    for r in doc["goals"]:
        age = f" {fmt_age(r['progress_age_s'])}" if r.get("progress_age_s") is not None else ""
        lines.append(f"  {r['state']:<9} {r['id']} ({r['ticket'] or 'no ticket'}, p{r['priority']}){age}: "
                     f"{clean(r['reason'], 300)}")
    if doc.get("advice"):
        lines.append(clean(doc["advice"], 600))
    return "\n".join(lines)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    claim_main(argv, home_dir())  # before parsing: a failing or --help main command leaves no stamp behind (M2)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit:
        _PROOF.clear()
        raise
    try:
        doc, rc = run(args, home_dir())
    except MissionError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 2
    finally:
        _PROOF.clear()  # never carried past the one command it was taken for
    print(json.dumps(doc, indent=1) if getattr(args, "json", False) or args.cmd not in ("report", "check")
          else render(doc))
    return rc


if __name__ == "__main__":
    sys.exit(main())
