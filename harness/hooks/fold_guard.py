"""Fold guard (GoodQA #15565): an agent cannot close a ticket as duplicate or wont_fix, or archive it while it is
open, when it still carries unfinished work.

A 4-day audit found at least 8 tickets (including P0 #14518) folded into umbrellas with their acceptance criteria,
open PENDING_REAL_TEST ids and P0 priority silently lost. The guard runs inside the spec_flow PreToolUse hook, on
the tools agents close tickets with (close_issue_wont_fix, update_issue, bulk_update_issues, call_api,
archive_issue), so it needs no GoodQA server change.

Unfinished work is any of:
  ac        an AC of the attached verified spec with no evidence on the current spec
  checklist an unchecked `- [ ]` item in the description or a comment (only when no verified spec exists)
  pending   a PENDING_REAL_TEST id with no later REALLY_TESTED (ticket comments, and this user's WALs that name it)
  priority  the ticket is immediate/urgent, so it has no DONE_LIVE evidence by definition while it is open

A close is allowed when nothing is unfinished, or when its note carries ONE of:
  Carried-to: GoodQA <project>#<n>   the open target ticket names this ticket and EVERY unfinished item id
  Fold-Override: <Source>            a user:/answer:/queue: source that provenance.py resolves (main's sourced
                                     disposition); a bare assertion is not a source

Policy: spec_policy.json `fold_guard` = off|warn|enforce (default enforce). It is independent of
enforced_projects: the guard protects every project.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

CARRY = re.compile(r"(?im)^[ \t]*Carried-to:[ \t]*(?:GoodQA[ \t]+)?([a-z0-9][a-z0-9-]{0,62})#(\d{1,9})[ \t\r]*$")
OVERRIDE = re.compile(r"(?im)^[ \t]*Fold-Override:[ \t]*(.+?)[ \t\r]*$")
UNCHECKED = re.compile(r"(?m)^[ \t]*(?:[-*+]|\d{1,3}[.)])[ \t]+\[ {1,2}\][ \t]+(.+?)[ \t\r]*$")
FOLD_WORDS = re.compile(r"\b(?:fold(?:ed|ing)?|clos(?:e|ed|ing)|won'?t[ -]?fix|duplicate|drop(?:ped)?|abandon\w*|cancel\w*|"
                        r"supersed\w*|no longer (?:needed|wanted)|not needed)\b", re.I)
# A LATER sentence of the user's turn voids a fold only when it refuses, defers or retracts it (red-team ad4294 E1: words
# like "next", "should" or "think" in an unrelated later sentence must not void a legitimate fold).
FOLD_REFUSE = re.compile(r"\b(?:not|never|don'?t|do not|keep|stop|unless|if|without|leave|reopen|no|later|wait|pause|hold|"
                         r"defer|tomorrow|let me think|think (?:about|it over)|sleep on|get back|"
                         r"once|after|before|when|while|until|but|only|except|pending|soon)\b|n't\b", re.I)  # R1: conditions too
# The sentence that HOLDS the excerpt (and the excerpt itself) must also be free of hedges and conditions (E2).
FOLD_NEGATION = re.compile(FOLD_REFUSE.pattern[:-len(r")\b|n't\b")] + r"|might|maybe|should|eventually|next|think|unsure|"
                           r"consider\w*|hmm|perhaps|could|may|suppose|hopefully|presumably|whatever|ish|"
                           r"probably|possibly|likely|guess|wonder\w*|tbd|for now|sort of|kind of|lean\w*|seems?|"
                           r"i'?d|rather)\b|n't\b", re.I)
FOLD_RETRACT = re.compile(r"\b(?:never ?mind|scratch that|actually|hold on|belay|forget (?:it|that)|on second thought)\b", re.I)
PRIORITY_RANK ={"immediate": 4, "urgent": 3, "high": 2, "medium": 1, "low": 0, "none": 0}
PENDING_NOTE = re.compile(r"(?m)^[ \t]*PENDING_REAL_TEST[ \t]+([A-Za-z0-9][A-Za-z0-9._-]{0,40})[ \t]*:")
TESTED_NOTE = re.compile(r"(?m)^[ \t]*REALLY_TESTED[ \t]+([A-Za-z0-9][A-Za-z0-9._-]{0,40})[ \t]*:")
HIGH = {"immediate", "urgent"}
OPEN_STATUSES = {"triage", "backlog", "todo", "in_progress", "in_review", "on_dev", "verified_on_dev",
                 "on_staging", "verified_on_staging", "on_production"}
SOURCE_KINDS = {"user", "answer", "queue"}
MAX_WAL_BYTES = 32 << 20
WAL_WINDOW_DAYS = 30


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def has_token(text: str, token: str) -> bool:
    """token occurs in text as a whole token: AC-1 is not found inside AC-10 or foo-ac-1x."""
    token = norm(token)
    return bool(token) and re.search(r"(?<![a-z0-9._-])" + re.escape(token) + r"(?![a-z0-9_-])", text) is not None


def _bodies(issue: dict, comments: list):
    yield str(issue.get("description") or "")
    for comment in comments:
        yield str(comment.get("body") or "")


def pending_in_text(bodies) -> list:
    """PENDING_REAL_TEST ids in these texts with no REALLY_TESTED for the same id anywhere in them."""
    pending, tested = [], set()
    for body in bodies:
        tested |= set(TESTED_NOTE.findall(body))
        pending += [p for p in PENDING_NOTE.findall(body) if p not in pending]
    return [p for p in pending if p not in tested]


def tested_in_text(bodies) -> set:
    found = set()
    for body in bodies:
        found |= set(TESTED_NOTE.findall(body))
    return found


def wal_pending_index(targets: dict, home: Path | None = None, now: float | None = None, deadline: float | None = None) -> tuple:
    """({number: [open PENDING_REAL_TEST ids]}, complete) for targets {number: project slug}, from ONE scan of this
    user's WALs (last 30 days, so a bulk close does not rescan per ticket). A pending id names a ticket when its note has
    #number with no project or the ticket's own project (bugtracker#14518 is not goodqa#14518); it is open when no
    REALLY_TESTED with the same id exists in any WAL. `complete` is False when the scan hit `deadline` (monotonic
    seconds): the caller must block, not treat the missing part as clean. Unreadable or oversized WALs are skipped."""
    home = home or Path.home()
    root = home / ".claude" / "wals"
    now = time.time() if now is None else now
    pending, tested, complete = {}, [], True
    try:
        files = [f for session in root.iterdir() if session.is_dir() for f in session.glob("*.jsonl")]
    except OSError:
        return {n: [] for n in targets}, True
    for path in files:
        if deadline is not None and time.monotonic() > deadline:
            complete = False
            break
        try:
            if now - path.stat().st_mtime > WAL_WINDOW_DAYS * 86400 or path.stat().st_size > MAX_WAL_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            if "REAL" not in raw:
                continue
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            note = str(row.get("note") or "") if isinstance(row, dict) else ""
            for ident in TESTED_NOTE.findall(note):
                tested.append((path.parent.name, ident, note))
            for ident in PENDING_NOTE.findall(note):
                for number, slug in targets.items():
                    if _names_ticket(note, number, slug):
                        pending.setdefault(number, {})[ident] = path.parent.name
    # a pending id is closed by a REALLY_TESTED with the same id in the SAME session, or one that names this ticket
    # (short ids such as T1 are reused across tickets, so a bare id elsewhere proves nothing)
    return {n: [i for i, session in pending.get(n, {}).items()
                if not any(t[1] == i and (t[0] == session or _names_ticket(t[2], n, targets[n])) for t in tested)]
            for n in targets}, complete


def _names_ticket(note: str, number, slug) -> bool:
    """note has #number bare or with this ticket's own project (bugtracker#14518 is not goodqa#14518)."""
    for found in re.finditer(r"(?:\b([A-Za-z0-9][A-Za-z0-9-]*))?#%d(?!\d)" % int(number), note):
        if not found.group(1) or not slug or found.group(1).lower() == str(slug).lower():
            return True
    return False


def unmet_items(issue: dict, comments: list, spec_view=None, extra_pending=()) -> list:
    """The unfinished work this ticket still carries: [{"kind", "id", "text"}].

    spec_view: the AC ids of the verified spec that have no evidence ([] when all are proven), or None when no
    verified spec is attached (the description's unchecked checklist is read instead)."""
    items = []
    has_spec = spec_view is not None
    if has_spec:
        for ac in spec_view:
            items.append({"kind": "ac", "id": ac, "text": f"{ac} has no evidence on the current spec"})
    else:
        for body in _bodies(issue, comments):
            for line in UNCHECKED.findall(body):
                key = norm(line)[:80]
                if key and all(i["id"] != key for i in items):
                    items.append({"kind": "checklist", "id": key, "text": f"unchecked item: {line[:100]}"})
    for ident in list(pending_in_text(_bodies(issue, comments))) + [p for p in extra_pending]:
        if all(i["id"] != ident for i in items):
            items.append({"kind": "pending", "id": ident, "text": f"PENDING_REAL_TEST {ident} is still open"})
    if str(issue.get("priority") or "").lower() in HIGH:
        items.append({"kind": "priority", "id": "priority",
                      "text": f"priority is {issue.get('priority')}: a P0 or P1 is carried to an equal-priority umbrella or "
                              "folded only on the user's own words"})
    return items


def check_carry(note: str, items: list, source_number: int, source_project: str, adapter, source_id=None,
                priority=None) -> tuple:
    """(ok, problem). The named target must be a different, still-open ticket that names this ticket and every
    unfinished item id, so the work is visible where it will be tracked."""
    found = CARRY.search(note or "")
    if not found:
        return False, "no `Carried-to: GoodQA <project>#<n>` line in the note"
    slug, number = found.group(1).lower(), int(found.group(2))
    if number == source_number and slug == source_project:
        return False, "Carried-to names the ticket being closed"
    try:
        target = adapter.lookup(slug, number)
        if isinstance(target, dict) and target.get("id") == source_id:
            return False, "Carried-to names the ticket being closed"
    except Exception as error:  # an unreadable target proves nothing; fail closed
        return False, f"Carried-to {slug}#{number} could not be read ({type(error).__name__})"
    if not isinstance(target, dict):
        return False, f"Carried-to {slug}#{number} does not exist (or this key cannot see it)"
    if target.get("status") not in OPEN_STATUSES or target.get("closedAt"):
        return False, f"Carried-to {slug}#{number} is not an open ticket (status {target.get('status')})"
    text = norm("\n".join(_bodies(target, adapter.all_comments(target["id"]))))
    ref = f"#{source_number}"
    if not re.search(re.escape(ref) + r"(?!\d)", text):
        return False, f"Carried-to {slug}#{number} does not mention {ref}"
    if any(i["kind"] == "priority" for i in items) and \
            PRIORITY_RANK.get(str(target.get("priority") or "none").lower(), 0) < PRIORITY_RANK.get(str(priority or "").lower(), 0):
        return False, (f"Carried-to {slug}#{number} has priority {target.get('priority') or 'none'}, lower than this "
                       f"ticket's {priority}: a P0 or P1 cannot be carried to a lower-priority ticket")
    lost = [i for i in items if i["kind"] != "priority" and not has_token(text, i["id"])]
    if lost:
        return False, (f"Carried-to {slug}#{number} does not list these unfinished items: "
                       + ", ".join(i["id"] for i in lost[:8]))
    return True, ""


def check_override(note: str, resolver=None, number=None, turn_text=None, slug="") -> tuple:
    found = OVERRIDE.search(note or "")
    if not found:
        return False, "no `Fold-Override: <Source>` line in the note"
    quoted = re.findall(r'"([^"]*)"', found.group(1))
    cited = " ".join(quoted) if quoted else found.group(1)  # the user's words, not the session and message ids
    # The cited words must name THIS ticket (a fold word alone matched an unrelated slash command in review) and must not
    # refuse the fold: "do not close #14518" is the opposite of a disposition.
    if not (number and re.search(r"#%d(?!\d)" % int(number), cited)):
        return False, ("the words cited in Fold-Override do not name this ticket (#%s): cite the user's own sentence "
                       "about this ticket, not any message of theirs" % number)
    if FOLD_NEGATION.search(cited):
        return False, "the words cited in Fold-Override refuse or condition the fold (not, never, keep, if, unless)"
    if resolver is None:
        import provenance
        resolver = provenance.resolve
    result = resolver(found.group(1))
    kind = result.get("kind") if isinstance(result, dict) else None
    if not isinstance(result, dict) or not result.get("ok") or kind not in SOURCE_KINDS or result.get("weak"):
        return False, ("Fold-Override must cite the user's own words (user:, answer: or queue:) that resolve; "
                       "an agent message or an unresolved source is not a disposition")
    # The agent picks the quoted excerpt, so judge the user's WHOLE sentence that holds it (review R1): it must name this
    # ticket, hold a fold word, and hold no refusal or condition. Unreadable turn text fails closed.
    try:
        text = (turn_text or _turn_text)(found.group(1))
    except Exception as error:  # noqa: BLE001
        return False, f"the user's cited turn could not be read to judge the whole sentence ({type(error).__name__})"
    excerpt = norm(" ".join(quoted))
    every = [s for s in re.split(r"(?<=[.!?;])\s+|\n+", text or "") if s.strip()]
    holding = [i for i, s in enumerate(every) if excerpt and excerpt in norm(s)]
    if not holding:
        return False, "the cited excerpt is not inside one sentence of the user's turn"
    for i in holding:
        sentence = every[i]
        if not (_names_ticket(sentence, number, slug) and FOLD_WORDS.search(sentence)):
            return False, ("the user's sentence holding the excerpt must name this ticket (#%s) and say to fold, close, "
                           "drop or supersede it" % number)
        if FOLD_NEGATION.search(sentence) or "?" in sentence:
            return False, "the user's sentence holding the excerpt refuses, defers, conditions or questions the fold"
    for later in every[max(holding) + 1:]:  # the latest word decides: a later retraction voids the instruction
        if FOLD_REFUSE.search(later) or FOLD_RETRACT.search(later):
            return False, "a later sentence of the user's turn refuses, defers or retracts the fold"
    return True, ""


def _turn_text(source: str) -> str:
    """The text of the user turn a user:/answer:/queue: source cites, from the installed Claude home."""
    import escalation
    import provenance
    parsed = provenance.parse_source(source)
    return str(escalation._turn_for(parsed, escalation.installed_home() / ".claude").get("text") or "")


def assess(issue: dict, comments: list, note: str, adapter, spec_view=None, extra_pending=(),
           resolver=None) -> dict:
    """{"unmet": [...], "allowed": bool, "problems": [str]} for one close/fold of `issue`."""
    items = unmet_items(issue, comments, spec_view, extra_pending)
    if not items:
        return {"unmet": [], "allowed": True, "problems": []}
    number, project = issue.get("number"), str(issue.get("_project_slug") or "")
    carried, why_carry = (check_carry(note, items, number, project, adapter, issue.get("id"), issue.get("priority"))
                          if CARRY.search(note or "") else (False, None))
    if carried:
        return {"unmet": items, "allowed": True, "problems": []}
    overridden, why_over = check_override(note, resolver, number, slug=project) if OVERRIDE.search(note or "") else (False, None)
    if overridden:
        return {"unmet": items, "allowed": True, "problems": []}
    problems = [p for p in (why_carry, why_over) if p]
    return {"unmet": items, "allowed": False, "problems": problems}


def format_block(label: str, status: str, result: dict) -> str:
    lines = [f"{label}: closing as {status} would drop unfinished work:"]
    lines += [f"  - {i['text']}" for i in result["unmet"][:12]]
    if len(result["unmet"]) > 12:
        lines.append(f"  - ... and {len(result['unmet']) - 12} more")
    lines += [f"  Why the note was not accepted: {p}" for p in result["problems"]]
    lines.append("  Fix: finish and evidence the work; or copy each item to an open umbrella ticket and add "
                 "`Carried-to: GoodQA <project>#<n>` to the close note (the umbrella must name this ticket and "
                 "each item id); or have main add `Fold-Override: user:<session>/<uuid> \"<the user's words>\"`.")
    return "\n".join(lines)
