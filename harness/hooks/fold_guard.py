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

CARRY = re.compile(r"(?im)^[ \t]*Carried-to:[ \t]*(?:GoodQA[ \t]+)?([a-z0-9][a-z0-9-]{0,62})#(\d{1,9})[ \t]*$")
OVERRIDE = re.compile(r"(?im)^[ \t]*Fold-Override:[ \t]*(.+?)[ \t]*$")
UNCHECKED = re.compile(r"(?m)^[ \t]*[-*][ \t]+\[ \][ \t]+(.+?)[ \t]*$")
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


def wal_pending(number: int, home: Path | None = None, now: float | None = None) -> list:
    """Open PENDING_REAL_TEST ids that name #number in this user's WALs (last 30 days): a pending id is open when
    no REALLY_TESTED with the same id exists in the same session. Unreadable or oversized WALs are skipped (a
    comment-borne PENDING still blocks, and the skip is not a pass for the ticket's other findings)."""
    home = home or Path.home()
    root = home / ".claude" / "wals"
    now = time.time() if now is None else now
    token = re.compile(r"#%d(?!\d)" % int(number))
    found = []
    try:
        sessions = [p for p in root.iterdir() if p.is_dir()]
    except OSError:
        return found
    for session in sessions:
        pending, tested = {}, set()
        try:
            files = list(session.glob("*.jsonl"))
        except OSError:
            continue
        for path in files:
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
                    tested.add(ident)
                for ident in PENDING_NOTE.findall(note):
                    if token.search(note):
                        pending[ident] = True
        found += [i for i in pending if i not in tested and i not in found]
    return found


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
                      "text": f"priority is {issue.get('priority')} and there is no DONE_LIVE evidence"})
    return items


def check_carry(note: str, items: list, source_number: int, source_project: str, adapter, source_id=None) -> tuple:
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
    lost = [i for i in items if i["kind"] != "priority" and norm(i["id"]) not in text]
    if lost:
        return False, (f"Carried-to {slug}#{number} does not list these unfinished items: "
                       + ", ".join(i["id"] for i in lost[:8]))
    return True, ""


def check_override(note: str, resolver=None) -> tuple:
    found = OVERRIDE.search(note or "")
    if not found:
        return False, "no `Fold-Override: <Source>` line in the note"
    if resolver is None:
        import provenance
        resolver = provenance.resolve
    result = resolver(found.group(1))
    kind = result.get("kind") if isinstance(result, dict) else None
    if not isinstance(result, dict) or not result.get("ok") or kind not in SOURCE_KINDS or result.get("weak"):
        return False, ("Fold-Override must cite the user's own words (user:, answer: or queue:) that resolve; "
                       "an agent message or an unresolved source is not a disposition")
    return True, ""


def assess(issue: dict, comments: list, note: str, adapter, spec_view=None, extra_pending=(),
           resolver=None) -> dict:
    """{"unmet": [...], "allowed": bool, "problems": [str]} for one close/fold of `issue`."""
    items = unmet_items(issue, comments, spec_view, extra_pending)
    if not items:
        return {"unmet": [], "allowed": True, "problems": []}
    number, project = issue.get("number"), str(issue.get("_project_slug") or "")
    carried, why_carry = check_carry(note, items, number, project, adapter, issue.get("id")) if CARRY.search(note or "") else (False, None)
    if carried:
        return {"unmet": items, "allowed": True, "problems": []}
    overridden, why_over = check_override(note, resolver) if OVERRIDE.search(note or "") else (False, None)
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
