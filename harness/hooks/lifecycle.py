#!/usr/bin/env python3
"""Initiative lifecycle (GoodQA goodqa#15952): PENDING > AGREED > ACTIVE > READY > DONE, plus LEGACY.

The user's rule (queue 2026-11-14T04:40:13Z #69c80ac14ad8): "from now on when i tell you do something that is
initiative/owner worthy, it starts as pending - and requires us to agree on acceptence gates/definition of done -- that
you [coordinator] agree can be meaured/tested/computed without external forces -- so you can drive it to 'ready' and i
can agree its 'done'"; and (04:40:36Z #f500ab254868) "the harness/fabric/sytems need to operate like that".

Where it lives: an optional `lifecycle` object on each goal of the mission ledger (~/.agent-harness/mission/goals.json,
mission_coverage.py). The `status` enum is unchanged on purpose: installed readers reject an unknown status value but
ignore unknown keys, so an older hook keeps reading a ledger written by this code.

  lifecycle: {state: pending|agreed|active|ready|done|legacy,
              gates: [{id: "G1", text, check: {kind: test|live_test|deploy, name, verify_by}}],
              gates_sha, proposed_at, ask,                              (propose; main-only)
              agreed: {source, at, gates_sha},                          (agree; main records the user's words)
              ready: {at, gates_sha, evidence: [ids], ask},             (ready; computed, main records it)
              done: {source, at},                                       (done; the user's words only)
              legacy: {from_status, migrated_at}}                       (migrate-lifecycle; goals present then)

A goal with no lifecycle object reads PENDING: only `migrate-lifecycle` (main, once) marks goals legacy, and it marks
only goals that exist when it runs.

What this module decides (pure functions; the ledger I/O stays in mission_coverage.py):
  - gate_problems: a gate must name a registered check kind, a check name and a verify_by, and must not read as
    needing a person, an outside party or an opinion. LIMIT: this checks the gate's form. Whether a check is truly
    autonomous stays the coordinator's judgement; the user's agreement is the backstop.
  - agreement_problem / done_problem: the user's words, bound to this proposal (answer: the AskUserQuestion answer to
    the question that carries [ask:<id>], the goal id and the gates_sha prefix; user: a human turn naming the goal and
    the sha prefix or ask id). queue: records, agent text, wal:, ticket: and inferred: sources never count.
  - gate_status / ready_problems: READY from attached evidence rows (goals_view items) only.
  - effective_state: what a reader may believe. A state an agent could hand-set (agreed, active, ready, done) counts
    only when the audit chain shows the matching tool action for the goal; otherwise it reads UNVERIFIED.
Threat model: the same as caller_identity.py. Stamps are unsigned and a same-user process can edit hooks or forge a
transcript; these checks stop a careless or shortcut-taking agent, not a determined same-user forger.
Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

STATES = ("pending", "agreed", "active", "ready", "done", "legacy")
GATE_KINDS = ("test", "live_test", "deploy")
GATE_ID_RE = re.compile(r"^G[0-9]{1,2}[a-z]?$")
CHECK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")
ASK_ID_RE = re.compile(r"^w[0-9a-f]{11}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_PREFIX = 12
MAX_GATES = 20
TEXT_MAX = 600
VERIFY_MIN = 10
# The tool action that may leave a goal in each hand-settable state (audit rows carry `action`).
STATE_ACTIONS = {"agreed": ("agree",), "active": ("activate",), "ready": ("ready",), "done": ("done",),
                 "pending": ("propose", "add", "import"), "legacy": ("migrate-lifecycle",)}
LIFECYCLE_ACTIONS = ("propose", "agree", "activate", "ready", "done", "migrate-lifecycle", "add", "import")

# Wording that makes a gate depend on a person, an outside party or an opinion. Agents are named "main" and "owner"
# and may run checks; a person or vendor may not be the check.
_PEOPLE = r"(?:the\s+)?(?:user|users|human|humans|person|people|someone|somebody|customer|customers|eric|operator|" \
          r"stakeholder|stakeholders|reviewer|reviewers|qa team|team member|vendor|vendors|client|clients)"
_HUMAN_VERBS = r"(?:click\w*|tap\w*|approv\w*|confirm\w*|check\w*|verif\w*|review\w*|sign\w*|decid\w*|judg\w*|" \
               r"look\w*|eyeball\w*|accept\w*|test\w*|tries|try|agree\w*|say\w*|feel\w*|like\w*|respond\w*|repl\w*)"
HUMAN_WORDING = re.compile(
    r"\b" + _PEOPLE + r"\s+(?:\w+\s+){0,2}?" + _HUMAN_VERBS + r"\b"
    r"|\bmanual(?:ly)?\b|\bby hand\b|\bby eye\b|\beyeball\w*\b|\bwait(?:s|ing)?\s+(?:for|on|until)\b"
    r"|\blooks?\s+(?:good|right|fine|ok|okay|nice|correct)\b|\bsign[- ]?off\b|\bgut\b|\bsubjective\w*\b"
    r"|\bin\s+(?:my|our|his|her|their|your)\s+opinion\b|\bopinion of\b|\bthird[- ]part(?:y|ies)\b"
    r"|\bapproval (?:from|by|of)\b|\bhuman (?:review|judg\w*|check\w*|test\w*|approv\w*)\b"
    r"|\bjudge?ment call\b|\bfeels?\b|\bseems?\s+(?:good|right|fine|ok|okay)\b|\bif (?:possible|time permits)\b",
    re.I)
REFUSAL = re.compile(r"\b(?:don't|dont|do not|never|not|no|nor|neither|if|unless|maybe|perhaps|whether|should|could|"
                     r"would|might|won't|can't|cannot|wait|later|change|changes|instead|except|but|"
                     r"(?:does|did|is|are|was|were|should|would|could|must|have|has|had|need)n'?t)\b|n't\b|\?", re.I)
ASSENT = re.compile(r"\b(?:agree|agreed|agrees|approve|approved|accept|accepted|yes|ok|okay|go|lgtm|confirmed|"
                    r"sounds good|ship it)\b", re.I)
DONE_WORDS = re.compile(r"\b(?:done|accept|accepted|complete|completed|close it|closed|finished|ship it|"
                        r"signed off|it'?s good|approved)\b", re.I)


class LifecycleError(ValueError):
    pass


def now_iso(ts=None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if ts is None else ts))


def parse_ts(value) -> float:
    if not isinstance(value, str) or not value:
        return 0.0
    text = value.strip().replace("Z", "+00:00")
    try:
        import datetime as dt  # noqa: PLC0415
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return 0.0


# ------------------------------------------------------------------ gates

def gates_sha(gates) -> str:
    """sha256 of the canonical JSON of the gate list (sort_keys, compact separators, ensure_ascii False)."""
    data = json.dumps(gates, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def gate_problems(gates) -> list:
    """Every reason the gate list cannot be agreed, each naming its gate. Empty list = acceptable form."""
    if not isinstance(gates, list) or not gates:
        return ["gates: a non-empty JSON list of {id, text, check: {kind, name, verify_by}}"]
    if len(gates) > MAX_GATES:
        return [f"gates: at most {MAX_GATES} gates"]
    problems, seen = [], set()
    for n, g in enumerate(gates):
        gid = g.get("id") if isinstance(g, dict) else None
        label = gid if isinstance(gid, str) and GATE_ID_RE.match(gid) else f"gate #{n + 1}"
        if not isinstance(g, dict):
            problems.append(f"{label}: not an object")
            continue
        if label != gid:
            problems.append(f"{label}: id must look like G1, G2, G2b")
        elif gid in seen:
            problems.append(f"{label}: duplicate id")
        seen.add(gid)
        text = g.get("text")
        if not isinstance(text, str) or not 10 <= len(text.strip()) <= TEXT_MAX:
            problems.append(f"{label}: text must say what is measured (10..{TEXT_MAX} characters)")
            text = ""
        check = g.get("check")
        if not isinstance(check, dict):
            problems.append(f"{label}: no check: every gate needs check {{kind, name, verify_by}} an agent can run")
            continue
        kind, name, verify = check.get("kind"), check.get("name"), check.get("verify_by")
        if kind not in GATE_KINDS:
            problems.append(f"{label}: check kind {str(kind)[:20]!r} is not registered ({', '.join(GATE_KINDS)}); "
                            "a review, approval or wait is not a check")
        if not isinstance(name, str) or not CHECK_NAME_RE.match(name):
            problems.append(f"{label}: check name must be the REALLY_TESTED id (or deploy token) its evidence will carry")
        if not isinstance(verify, str) or not VERIFY_MIN <= len(verify.strip()) <= TEXT_MAX:
            problems.append(f"{label}: verify_by must give the command or agent-run live steps "
                            f"({VERIFY_MIN}..{TEXT_MAX} characters)")
            verify = ""
        for field, value in (("text", text), ("verify_by", verify)):
            hit = HUMAN_WORDING.search(value or "")
            if hit:
                problems.append(f"{label}: {field} depends on a person, an outside party or an opinion "
                                f"({hit.group(0)!r}); agents must be able to measure, test or compute it unaided")
        extra = set(g) - {"id", "text", "check"}
        if extra:
            problems.append(f"{label}: unknown keys {sorted(extra)}")
    return problems


# ------------------------------------------------------------------ the user's words

def _source_kind(source) -> str:
    m = re.match(r"(?is)^\s*([A-Za-z]+)\s*:", source or "")
    kind = m.group(1).lower() if m else ""
    return {"uuid": "user"}.get(kind, kind)


def _resolve(source, home):
    """(text-or-pairs, timestamp, kind) of a verified user: or answer: source, else raise LifecycleError."""
    kind = _source_kind(source)
    if kind not in ("user", "answer"):
        raise LifecycleError(f"a {kind or 'malformed'}: source is not the user's decision: cite an answer: (the "
                             "AskUserQuestion answer) or user: turn (ah user-msg prints it); queue:, wal:, ticket:, "
                             "inferred: and agent text never count")
    import provenance  # noqa: PLC0415
    try:
        parsed = provenance.parse_source(source)
    except provenance.Problem as problem:
        raise LifecycleError(f"source unreadable: {problem.message}") from None
    ctx = {"home": _claude_dir()}
    result = provenance.resolve(source, ctx)
    if not (result.get("ok") and result.get("origin") == "user" and not result.get("weak")):
        why = "; ".join(str(p) for p in (result.get("problems") or [])[:2]) or "not a human-authored turn"
        raise LifecycleError(f"source does not resolve to the user's own words: {why[:200]}")
    if kind == "answer":
        try:
            pairs, ts = provenance.answer_pairs(parsed["session"], parsed["uuid"], ctx["home"])
        except provenance.Problem as problem:
            raise LifecycleError(f"answer unreadable: {problem.message}") from None
        return pairs, ts, kind
    turn = provenance.user_turn(parsed["session"], parsed["uuid"], ctx["home"])
    return turn["text"], turn.get("timestamp"), kind


def _claude_dir():
    import os  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured) if configured else Path.home() / ".claude"


def _clean_answer(text: str) -> str:
    return re.sub(r"\(recommended\)", " ", text or "", flags=re.I).strip()


def _bound_answer(pairs: dict, needles, goal_id: str = "") -> tuple:
    """(question, answer) of the one question that carries every needle (substring) and names goal_id as a whole
    token; ambiguity or absence -> (None, why)."""
    hits = [(q, a) for q, a in pairs.items() if isinstance(q, str) and all(n.lower() in q.lower() for n in needles)
            and (not goal_id or _names_goal(q, goal_id))]
    wanted = ", ".join(list(needles) + ([goal_id] if goal_id else []))
    if not hits:
        return None, "no question in that answer record carries " + wanted
    if len(hits) > 1:
        return None, "more than one question in that answer record carries " + wanted
    return hits[0], ""


def _assent(answer: str, words=ASSENT) -> bool:
    text = _clean_answer(answer)
    return bool(words.search(text)) and not REFUSAL.search(text)


def _names_goal(text: str, goal_id: str) -> bool:
    """goal_id as a whole token: its - and _ may be written as -, _ or a space, but a longer id that extends it
    (lc-goal-two for lc-goal) does not count."""
    parts = [re.escape(x) for x in re.split(r"[_-]+", goal_id.lower()) if x]
    if not parts:
        return False
    pattern = r"(?<![a-z0-9_-])" + r"[-_ ]+".join(parts) + r"(?![a-z0-9_]|[-_ ]?-[a-z0-9]|[-_][a-z0-9])"
    return bool(re.search(pattern, (text or "").lower()))


def agreement_check(source, goal_id: str, lc: dict, resolver=None) -> tuple:
    """(why, at): why is '' when `source` is the user's agreement to exactly this proposal; at is the verified time of
    the user's words (the agreement time: evidence must not predate it). Order: source kind, binding, then time."""
    sha, ask, proposed = lc.get("gates_sha") or "", lc.get("ask") or "", parse_ts(lc.get("proposed_at"))
    if not SHA_RE.match(sha):
        return "no proposed gates to agree: run propose first", ""
    try:
        body, ts, kind = (resolver or _resolve)(source, None)
    except LifecycleError as error:
        return str(error), ""
    prefix = sha[:SHA_PREFIX]
    if kind == "answer":
        if not ask:
            return "this proposal has no ask id; an answer can be bound only to a registered ask", ""
        found, why = _bound_answer(body if isinstance(body, dict) else {}, [f"[ask:{ask}]", prefix], goal_id)
        if found is None:
            return why, ""
        if not _assent(found[1]):
            return f"the answer to the bound question is not an agreement: {found[1][:80]!r}", ""
    else:
        text = str(body or "")
        if not _names_goal(text, goal_id) or not (prefix in text or (ask and ask in text)):
            return f"the user's turn must name {goal_id} and the gates ({prefix}) or the ask id", ""
        if not _assent(text):
            return "the user's turn does not plainly agree (agree word missing, or a refusal, condition or question)", ""
    when = parse_ts(ts)
    if not when or (proposed and when < proposed):
        return "the user's words predate this proposal (proposed_at); ask again about the current gates", ""
    return "", now_iso(when)


def agreement_problem(source, goal_id: str, lc: dict, resolver=None) -> str:
    return agreement_check(source, goal_id, lc, resolver)[0]


def source_kind_problem(source) -> str:
    """'' for a user:/answer: source; otherwise the refusal (checked before anything else, so the reason is the
    source kind whatever the goal's state)."""
    kind = _source_kind(source)
    if kind in ("user", "answer"):
        return ""
    return (f"a {kind or 'malformed'}: source is not the user's decision: cite an answer: (the AskUserQuestion answer) "
            "or user: turn (ah user-msg prints it); queue:, wal:, ticket:, inferred: and agent text never count")


def done_problem(source, goal_id: str, lc: dict, resolver=None, after=None, ask=None) -> str:
    """'' when `source` is the user saying this goal is done, else why not. An answer: must answer the question that
    carries the done ask (`ready --ask`, or `done --ask` for a legacy goal) and names the goal as a token. `after`: an
    ISO time the words must follow (the READY record for a lifecycle goal)."""
    try:
        body, ts, kind = (resolver or _resolve)(source, None)
    except LifecycleError as error:
        return str(error)
    if kind == "answer":
        ask = ask or (lc.get("ready") or {}).get("ask") or ""
        if not ask:
            return "an answer: can close a goal only through a registered done ask (ready --ask or done --ask)"
        found, why = _bound_answer(body if isinstance(body, dict) else {}, [f"[ask:{ask}]"], goal_id)
        if found is None:
            return why
        if not _assent(found[1], ASSENT) and not _assent(found[1], DONE_WORDS):
            return f"the answer to the bound question does not say done: {found[1][:80]!r}"
    else:
        text = str(body or "")
        if not _names_goal(text, goal_id):
            return f"the user's turn must name {goal_id}"
        if not DONE_WORDS.search(text) or REFUSAL.search(text):
            return "the user's turn does not plainly say it is done (done word missing, or a refusal or condition)"
    when = parse_ts(ts)
    if after and (not when or when < parse_ts(after)):
        return "the user's words predate READY; ask about the current state"
    return ""


# ------------------------------------------------------------------ READY from evidence

def gate_status(goal: dict, items) -> list:
    """Per gate: {id, kind, name, met, row, why}. items: goals_view evidence items, each with id, kind, verdict, by,
    check, unpinned, at, gate (from the ledger row), gates_sha (the revision the row was attached under), note.
    A row qualifies only when main attached it under the current gates_sha, after the agreement, pinned and unchanged,
    with an explicit PASS (DEPLOY for a deploy gate) of the gate's kind and check name; a newer FAIL for the gate
    disqualifies it; a live_test must be no older than the newest qualifying deploy (review F1)."""
    lc = goal.get("lifecycle") or {}
    sha = lc.get("gates_sha") or ""
    agreed_at = parse_ts((lc.get("agreed") or {}).get("at"))
    deploys = []
    for i in items:
        if i.get("kind") == "deploy" and i.get("by") == "main" and i.get("verdict") == "DEPLOY" \
                and i.get("gates_sha") == sha and not i.get("unpinned"):
            deploys.append(parse_ts(i.get("at")))
    newest_deploy = max(deploys) if deploys else 0.0
    out = []
    for g in lc.get("gates") or []:
        check = g.get("check") or {}
        kind, name = check.get("kind"), check.get("name") or ""
        mine = [i for i in items if i.get("gate") == g.get("id")]
        best, why = None, "no evidence attached for this gate"
        fails = [parse_ts(i.get("at")) for i in mine if i.get("verdict") in ("FAIL", "TAMPERED", "MISSING")
                 or i.get("pinned_verdict") == "FAIL"]
        newest_fail = max(fails) if fails else 0.0
        for i in sorted(mine, key=lambda x: parse_ts(x.get("at")), reverse=True):
            at = parse_ts(i.get("at"))
            reason = ""
            if i.get("by") != "main":
                reason = "attached by an owner, not main"
            elif i.get("unpinned"):
                reason = "unpinned row"
            elif i.get("verdict") in ("TAMPERED", "MISSING"):
                reason = f"row {i.get('verdict')}"
            elif i.get("gates_sha") != sha:
                reason = "attached under an earlier gate revision"
            elif agreed_at and at and at < agreed_at:
                reason = "older than the agreement"
            elif kind == "deploy":
                if i.get("verdict") != "DEPLOY" or i.get("kind") != "deploy":
                    reason = "not a deploy record"
                elif not re.search(r"(?<![A-Za-z0-9._-])" + re.escape(name) + r"(?![A-Za-z0-9._-])",
                                   str(i.get("note_full") or i.get("note") or "")):
                    reason = f"deploy record does not name {name}"
            else:
                if i.get("verdict") != "PASS" or not i.get("explicit"):
                    reason = "not an explicit PASS"
                elif i.get("kind") != kind:
                    reason = f"a {i.get('kind')} row for a {kind} gate"
                elif i.get("check") != name:
                    reason = f"REALLY_TESTED {i.get('check')} is not {name}"
                elif kind == "live_test" and i.get("live") is not True:
                    reason = "the WAL row is not a live test (live flag missing)"
                elif kind == "live_test" and newest_deploy and at < newest_deploy:
                    reason = "live test older than the newest deploy"
            if not reason and newest_fail and newest_fail >= at:
                reason = "a newer FAIL is attached for this gate"
            if not reason:
                best, why = i, ""
                break
            if why == "no evidence attached for this gate":  # report the newest row's reason
                why = f"{i.get('id')}: {reason}"
        out.append({"id": g.get("id"), "kind": kind, "name": name, "met": best is not None,
                    "row": best.get("id") if best else None, "why": why})
    return out


def ready_problems(goal: dict, items) -> list:
    lc = goal.get("lifecycle") or {}
    if not lc.get("gates"):
        return ["no agreed gates"]
    if not (lc.get("agreed") or {}).get("gates_sha") == lc.get("gates_sha"):
        return ["the gates are not agreed at their current revision"]
    return [f"{s['id']} unmet ({s['why']})" for s in gate_status(goal, items) if not s["met"]]


# ------------------------------------------------------------------ effective state

def raw_state(goal: dict) -> str:
    lc = goal.get("lifecycle")
    if not isinstance(lc, dict):
        return "pending"
    state = lc.get("state")
    return state if state in STATES else "pending"


def lc_sha(lc) -> str:
    """sha256 of a lifecycle object in canonical form; every lifecycle audit row records it (review R1-A M2)."""
    return gates_sha(lc if isinstance(lc, dict) else None)


def lifecycle_rows(audit_rows, goal_id: str) -> list:
    """[(action, lc_sha, detail)] of the audit rows that wrote this goal's lifecycle, oldest first. A multi-goal row
    (migrate-lifecycle, import) names the goal in detail.lc_shas."""
    out = []
    for row in audit_rows or []:
        if not isinstance(row, dict):
            continue
        action, detail = row.get("action"), row.get("detail") if isinstance(row.get("detail"), dict) else {}
        shas = detail.get("lc_shas") if isinstance(detail.get("lc_shas"), dict) else None
        if shas is not None and goal_id in shas:
            out.append((action, shas[goal_id], dict(detail, _main=bool((row.get("actor") or {}).get("main_stamp")))))
        elif row.get("goal") == goal_id and action in LIFECYCLE_ACTIONS and isinstance(detail.get("lc_sha"), str):
            out.append((action, detail["lc_sha"], dict(detail, _main=bool((row.get("actor") or {}).get("main_stamp")))))
    return out


def main_created(audit_rows, goal_id: str) -> bool:
    """True when main (stamped) added or proposed this goal: the only goals a scoping owner may be spawned for."""
    return any(a in ("add", "propose", "import") and d.get("_main") for a, _s, d in lifecycle_rows(audit_rows, goal_id))


def effective_state(goal: dict, audit_rows=None, chain_ok: bool = True) -> tuple:
    """(state, note). A hand-settable state (agreed, active, ready, done, legacy) counts only when the chain verifies,
    the newest lifecycle audit row for the goal is that state's tool action, its lc_sha equals the sha of the current
    lifecycle object, and the gates still hash to the gates_sha the newest `agree` row recorded. Otherwise UNVERIFIED,
    which every caller treats as pending. audit_rows=None skips the audit comparison (unit use only)."""
    state = raw_state(goal)
    lc = goal.get("lifecycle") if isinstance(goal.get("lifecycle"), dict) else {}
    if not chain_ok and not (isinstance(goal.get("lifecycle"), dict) and state == "pending"):
        return "unverified", "the ledger's audit chain does not verify"
    if not isinstance(goal.get("lifecycle"), dict) and audit_rows is not None \
            and not any(isinstance(r, dict) and r.get("action") == "migrate-lifecycle" for r in audit_rows):
        # a ledger never migrated: its goals predate the lifecycle (main runs migrate-lifecycle once after install)
        return "legacy", "unmigrated ledger: main runs migrate-lifecycle"
    if state == "pending":
        return "pending", ""
    if not chain_ok:
        return "unverified", "the ledger's audit chain does not verify"
    if audit_rows is not None:
        rows = lifecycle_rows(audit_rows, goal["id"])
        if not rows:
            return "unverified", f"{state} has no lifecycle audit row (hand edit?)"
        action, recorded, _detail = rows[-1]
        if action not in STATE_ACTIONS.get(state, ()):
            return "unverified", f"{state} was not set by its tool action (last lifecycle write: {action})"
        if recorded != lc_sha(lc):
            return "unverified", "the lifecycle block changed after its last tool write (hand edit?)"
        if state in ("agreed", "active", "ready", "done") and lc.get("gates"):
            agrees = [d for a, _s, d in rows if a == "agree"]
            if not agrees or agrees[-1].get("gates_sha") != gates_sha(lc.get("gates")):
                return "unverified", "the gates do not hash to what the user agreed"
    if state in ("agreed", "active", "ready"):
        agreed = lc.get("agreed") or {}
        if not lc.get("gates") or agreed.get("gates_sha") != lc.get("gates_sha") \
                or gates_sha(lc.get("gates")) != lc.get("gates_sha"):
            return "unverified", "the agreement does not match the current gates"
    if state == "done" and not (lc.get("done") or {}).get("source"):
        return "unverified", "done without the user's source"
    if state == "done" and not lc.get("gates") and audit_rows is not None and not any(
            a == "migrate-lifecycle" and d.get("_main") for a, _s, d in lifecycle_rows(audit_rows, goal["id"])):
        # review r4 minor 1: only a legacy goal may close without gates and READY
        return "unverified", "done without gates is allowed only for a legacy goal"
    return state, ""


def owners_allowed(state: str) -> bool:
    return state in ("active", "ready", "legacy")
