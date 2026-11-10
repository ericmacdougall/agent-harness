"""Ask hygiene: do not route agent-doable work to the user (GoodQA #15565, never-drop upgrade 5, first slice).

The audit found asks raised for things an agent can do itself or was already allowed to do: a Stripe settings edit the user
had granted ("agent may drive my browser to edit Stripe settings"), a process stop, a sign-in the agent-safe login path
covers. Each such ask turns into a chore for the user and stays open, re-reminding in the alert stream.

`agent_doable(note, reason, grants)` says whether a new ask should be refused. It never refuses anything that needs a
human by the harness rules: CAPTCHA, payments, new terms, creating an account, a production password.

  grant     a main-WAL row (decision, requirement or scope) whose source is the user's own words and whose note starts
            with `GRANT:`, naming what the agent may do (`GRANT: agent may drive the browser to edit Stripe settings`).
            An ask that shares two distinctive words with a grant is refused as already granted.
  pattern   ask_gate_policy.json `agent_doable`: a process stop (ah kill), a sign-in (user token, approve link,
            secure-login), a plain "please run/click/check".

Policy `mode`: off | warn | enforce (default warn: the ask is still written, with the reason as a warning).
Not built in this slice: binding AskUserQuestion answers by option id with auto-resolve, converting a thrice-reminded ask
into a main AskUserQuestion, and the 2 h `waiting on main decision` alert. Stdlib only; Python 3.9+.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "ask_gate_policy.json"
USER_SOURCE = re.compile(r"^\s*(?:user|uuid|answer|queue):", re.I)
GRANT = re.compile(r"^\s*GRANT:\s*(.+)$", re.I | re.S)
WORD = re.compile(r"[a-z][a-z0-9-]{3,}")
STOP = {"agent", "that", "this", "with", "from", "have", "will", "your", "what", "which", "should", "could", "would", "about",
        "please", "need", "want", "like", "make", "does", "into", "when", "then", "there", "their", "them", "they", "some",
        "user", "asks", "ask", "may", "can", "the", "and", "for", "you", "are", "was", "has", "not", "any", "all"}
# verbs and nouns so common in grants that sharing them alone says nothing: a grant to edit Stripe settings must not
# silence an ask to edit the Hawkeye settings
GENERIC = {"edit", "settings", "update", "change", "publish", "enable", "disable", "check", "open", "close", "create",
           "delete", "remove", "access", "page", "site", "account", "dashboard", "browser", "drive", "configure", "run"}
DEFAULT_POLICY = {"mode": "warn", "min_shared": 2, "human_only": [], "agent_doable": []}


def load_policy(path: Path = POLICY_FILE) -> dict:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_POLICY)
    if not isinstance(policy, dict) or policy.get("mode") not in ("off", "warn", "enforce"):
        return dict(DEFAULT_POLICY)
    policy["human_only"] = [str(x) for x in policy.get("human_only", []) if isinstance(x, str)] \
        if isinstance(policy.get("human_only"), list) else []
    rules = []
    for rule in policy.get("agent_doable") if isinstance(policy.get("agent_doable"), list) else []:
        if isinstance(rule, dict) and isinstance(rule.get("pattern"), str) and isinstance(rule.get("why"), str):
            try:
                rules.append({"id": str(rule.get("id") or "rule"), "re": re.compile(rule["pattern"], re.I), "why": rule["why"]})
            except re.error:
                continue
    policy["agent_doable"] = rules
    try:
        policy["min_shared"] = max(2, int(policy.get("min_shared", 2)))
    except (TypeError, ValueError):
        policy["min_shared"] = 2
    return policy


def _tokens(text: str) -> set:
    return {w for w in WORD.findall((text or "").lower()) if w not in STOP}


def grants_from_rows(rows) -> list:
    """GRANT rows of the user's own words: [{"text", "tokens", "row"}]."""
    out = []
    for row in rows:
        if not isinstance(row, dict) or row.get("event") not in ("decision", "requirement", "scope"):
            continue
        if not USER_SOURCE.match(str(row.get("source") or "")) or row.get("unsourced") or row.get("assumption"):
            continue
        found = GRANT.match(str(row.get("note") or ""))
        if found:
            tokens = _tokens(found.group(1))
            quoted = " ".join(re.findall(r'"([^"\n]*)"', str(row.get("source") or "")))
            # The grant must be a paraphrase of the user's quoted words: an agent could cite any real user message and
            # write an unrelated GRANT (review F2), so the tokens must also occur in the quoted excerpt, one of them distinctive.
            backed = tokens & _tokens(quoted)
            if len(backed) < 2 or not backed - GENERIC:
                continue
            out.append({"text": found.group(1).strip()[:200], "tokens": backed, "row": row.get("id")})
    return out


def grants_from_wal(main_wal: Path) -> list:
    rows = []
    try:
        import safe_input
        if Path(main_wal).is_symlink():
            return []
        for _, line in safe_input.iter_jsonl_lines(main_wal, max_line=65536, max_total_bytes=16 << 20, max_seconds=1.0):
            if line:
                try:
                    rows.append(json.loads(line))
                except (ValueError, RecursionError):  # one hostile line must not drop every grant
                    continue
    except Exception:  # noqa: BLE001 - no readable main log: no grants
        return []
    return grants_from_rows(rows)


def agent_doable(note: str, reason: str, grants: list, policy: dict) -> tuple:
    """(True, why) when a new ask should be refused as agent-doable or already granted, else (False, "")."""
    text = f"{note or ''} {reason or ''}"
    low = text.lower()
    if any(re.search(r"\b" + re.escape(term.lower()), low) for term in policy.get("human_only") or []):
        return False, ""  # CAPTCHA, payment, new terms, a new account, a production password stay human steps
    asked = _tokens(text)
    for grant in grants:
        shared = asked & grant["tokens"]
        if len(shared) >= policy.get("min_shared", 2) and shared - GENERIC:  # at least one distinctive word in common
            return True, (f"already granted by the user ({grant['text'][:100]}; shared words: {', '.join(sorted(shared)[:4])}): "
                          "if no step needs a person, do it and record REALLY_TESTED")
    for rule in policy.get("agent_doable") or []:
        if rule["re"].search(text):
            return True, rule["why"]
    return False, ""
