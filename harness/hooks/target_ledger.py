"""Target ledger with narrowing detection (GoodQA #15565, never-drop upgrade 4).

A target is the user's: a number, scope, method or tool he stated (1000 desktop leads, all repos, the real GoodQA
browser, a dedicated key, swarm on). The audit found them narrowed quietly (a 25-lead pilot, core repos only, a pool key,
headless instead of the agent browser) and reported as progress without an ASSUMPTION or TARGET_MISMATCH label.

The ledger is DERIVED, never stored: the sourced `requirement`, `scope` and `decision` rows of the session's main WAL whose
source is the user's own words (user:, answer:, queue:; an inferred or unsourced row is never a target). From each row
it extracts
  count   "<number> <noun>"          1000 desktop leads -> (1000, lead)
  all     "all <noun>"               all repos          -> (all, repo)
  term    a method or tool phrase from target_ledger_policy.json (goodqa browser, dedicated key, swarm, ...)
`check_text` then flags a sentence of a checkpoint or handoff note that
  - states a SMALLER number of a ledgered noun ("25-lead pilot" against 1000) next to a narrowing word, or
  - holds a narrowing word (pilot, interim, subset, headless, fallback, instead, for now, only, sample, core) and names a
    ledgered noun or term,
unless the same note carries the label ASSUMPTION or TARGET_MISMATCH (in enforce mode with require_ask, also a registered
ask id). Stdlib only; Python 3.9+.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "target_ledger_policy.json"
USER_SOURCE = re.compile(r"^\s*(?:user|uuid|answer|queue):", re.I)
COUNT = re.compile(r"\b(\d[\d,]{1,9})\+?\s+((?:[a-z][a-z-]*\s+){0,2}[a-z][a-z-]*)", re.I)
ALL_OF = re.compile(r"\ball\s+(?:the\s+|of\s+the\s+)?([a-z][a-z-]*)", re.I)
LABEL = re.compile(r"\b(?:ASSUMPTION|TARGET_MISMATCH)\b")
ASK_ID = re.compile(r"\bw[0-9a-f]{11}\b")
SENTENCES = re.compile(r"(?<=[.!?;])\s+|\n+")
STOP_NOUNS = {"the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "with", "by", "is", "are", "was", "were", "at"}
CHECKED_EVENTS = ("handoff", "result", "status", "decision", "check", "scope")
DEFAULT_POLICY = {"mode": "warn", "terms": [], "narrowing": [], "require_ask": False}


def load_policy(path: Path = POLICY_FILE) -> dict:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_POLICY)
    if not isinstance(policy, dict) or policy.get("mode") not in ("off", "warn", "enforce"):
        return dict(DEFAULT_POLICY)
    return policy


def _noun(phrase: str) -> str:
    words = [w for w in re.findall(r"[a-z][a-z-]*", phrase.lower()) if w not in STOP_NOUNS]
    return words[-1].rstrip("s") if words else ""


def _nouns(phrase: str) -> set:
    return {w.rstrip("s") for w in re.findall(r"[a-z][a-z-]*", phrase.lower()) if w not in STOP_NOUNS}


def extract_targets(text: str, terms=(), nouns=()) -> list:
    """Targets stated in the user's words."""
    out = []
    for m in COUNT.finditer(text or ""):
        number = int(m.group(1).replace(",", ""))
        noun = _noun(m.group(2))
        if noun and number >= 10 and (not nouns or noun in nouns):
            out.append({"kind": "count", "number": number, "noun": noun})
    for m in ALL_OF.finditer(text or ""):
        noun = _noun(m.group(1))
        if noun and (not nouns or noun in nouns):
            out.append({"kind": "all", "noun": noun})
    low = (text or "").lower()
    for term in terms:
        if str(term).lower() in low:
            out.append({"kind": "term", "term": str(term).lower()})
    return out


def ledger_from_rows(rows, terms=(), nouns=()) -> list:
    """Targets from main-WAL rows whose source is the user's own words."""
    ledger = []
    for row in rows:
        if not isinstance(row, dict) or row.get("event") not in ("requirement", "scope", "decision"):
            continue
        source = str(row.get("source") or "")
        if not USER_SOURCE.match(source) or row.get("unsourced") or row.get("assumption"):
            continue
        for target in extract_targets(str(row.get("note") or "") + " " + source, terms, nouns):
            ledger.append(dict(target, row=row.get("id"), source=source[:160]))
    return ledger


def ledger_from_wal(main_wal: Path, terms=(), nouns=()) -> list:
    rows = []
    try:
        import safe_input
        for _, line in safe_input.iter_jsonl_lines(main_wal, max_line=65536):
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except Exception:  # noqa: BLE001 - no readable main WAL: no ledger, nothing to check against
        return []
    return ledger_from_rows(rows, terms, nouns)


def _has_word(low: str, words) -> bool:
    return any(re.search(r"\b" + re.escape(w) + r"\b", low) for w in words)


def check_text(text: str, ledger: list, narrowing=(), require_ask: bool = False) -> list:
    """Findings [{"sentence", "why", "target"}] for sentences that narrow a ledgered target; [] when the note is labelled
    (and, with require_ask, cites a registered ask id)."""
    if not ledger or (LABEL.search(text or "") and (not require_ask or ASK_ID.search(text or ""))):
        return []
    words = [str(w).lower() for w in narrowing]
    findings = []
    for sentence in SENTENCES.split(text or ""):
        low = sentence.lower()
        if not low.strip():
            continue
        hit = None
        for target in ledger:
            names = target["kind"] != "term" and re.search(r"\b%ss?\b" % re.escape(target.get("noun", "")), low)
            if target["kind"] == "count":
                for m in COUNT.finditer(sentence):
                    n = int(m.group(1).replace(",", ""))
                    if target["noun"] in _nouns(m.group(2)) and n < target["number"] and _has_word(low, words):
                        hit = (f"states {n} {target['noun']}s against the stated {target['number']}", target)
                if not hit and names and _has_word(low, words):
                    hit = (f"narrows {target['number']} {target['noun']}s with a narrowing word", target)
            elif target["kind"] == "all" and names and _has_word(low, words):
                hit = (f"narrows 'all {target['noun']}s' with a narrowing word", target)
            elif target["kind"] == "term" and target["term"] in low and _has_word(low, words):
                hit = (f"narrows the stated method '{target['term']}'", target)
            if hit:
                break
        if hit:
            findings.append({"sentence": sentence.strip()[:200], "why": hit[0], "target": hit[1]})
    return findings


def advice(findings: list, require_ask: bool = False) -> str:
    first = findings[0]
    return (f"target ledger: this note {first['why']} (user target from {first['target'].get('source', 'the main log')}): "
            f"\"{first['sentence'][:120]}\". Label the narrowing ASSUMPTION or TARGET_MISMATCH"
            + (" and cite the registered ask id" if require_ask else "")
            + "; never report it as done against the original target (only the user's own words change a target).")
