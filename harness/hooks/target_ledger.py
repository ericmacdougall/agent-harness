"""Target ledger with narrowing detection (GoodQA #15565, never-drop upgrade 4).

A target is the user's: a number, scope, method or tool he stated (1000 desktop leads, all repos, the real GoodQA
browser, a dedicated key, swarm on). The audit found them narrowed quietly (a 25-lead pilot, core repos only, a pool key,
headless instead of the agent browser) and reported as progress without an ASSUMPTION or TARGET_MISMATCH label.

The ledger is DERIVED, never stored: the sourced `requirement`, `scope` and `decision` rows of the session's main WAL whose
source is the user's own words (user:, answer:, queue:; an inferred or unsourced row is never a target). From each row's
note and the quoted words of its source it extracts
  count   "<number> <noun>"          1000 desktop leads, 1k leads, twenty-five leads -> (1000, lead)
  all     "all <noun>"               all repos          -> (all, repo)
  term    a method or tool phrase from target_ledger_policy.json (goodqa browser, dedicated key, swarm, ...)
`check_text` flags a sentence of a checkpoint or handoff note that
  - states a SMALLER number of a ledgered noun next to a narrowing word (in that sentence or its neighbours) or a done word,
  - names a ledgered noun (all-target) or term with a narrowing word in the same sentence
unless a sentence that STARTS with ASSUMPTION or TARGET_MISMATCH covers it (the same sentence or an adjacent one; with
require_ask, the id of an `ask` row registered in this session's logs in the note too). A label inside a code span, a
file name or the middle of a sentence is not a label.
Stdlib only; Python 3.9+.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "target_ledger_policy.json"
USER_SOURCE = re.compile(r"^\s*(?:user|uuid|answer|queue):", re.I)
NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
                "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
                "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60,
                "seventy": 70, "eighty": 80, "ninety": 90}
_WORDNUM = "|".join(sorted(NUMBER_WORDS, key=len, reverse=True))
NUMBER = (r"(?:\d[\d,]*(?:\.\d+)?\s?[kK]?\b|(?:(?:a|one)\s+)?(?:hundred|thousand)\b|"
          r"(?:" + _WORDNUM + r")(?:-(?:" + _WORDNUM + r"))?\b)")
COUNT = re.compile(r"(?<![\w.])(" + NUMBER + r")[+]?[ \t-]+((?:[a-z][a-z-]*[ \t]+){0,2}[a-z][a-z-]*)", re.I)
ALL_OF = re.compile(r"\ball[ \t]+(?:the[ \t]+|of[ \t]+the[ \t]+)?([a-z][a-z-]*)", re.I)
CODE_SPAN = re.compile(r"`[^`\n]*`")
LABEL_START = re.compile(r"^[\s(\[\"'*_>-]*(?:ASSUMPTION|TARGET_MISMATCH)(?![\w./-])")
ASK_ID = re.compile(r"\bw[0-9a-f]{11}\b")
CLAUSES = re.compile(r"[,:()]|\s+-\s+|\s+(?:but|while|whereas)\s+")
SENTENCES = re.compile(r"(?<=[.!?;])\s+|\n+")
STOP_NOUNS = {"the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "with", "by", "is", "are", "was", "were", "at",
              "pilot", "only", "done", "complete", "completed", "finished"}
ALIASES = {"repository": "repo", "repositorie": "repo", "repositories": "repo", "repos": "repo"}
DONE = re.compile(r"\b(?:done|complete|completed|finished|shipped|delivered|reached)\b", re.I)
PART_OF = re.compile(r"\b(?:sample|subset|portion|fraction|slice)\b|\b(?:part|some|few)\b[ \t]+of\b", re.I)
FULL_SCOPE = re.compile(r"\b(?:all|every|each|whole|entire)\b[ \t]+((?:[a-z][a-z-]*[ \t]+){0,2}[a-z][a-z-]*)", re.I)
CHECKED_EVENTS = ("handoff", "result", "status", "decision", "check", "scope")
DEFAULT_POLICY = {"mode": "warn", "terms": [], "narrowing": [], "term_narrowing": [], "nouns": [], "require_ask": False}
MAX_LEDGER_BYTES = 16 << 20
MAX_LEDGER_SECONDS = 1.0


def load_policy(path: Path = POLICY_FILE) -> dict:
    """The policy, with every list checked: a malformed file gives the defaults, never an exception."""
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_POLICY)
    if not isinstance(policy, dict) or policy.get("mode") not in ("off", "warn", "enforce"):
        return dict(DEFAULT_POLICY)
    for key in ("terms", "narrowing", "term_narrowing", "nouns"):
        value = policy.get(key)
        policy[key] = [str(x) for x in value if isinstance(x, str)] if isinstance(value, list) else []
    policy["require_ask"] = bool(policy.get("require_ask"))
    return policy


def _stem(word: str) -> str:
    word = word.lower()
    if word in ALIASES:
        return ALIASES[word]
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    return word[:-1] if word.endswith("s") and not word.endswith("ss") else word


def _noun(phrase: str, nouns=()) -> str:
    """The counted noun of the words after a number. With configured nouns, the LAST configured noun before the first
    stop word ("1000 email leads today", "1000 leads by Friday" -> lead): a trailing adverb, deadline or qualifier never
    hides it (final-gate F3). Without nouns, the last word before the first stop word."""
    head = []
    for w in re.findall(r"[a-z][a-z-]*", phrase.lower()):
        if w in STOP_NOUNS:
            if head:
                break
            continue
        head.append(_stem(w))
    if nouns:
        found = [w for w in head if w in nouns]
        return found[-1] if found else ""
    return head[-1] if head else ""


def _nouns(phrase: str) -> set:
    return {_stem(w) for w in re.findall(r"[a-z][a-z-]*", phrase.lower()) if w not in STOP_NOUNS}


def _number(token: str):
    token = token.strip().lower().replace(",", "")
    try:
        if token.endswith("k"):
            return int(float(token[:-1].strip()) * 1000)
        return int(float(token))
    except ValueError:
        pass
    token = re.sub(r"^(?:a|one)\s+", "", token) if token.split()[-1:] in (["hundred"], ["thousand"]) else token
    if token == "hundred":
        return 100
    if token == "thousand":
        return 1000
    parts = token.split("-")
    if parts and all(p in NUMBER_WORDS for p in parts):
        return sum(NUMBER_WORDS[p] for p in parts)
    return None


def extract_targets(text: str, terms=(), nouns=()) -> list:
    """Targets stated in the user's words."""
    out = []
    for m in COUNT.finditer(text or ""):
        number, noun = _number(m.group(1)), _noun(m.group(2), nouns)
        if number is not None and number >= 10 and noun:
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


def _words(row: dict) -> str:
    """The user's words in a row: its note and the quoted excerpts of its source, never the session and message ids."""
    source = str(row.get("source") or "")
    return str(row.get("note") or "") + "\n" + "\n".join(re.findall(r'"([^"\n]*)"', source))


def ledger_from_rows(rows, terms=(), nouns=()) -> list:
    """Targets from main-WAL rows whose source is the user's own words."""
    ledger = []
    for row in rows:
        if not isinstance(row, dict) or row.get("event") not in ("requirement", "scope", "decision"):
            continue
        source = str(row.get("source") or "")
        if not USER_SOURCE.match(source) or row.get("unsourced") or row.get("assumption"):
            continue
        for target in extract_targets(_words(row), terms, nouns):
            ledger.append(dict(target, row=row.get("id"), source=source[:160]))
    return ledger


def ledger_from_wal(main_wal: Path, terms=(), nouns=()) -> list:
    """The ledger of a session's main log; none when it is unreadable, a symlink, a FIFO or not a regular file. The read
    has a byte and a time budget, so a huge log cannot slow every note."""
    rows = []
    try:
        import safe_input
        if Path(main_wal).is_symlink():
            return []
        for _, line in safe_input.iter_jsonl_lines(main_wal, max_line=65536, max_total_bytes=MAX_LEDGER_BYTES,
                                                   max_seconds=MAX_LEDGER_SECONDS):
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except Exception:  # noqa: BLE001 - no readable main log: no ledger, nothing to check against
        return []
    return ledger_from_rows(rows, terms, nouns)


def _has_word(low: str, words) -> bool:
    return any(re.search(r"\b" + re.escape(w) + r"\b", low) for w in words)


def _full_scope(plain: str, noun: str) -> bool:
    """A full-scope word bound to the ledgered noun ("all repos", "every one of the repos"), never one about something
    else in the sentence ("core repos only, all tests passed"; final-gate F2)."""
    return any(noun in _nouns(m.group(1)) for m in FULL_SCOPE.finditer(plain))


def registered_asks(wal_dir) -> set:
    """Ids of the `ask` rows (open or resolved) in the main and agent logs of the session whose log folder is wal_dir
    (<home>/wals/<session>), read with provenance's asks ledger. Empty when the folder is not a session log folder or
    cannot be read, so require_ask fails closed (final-gate F4)."""
    try:
        wal_dir = Path(wal_dir)
        if wal_dir.parent.name != "wals" or wal_dir.is_symlink():
            return set()
        import provenance
        return {r["id"] for r in provenance.ledger(wal_dir.name, home=wal_dir.parent.parent)
                if isinstance(r.get("id"), str) and ASK_ID.fullmatch(r["id"])}
    except Exception:  # noqa: BLE001 - no readable asks: no ask exempts a note
        return set()


def _labelled(sentences: list, i: int) -> bool:
    """A sentence that STARTS with the label covers its own sentence and the two beside it."""
    for j in (i - 1, i, i + 1):
        if 0 <= j < len(sentences) and LABEL_START.match(CODE_SPAN.sub("", sentences[j])):
            return True
    return False


def check_text(text: str, ledger: list, narrowing=(), require_ask: bool = False, term_narrowing=(),
               registered_asks=None) -> list:
    """Findings [{"sentence", "why", "target"}] for sentences that narrow a ledgered target and are not labelled.
    With require_ask, a label counts only beside an ask id in registered_asks (the session's own `ask` rows); an id
    that merely has the shape, or no registry at all, never does."""
    if not ledger or not text:
        return []
    words = [str(w).lower() for w in narrowing]
    term_words = words + [str(w).lower() for w in term_narrowing]  # common words only count next to a ledgered method
    sentences = [s for s in SENTENCES.split(text) if s.strip()]
    known = set(registered_asks or ())
    asked = any(m.group(0) in known for m in ASK_ID.finditer(text))
    findings = []
    for i, sentence in enumerate(sentences):
        plain = CODE_SPAN.sub(" ", sentence)
        low = plain.lower()
        around = " ".join(sentences[j].lower() for j in (i - 1, i, i + 1) if 0 <= j < len(sentences))
        hit = None
        for target in ledger:
            if target["kind"] == "count":
                numbers = [(_number(m.group(1)), m.group(2)) for m in COUNT.finditer(plain)]
                same = [n for n, phrase in numbers if n is not None and target["noun"] in _nouns(phrase)]
                if same and max(same) >= target["number"]:
                    smaller = [n for n in same if n < target["number"]]
                    if PART_OF.search(plain):
                        hit = (f"takes a part of the stated {target['number']} {target['noun']}s", target)
                        same = []  # reported below
                    elif smaller and _has_word(low, words):
                        same = smaller  # a smaller result beside a mention of the target is still smaller (final-gate F1)
                    else:
                        continue  # the full count is stated: not a narrowing
                if same and (_has_word(around, words) or DONE.search(plain)):
                    hit = (f"states {min(same)} {target['noun']}s against the stated {target['number']}", target)
            elif target["kind"] == "all":
                clauses = [c for c in CLAUSES.split(low) if target["noun"] in _nouns(c)]
                if clauses and not _full_scope(plain, target["noun"]) and any(_has_word(c, words) for c in clauses):
                    hit = (f"narrows 'all {target['noun']}s' with a narrowing word", target)
            elif target["kind"] == "term" and target["term"] in low and _has_word(around, term_words):
                hit = (f"narrows the stated method '{target['term']}'", target)
            if hit:
                break
        if hit and not (_labelled(sentences, i) and (not require_ask or asked)):
            findings.append({"sentence": sentence.strip()[:200], "why": hit[0], "target": hit[1]})
    return findings


def advice(findings: list, require_ask: bool = False) -> str:
    first = findings[0]
    return (f"target ledger: this note {first['why']} (user target from {first['target'].get('source', 'the main log')}): "
            f"\"{first['sentence'][:120]}\". Start a sentence with ASSUMPTION or TARGET_MISMATCH for the narrowing"
            + (" and cite the registered ask id" if require_ask else "")
            + "; never report it as done against the original target (only the user's own words change a target).")
