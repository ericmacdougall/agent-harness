"""Mechanical check of a multi-entity state machine section in an ahc spec (goodqa#16049 slice M-1).

Vendored from the spec owner's draft checker (slice 1a, ruling Q-A4); a protected path by its `ahc*` name. Run:
`python3 scripts/ahc_check_state_tables.py docs/spec/ahc-m1-state-machine.md`. `entity_tables` and `embedded_core`
serve the AC-1 equality test (tests.test_ahc_core.TransitionTableTests).

Layout: a `## State machine` section containing `### Entity: <name>` subsections, each with a `#### States`
table (State | Class | Outcome | Next actor | Escalation bound | Test id) and a `#### Transitions` table
(ID | From | Event and guard | To | Actor | Effects | Obligation | Test id).

Checks per entity: unique state names; class in {active, waiting, terminal}; waiting states have a time bound;
terminal states have an outcome in {success, failure, neutral} and no exits; non-terminal states have an exit to
another state and can reach a terminal state; every state is reachable from an entry transition; every transition
has a known actor, known From/To states and a unique test id.
Rescue rules (v6e red-team): R1 an `owner` transition out of a waiting state into a terminal state must carry its
obligation (Obligation column says `carried`); R2 every transition into a `failure` terminal state escalates
(Effects column contains `escalate`); R3 only the Effect entity may dispatch (the word `dispatch` appears in the
Effects column of no other entity). Old names banned by design v3 (`blocked`, `needs-attention`) and old P0 names
may not appear as state names. Exit 0 when everything passes.
"""
import re
import sys
from collections import defaultdict

ACTORS = {"ahc-core", "ahc-review", "ahc-merge", "owner", "main", "user"}
CLASSES = {"active", "waiting", "terminal"}
OUTCOMES = {"success", "failure", "neutral"}
BANNED = {"blocked", "needs-attention", "routed-to-main", "refused", "stale-head", "pass-awaiting-main"}


def rows(lines, heading):
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == heading)
    except StopIteration:
        return None
    out = []
    for ln in lines[start + 1:]:
        if ln.startswith("#"):
            break
        if ln.startswith("|") and not re.match(r"^\|[-| ]+\|$", ln.strip()):
            out.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return out[1:]


def check_entity(name, lines, problems, tests):
    states = {}
    srows = rows(lines, "#### States")
    trows = rows(lines, "#### Transitions")
    if srows is None or trows is None:
        problems.append(f"{name}: missing States or Transitions table")
        return {}
    for r in srows:
        if len(r) != 6:
            problems.append(f"{name}: States row has {len(r)} columns: {r[:1]}")
            continue
        st, cls, outcome, actor, bound, test = r
        if st in states:
            problems.append(f"{name}: state {st} has two rows")
        if st in BANNED:
            problems.append(f"{name}: banned state name {st}")
        if cls not in CLASSES:
            problems.append(f"{name}: state {st} unknown class {cls}")
        if cls == "terminal" and outcome not in OUTCOMES:
            problems.append(f"{name}: terminal state {st} has no outcome")
        if cls != "terminal" and outcome not in ("-", ""):
            problems.append(f"{name}: non-terminal state {st} carries an outcome")
        if cls == "waiting" and not re.search(r"\d+ ?(h|min|s|d)\b", bound):
            problems.append(f"{name}: waiting state {st} has no time bound")
        if not test or test in tests:
            problems.append(f"{name}: state {st} test id missing or reused")
        tests.add(test)
        states[st] = (cls, outcome)
    names = sorted(states, key=len, reverse=True)

    def find(cell):
        found, rest = set(), cell
        for n in names:
            pat = r"(?<![\w-])" + re.escape(n) + r"(?![\w-])"
            if re.search(pat, rest):
                found.add(n)
                rest = re.sub(pat, " ", rest)
        return found

    edges = defaultdict(set)
    for r in trows:
        if len(r) != 8:
            problems.append(f"{name}: Transitions row has {len(r)} columns: {r[:1]}")
            continue
        tid, frm, event, to, actor, effects, oblig, test = r
        if actor not in ACTORS:
            problems.append(f"{name}: {tid} actor {actor!r} unknown")
        if not test or test in tests:
            problems.append(f"{name}: {tid} test id missing or reused")
        tests.add(test)
        src = {"(entry)"} if frm == "(entry)" else {s.strip() for s in frm.split(",")}
        for s in src - {"(entry)"}:
            if s not in states:
                problems.append(f"{name}: {tid} From {s!r} is not a state")
        dst = find(to)
        if not dst:
            problems.append(f"{name}: {tid} To names no known state")
        for s in src:
            edges[s] |= dst
        # R1
        if actor == "owner" and any(states.get(s, ("",))[0] == "waiting" for s in src) \
                and any(states[d][0] == "terminal" for d in dst) and "carried" not in oblig:
            problems.append(f"{name}: {tid} R1 owner moves a waiting state to terminal without carrying its obligation")
        # R2
        if any(states[d] == ("terminal", "failure") for d in dst) and "escalate" not in effects:
            problems.append(f"{name}: {tid} R2 enters a failure terminal state without escalation")
        # R3
        if name != "Effect" and re.search(r"\bdispatch", effects):
            problems.append(f"{name}: {tid} R3 dispatches an effect outside the Effect entity")
    for st, (cls, _) in states.items():
        if cls == "terminal" and edges.get(st):
            problems.append(f"{name}: terminal state {st} has exits")
        if cls != "terminal" and not (edges.get(st, set()) - {st}):
            problems.append(f"{name}: non-terminal state {st} has no exit")
    seen, todo = set(), ["(entry)"]
    while todo:
        for nxt in edges.get(todo.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    for st in states:
        if st not in seen:
            problems.append(f"{name}: state {st} unreachable from an entry")
    terminal = {s for s, (c, _) in states.items() if c == "terminal"}
    for st, (cls, _) in states.items():
        if cls == "terminal":
            continue
        reach, todo = set(), [st]
        while todo:
            for nxt in edges.get(todo.pop(), ()):
                if nxt not in reach:
                    reach.add(nxt)
                    todo.append(nxt)
        if not reach & terminal:
            problems.append(f"{name}: state {st} cannot reach a terminal state")
    return states


CORE_LINE = re.compile(r"Spec core sha256: ([0-9a-f]{64})")


def embedded_core(text):
    """The source spec core sha256 named in a vendored section's header, or None."""
    m = CORE_LINE.search(text.split("\n", 2)[0])
    return m.group(1) if m else None


def _targets(cell, names):
    found, rest = set(), cell
    for n in sorted(names, key=len, reverse=True):
        pat = r"(?<![\w-])" + re.escape(n) + r"(?![\w-])"
        if re.search(pat, rest):
            found.add(n)
            rest = re.sub(pat, " ", rest)
    return found


def entity_tables(text):
    """{entity: (states, transitions)} parsed from a State machine section, for the AC-1 equality test.

    states: {name: (class, outcome, next actor)}; transitions: {row id: (frozenset from, frozenset to, actor)}.
    A row whose To cell says "unchanged" (W24) names its From states, so it parses as a self-loop on each."""
    lines = text.split("\n")
    s0 = next(i for i, ln in enumerate(lines) if ln.startswith("## State machine"))
    s1 = next((i for i in range(s0 + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    sec = lines[s0:s1]
    heads = [i for i, ln in enumerate(sec) if ln.startswith("### Entity: ")]
    out = {}
    for k, i in enumerate(heads):
        j = heads[k + 1] if k + 1 < len(heads) else len(sec)
        part = sec[i:j]
        states = {r[0]: (r[1], r[2], r[3]) for r in rows(part, "#### States")}
        trans = {}
        for tid, frm, _event, to, actor, _effects, _oblig, _test in rows(part, "#### Transitions"):
            src = frozenset(["(entry)"]) if frm == "(entry)" else frozenset(s.strip() for s in frm.split(","))
            trans[tid] = (src, frozenset(_targets(to, states)), actor)
        out[sec[i][len("### Entity: "):].strip()] = (states, trans)
    return out


def main(path):
    lines = open(path).read().split("\n")
    try:
        s0 = next(i for i, ln in enumerate(lines) if ln.startswith("## State machine"))
    except StopIteration:
        print("PROBLEM: no State machine section")
        return 1
    s1 = next((i for i in range(s0 + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    sec = lines[s0:s1]
    heads = [i for i, ln in enumerate(sec) if ln.startswith("### Entity: ")]
    problems, tests, summary = [], set(), []
    if not heads:
        problems.append("no `### Entity:` subsections")
    for k, i in enumerate(heads):
        j = heads[k + 1] if k + 1 < len(heads) else len(sec)
        name = sec[i][len("### Entity: "):].strip()
        st = check_entity(name, sec[i:j], problems, tests)
        summary.append(f"{name}: {len(st)} states")
    print("; ".join(summary))
    for p in problems:
        print("PROBLEM:", p)
    print("RESULT:", "PASS" if not problems else "FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
