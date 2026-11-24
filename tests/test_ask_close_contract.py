"""#170 rounds 5 and 6 (main's redesign rulings, CRITICAL class): the contract between the listing and the writer.

ask_sweep.py offers a close only when wal_note.py would write it, and every close it does not offer, wal_note refuses.
Both run ask_close.precheck, so agreement alone would be vacuous: each cell below has its expected verdict written out
literally, and the test checks it four ways, with nothing stubbed (real ask_sweep.py, wal_note.py and provenance as
subprocesses under a temporary HOME holding synthetic WALs, a transcript, a ticket cache and a git repository):

1. the listing: offered (a close is printed) or manual (no close, the reason in `action`);
2. the writer: a manual cell's close, run by hand through wal_note.py, is REFUSED (rc 2, its JSON status) with a problem
   that the listing's `action` quotes, and writes nothing;
3. `ask_sweep --apply` on a manual cell refuses with rc 3 and writes nothing;
4. an offered close is applied through `ask_sweep --apply` and must write exactly one row, with no decision.

Cells: every source word and spelling (user:, USER:, `user :`, uuid:, answer:, queue:, pasted:, mc:, ticket:, file:),
each also behind one and two wal: hops, behind inferred:, behind wal: then inferred:, and behind inferred: then wal:; in
the two close modes ask_sweep writes (no outcome, and --outcome obsolete; never a decision close); as a related-session
close and, for the answer mode, as an answer row. Each cell's first value is the state ask_close.trace gives its
source: the user's words are in its tree (human), they are not and the walk reached an origin on every branch
(not-human), or the walk stopped before it could tell (unknown, #170 round 6: never read as "not the user's").

Round 6 adds a cell for every place a walk stops (a WAL missing on this host, a missing entry, a malformed line, a path
outside ~/.claude/wals, a cycle, a chain past provenance's depth limit, too many sources, a nested inferred:, an mc:
decision behind a pointer or inside inferred:, an internal error, an entry with no source, a source that names no kind,
a wal: pointer that does not parse, and a row written the way the warn policy writes one whose source no longer
resolves), the two ranking cells the R4 review named, a tie of a traced and an untraced answer, and two answer cards
(one clean, one whose answer holds a credential). ContractAskOff runs the stop, ranking and control cells again under
an installed policy file with `"ask": "off"` (a real copy of the hooks, since the environment can only tighten the
policy); its positive control, a file: line cited without an excerpt, is refused under enforce and written under off.

The AST guards at the end keep every private list of source kinds out of the modules that decide ask closes (only
ask_close.TABLE, over provenance.SOURCE_WORDS, holds one), and keep every problem code provenance can report
classified as an end of the walk or a stop.

Run: python3 -I tests/test_ask_close_contract.py
"""
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
# ask_close and provenance are imported inside the tests that read them, so the cell tests (subprocesses only) also run
# against an older tree for the failing-first evidence

S1 = "aaaaaaaa-1111-4111-8111-00000000c0a1"
S2 = "bbbbbbbb-2222-4222-8222-00000000c0a2"
S3 = "cccccccc-3333-4333-8333-00000000c0a3"  # a session whose WAL folder is not on this host
S4 = "dddddddd-4444-4444-8444-00000000c0a4"  # a session the listing does not read, holding a malformed line
U1, UP, ANS, ULOST, ANS2 = ("%08d-0000-4000-8000-%012d" % (n, n) for n in (71, 72, 73, 79, 75))
ASK_USE, ASK_USE2 = "toolu_CONTRACT000001", "toolu_CONTRACT000002"
CARD_OK, CARD_SECRET = "w0000000fff0", "w0000000fff1"
STAMP = "2026-11-23T10:04:00.000Z"
T1 = "Close the release ask, it is done"
TA = "Yes, close it today please"
TQ = "Close the queued release ask now"
TP = "Ticket notes say the release ask is finished"
TF = "the release ask is obsolete now"
FAKE = "tok" + "en=contract-fixture-not-a-real-value"  # what SECRET_PATTERN matches; built so no scanner reads it
TS = "Use %s on staging please" % FAKE
QSHA = hashlib.sha256(TQ.encode()).hexdigest()[:12]
DIRECT = ("user", "USER", "user_sp", "uuid", "answer", "queue", "pasted", "mc", "ticket", "file")
H, N, U = "human", "not-human", "unknown"

# form: (trace state, offered and written with no outcome, offered and written with --outcome obsolete)
EXPECT = {
    "user": (H, True, False), "USER": (H, False, False), "user_sp": (H, False, False),
    "uuid": (H, True, False), "answer": (H, True, False), "queue": (H, True, False),
    "pasted": (N, False, False), "mc": (N, False, False), "ticket": (N, True, True),
    "file": (N, False, True),

    "wal>user": (H, False, False), "wal>USER": (H, False, False), "wal>user_sp": (H, False, False),
    "wal>uuid": (H, False, False), "wal>answer": (H, False, False), "wal>queue": (H, False, False),
    "wal>pasted": (N, False, False), "wal>mc": (U, False, False), "wal>ticket": (N, False, True),
    "wal>file": (N, False, True),

    "wal>wal>user": (H, False, False), "wal>wal>USER": (H, False, False), "wal>wal>user_sp": (H, False, False),
    "wal>wal>uuid": (H, False, False), "wal>wal>answer": (H, False, False), "wal>wal>queue": (H, False, False),
    "wal>wal>pasted": (N, False, False), "wal>wal>mc": (U, False, False), "wal>wal>ticket": (N, False, True),
    "wal>wal>file": (N, False, True),

    "inf>user": (H, False, False), "inf>USER": (H, False, False), "inf>user_sp": (H, False, False),
    "inf>uuid": (H, False, False), "inf>answer": (H, False, False), "inf>queue": (H, False, False),
    "inf>pasted": (N, False, False), "inf>mc": (U, False, False), "inf>ticket": (N, False, False),
    "inf>file": (N, False, False),

    "wal>inf>user": (H, False, False), "wal>inf>USER": (H, False, False), "wal>inf>user_sp": (H, False, False),
    "wal>inf>uuid": (H, False, False), "wal>inf>answer": (H, False, False), "wal>inf>queue": (H, False, False),
    "wal>inf>pasted": (N, False, False), "wal>inf>mc": (U, False, False), "wal>inf>ticket": (N, False, True),
    "wal>inf>file": (N, False, True),

    "wal>wal>inf>user": (H, False, False), "wal>wal>inf>USER": (H, False, False),
    "wal>wal>inf>user_sp": (H, False, False), "wal>wal>inf>uuid": (H, False, False),
    "wal>wal>inf>answer": (H, False, False), "wal>wal>inf>queue": (H, False, False),
    "wal>wal>inf>pasted": (N, False, False), "wal>wal>inf>mc": (U, False, False),
    "wal>wal>inf>ticket": (N, False, True), "wal>wal>inf>file": (N, False, True),

    "inf>wal>user": (H, False, False), "inf>wal>USER": (H, False, False), "inf>wal>user_sp": (H, False, False),
    "inf>wal>uuid": (H, False, False), "inf>wal>answer": (H, False, False), "inf>wal>queue": (H, False, False),
    "inf>wal>pasted": (N, False, False), "inf>wal>mc": (U, False, False), "inf>wal>ticket": (N, False, False),
    "inf>wal>file": (N, False, False),

    # the round 5 edges: a backed inferred: that still quotes a chat turn, a user turn that no longer resolves
    "wal>inf>user+ticket": (H, False, False), "wal>inf>pasted+ticket": (N, False, False),
    "wal>lost-user": (H, False, False),
    # round 6: every place a walk stops is unknown, never "not the user's"
    "wal>no-entry": (U, False, False), "wal>no-file": (U, False, False), "wal>malformed": (U, False, False),
    "wal>outside": (U, False, False), "wal>cycle": (U, False, False), "wal^9>ticket": (U, False, False),
    "wal>many": (U, False, False), "inf>inf": (U, False, False), "wal>inf>inf": (U, False, False),
    "wal>nonstring": (U, False, False), "wal>unsourced": (U, False, False), "wal>free-text": (U, False, False),
    "wal>bad-wal": (U, False, False), "wal>warn>no-file": (U, False, False), "wal>inf-short": (U, False, False),
    # round 6 controls: outcome evidence that resolves only weakly (refused by the enforce policy alone), and evidence
    # that does not resolve (refused under every policy)
    "wal>file-bare": (N, False, False), "wal>file-wrong": (N, False, False),
}
# where the walk stops, for every unknown form (each must appear in the listing's `incomplete` entry)
STOP_OF = {
    "wal>mc": "mc-not-allowed", "wal>wal>mc": "mc-not-allowed", "inf>mc": "mc-not-allowed",
    "wal>inf>mc": "mc-not-allowed", "wal>wal>inf>mc": "mc-not-allowed", "inf>wal>mc": "mc-not-allowed",
    "wal>no-entry": "wal-entry-not-found", "wal>no-file": "wal-missing", "wal>malformed": "wal-malformed",
    "wal>outside": "wal-bad-path", "wal>cycle": "cycle", "wal^9>ticket": "too-deep", "wal>many": "too-many-sources",
    "inf>inf": "inferred-no-inputs", "wal>inf>inf": "inferred-no-inputs", "wal>nonstring": "internal",
    "wal>unsourced": "wal-unsourced", "wal>free-text": "bad-syntax", "wal>bad-wal": "bad-syntax",
    "wal>warn>no-file": "wal-missing", "wal>inf-short": "inferred-no-rationale",
}
# hop zero: the evidence row's own `source` field, and where its walk stops (None: the row has no source key)
ZERO_SOURCES = {"row:no-key": None, "row:empty": "", "row:int": 12345, "row:list": ["answer"], "row:dict": {"user": 1},
                "row:free-text": "the user said so in chat", "close:no-key": None}
ZERO_STOP = {"row:no-key": "no-source", "row:empty": "no-source", "row:int": "bad-syntax", "row:list": "bad-syntax",
             "row:dict": "bad-syntax", "row:free-text": "bad-syntax", "close:no-key": "no-source"}
# the stop codes no cell above reaches: one needs a scan past its time budget, tested in process (StopCoverage); the
# others cannot be reached, each for the reason given. StopCoverage fails when a stop code is in none of the three.
IN_PROCESS = {"scan-timeout"}
UNREACHABLE = {
    "inferred-nested": "the outer split at the first unquoted ` -- ` leaves none in any input, so an inner inferred: "
                       "fails as inferred-no-inputs first (cells inf>inf and wal>inf>inf)",
    "tree-too-large": "MAX_RESOLVES caps a tree at far fewer nodes than the walker's bound of 4 * MAX_RESOLVES",
    "rejected": "the fallback text of a message when a result has no problem, never a code resolve() records",
}
# why a refused cell is refused, for the classes the reason must name (checked in the listing's `action`)
REASON = {"USER": "lowercase", "user_sp": "lowercase", "pasted": "pasted", "wal>lost-user": "human turn",
          "wal>inf>user+ticket": "human turn", "wal>inf>pasted+ticket": "human turn", "wal>pasted": "human turn",
          "wal>user": "human turn", "wal>queue": "human turn", "wal>no-entry": "cannot be read",
          "wal>outside": "cannot be read", "wal>no-file": "cannot be read", "wal>malformed": "cannot be read",
          "wal>cycle": "cycle", "wal^9>ticket": "too-deep", "wal>mc": "dashboard", "wal>file-bare": "unverified",
          "wal>file-wrong": "source rejected (excerpt-not-found)"}
OUTCOME_ONLY_REASON = {"wal>user", "wal>queue", "wal>lost-user", "wal>inf>user+ticket", "wal>inf>pasted+ticket",
                       "wal>pasted", "wal>cycle", "wal^9>ticket", "wal>no-entry", "wal>outside", "wal>no-file",
                       "wal>malformed", "wal>mc", "wal>file-bare", "wal>file-wrong"}
# what the WRITER says for an outcome close of a stop cell whose first hop it can read: the stop, before any policy
STOPPED = "the source could not be traced to its end"
WRITER_OUTCOME = {name: STOPPED for name in ("wal>cycle", "wal^9>ticket", "wal>many", "wal>inf>inf", "wal>nonstring",
                                             "wal>unsourced", "wal>free-text", "wal>bad-wal", "wal>warn>no-file",
                                             "wal>inf-short")}
WRITER_OUTCOME.update({"wal>mc": "dashboard", "wal>wal>mc": "dashboard", "wal>inf>mc": "dashboard",
                       "wal>wal>inf>mc": "dashboard"})


def at(minute):
    return "2026-11-23T10:%02d:00+00:00" % minute


def row(event, ident, minute, note, source=None, **extra):
    out = {"at": at(minute), "event": event, "id": ident, "note": note, **extra}
    if source is not None:
        out["source"] = source
    return out


def jsonl(rows):
    return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)


def card(uuid, use, minute, key, text):
    return [{"type": "assistant", "uuid": "%08d-0000-4000-8000-%012d" % (minute + 80, minute + 80),
             "timestamp": "2026-11-23T10:%02d:00Z" % minute,
             "message": {"content": [{"type": "tool_use", "id": use, "name": "AskUserQuestion", "input": {}}]}},
            {"type": "user", "uuid": uuid, "timestamp": "2026-11-23T10:%02d:30Z" % minute, "sessionId": S1,
             "toolUseResult": {"answers": {key: text}},
             "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use, "content": "answered"}]}}]


class Contract(unittest.TestCase):
    POLICY = None  # None: the installed provenance_policy.json (enforce); else the "ask" mode of a copied hooks tree
    ONLY = None  # None: every form; else the forms that get cells
    OVERRIDE = {}  # form: EXPECT row under this policy

    @classmethod
    def install_hooks(cls, home: Path) -> Path:
        if cls.POLICY is None:
            return HOOKS
        hooks = home / "hooks"
        shutil.copytree(HOOKS, hooks, ignore=shutil.ignore_patterns("__pycache__"))
        policy_file = hooks / "provenance_policy.json"
        policy = json.loads(policy_file.read_text())
        policy["wal"]["ask"] = cls.POLICY
        policy_file.write_text(json.dumps(policy))
        return hooks

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.home = home = Path(cls.tmp.name)
        cls.hooks = cls.install_hooks(home)
        cls.repo = home / "repo"
        cls.repo.mkdir()
        (cls.repo / "notes.txt").write_text(TF + "\n")
        git = ["git", "-C", str(cls.repo), "-c", "user.name=contract", "-c", "user.email=contract@example.invalid"]
        genv = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
        for args in (["init", "-q"], ["add", "notes.txt"], ["commit", "-q", "-m", "fixture"]):
            subprocess.run(git + args, env=genv, check=True, capture_output=True, timeout=60)
        sha = subprocess.run(git + ["rev-parse", "HEAD"], env=genv, check=True, capture_output=True, text=True,
                             timeout=60).stdout.strip()
        cache = home / ".agent-harness" / "provenance" / "tickets.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(json.dumps({"goodqa#777": {"title": "the release ask is obsolete"}}))
        cls.env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "AH_HOME": str(home),
                   "HARNESS_PROVENANCE_OFFLINE": "1", "HARNESS_PROVENANCE_REPO": str(cls.repo)}

        proj = home / ".claude" / "projects" / "-contract"
        proj.mkdir(parents=True)
        human = {"origin": {"kind": "human"}, "sessionId": S1}
        transcript = [
            {"type": "user", "uuid": U1, "timestamp": "2026-11-23T10:01:00Z", **human,
             "message": {"role": "user", "content": T1}},
            {"type": "user", "uuid": UP, "timestamp": "2026-11-23T10:02:00Z", **human,
             "message": {"role": "user", "content": "<pasted_content>%s</pasted_content>" % TP}},
            *card(ANS, ASK_USE, 3, "[ask:%s] Release?" % CARD_OK, TA),
            {"type": "queue-operation", "operation": "enqueue", "timestamp": STAMP, "sessionId": S1, "content": TQ},
            *card(ANS2, ASK_USE2, 5, "[ask:%s] Which login?" % CARD_SECRET, TS),
        ]
        (proj / (S1 + ".jsonl")).write_text(jsonl(transcript))
        (proj / (S2 + ".jsonl")).write_text("")
        cls.s1 = home / ".claude" / "wals" / S1 / "main.jsonl"
        cls.s2 = home / ".claude" / "wals" / S2 / "main.jsonl"
        cls.s1.parent.mkdir(parents=True)
        cls.s2.parent.mkdir(parents=True)
        outside = home / "elsewhere" / "main.jsonl"
        outside.parent.mkdir()
        outside.write_text(jsonl([row("decision", "w0000000e0a1", 2, "outside the root", "ticket:GoodQA goodqa#777")]))
        s4 = home / ".claude" / "wals" / S4 / "main.jsonl"
        s4.parent.mkdir(parents=True)
        s4.write_text('{"id":"w0000000bad1","event":"decision","note": broken\n')

        direct = {
            "user": f'user:{S1}/{U1} "{T1}"', "USER": f'USER:{S1}/{U1} "{T1}"', "user_sp": f'user :{S1}/{U1} "{T1}"',
            "uuid": f'uuid:{S1}/{U1} "{T1}"', "answer": f'answer:{S1}/{ANS} "{TA}"',
            "queue": f'queue:{S1}/{STAMP}#{QSHA} "{TQ}"', "pasted": f'pasted:{S1}/{UP} "{TP}"',
            "mc": f'mc:{S1}/dash-01ARZ3NDEKTSV4RRFFQ69G5FAV "Approve the release now"',
            "ticket": "ticket:GoodQA goodqa#777", "file": f'file:notes.txt:1@{sha} "{TF}"'}
        cls.direct = direct
        counter = iter(range(0x100, 0x10000))

        def new_id():
            return "w%011x" % next(counter)

        s2_rows, forms = [], dict(direct)
        base, hop2, inf = {}, {}, {}
        pointer = f"wal:{cls.s2}#"
        for name in DIRECT:
            base[name] = new_id()
            s2_rows.append(row("decision", base[name], 2, "evidence row", direct[name]))
        for name in DIRECT:
            hop2[name] = new_id()
            s2_rows.append(row("decision", hop2[name], 2, "pointer row", pointer + base[name]))
            inf[name] = new_id()
            s2_rows.append(row("decision", inf[name], 2, "inferred row", f"inferred: from {direct[name]} -- derived from that"))
            forms["wal>" + name] = pointer + base[name]
            forms["wal>wal>" + name] = pointer + hop2[name]
            forms["inf>" + name] = f"inferred: from {direct[name]} -- derived from that"
            forms["wal>inf>" + name] = pointer + inf[name]
            forms["inf>wal>" + name] = f"inferred: from {pointer}{base[name]} -- derived from that row"
        for name in DIRECT:  # two wal: hops, then inferred: (round 5 F1 case b: the origin is lost at the inferred: hop)
            ident = new_id()
            s2_rows.append(row("decision", ident, 2, "pointer row", pointer + inf[name]))
            forms["wal>wal>inf>" + name] = pointer + ident
        nested = "inferred: from inferred: from ticket:GoodQA goodqa#777 ; ticket:GoodQA goodqa#777 -- derived from that"
        many = "inferred: from " + " ; ".join([f"wal:{S2}/main.jsonl#{base['ticket']}"] * 25) + " -- derived from all"
        gone = f"wal:{home}/.claude/wals/{S3}/main.jsonl#w0000000aaa1"
        extra = {"wal>inf>user+ticket": f"inferred: from {direct['user']} ; {direct['ticket']} -- both say so",
                 "wal>inf>pasted+ticket": f"inferred: from {direct['pasted']} ; {direct['ticket']} -- both say so",
                 "wal>lost-user": f'user:{S1}/{ULOST} "{T1}"', "wal>many": many, "wal>inf>inf": nested,
                 "wal>nonstring": 12345, "wal>free-text": "the user said so in chat", "wal>bad-wal": "wal:no-entry-named",
                 "wal>inf-short": "inferred: from ticket:GoodQA goodqa#777 -- short",
                 "wal>file-bare": f"file:notes.txt:1@{sha}", "wal>file-wrong": f'file:notes.txt:1@{sha} "not that line"'}
        for name, source in extra.items():
            ident = new_id()
            s2_rows.append(row("decision", ident, 2, "edge row", source))
            forms[name] = pointer + ident
        ident = new_id()  # a row with no source at all, as the warn policy writes one (provenance: missing)
        s2_rows.append(row("decision", ident, 2, "a note written with no source", provenance="missing", unsourced=True))
        forms["wal>unsourced"] = pointer + ident
        ident = new_id()  # a row the warn policy kept although its source did not resolve, read on a host without it
        s2_rows.append(row("decision", ident, 2, "written under warn", gone, provenance="unverified", unsourced=True))
        forms["wal>warn>no-file"] = pointer + ident
        forms["inf>inf"] = nested
        forms["wal>no-entry"] = pointer + "w0000000dead"
        forms["wal>no-file"] = gone
        forms["wal>malformed"] = f"wal:{s4}#w0000000bad1"
        c1, c2 = new_id(), new_id()
        s2_rows += [row("decision", c1, 2, "cycle row", pointer + c2), row("decision", c2, 2, "cycle row", pointer + c1)]
        forms["wal>cycle"] = pointer + c1
        forms["wal>outside"] = f"wal:{outside}#w0000000e0a1"
        previous = base["ticket"]
        for _ in range(9):
            ident = new_id()
            s2_rows.append(row("decision", ident, 2, "deep row", pointer + previous))
            previous = ident
        forms["wal^9>ticket"] = pointer + previous
        assert set(forms) == set(EXPECT), sorted(set(forms) ^ set(EXPECT))
        cls.forms = forms

        # one ask per cell: a related-session close in each mode, and an answer row (no outcome)
        s1_rows, cls.cells = [row("ask", CARD_OK, 1, "card: release?"), row("ask", CARD_SECRET, 1, "card: login?")], {}
        for name in sorted(forms):
            if cls.ONLY is not None and name not in cls.ONLY:
                continue
            for mode in ("answer", "outcome", "row"):
                ask = new_id()
                cls.cells[ask] = (name, mode)
                s1_rows.append(row("ask", ask, 1, f"contract cell {name} {mode}"))
                if mode == "row":
                    s1_rows.append(row("decision", new_id(), 20, f"Answer to ask {ask}: the user answered", forms[name]))
                else:
                    s2_rows.append(row("ask_resolved", new_id(), 30, "closed in the successor", forms[name], ref=ask,
                                       **({"outcome": "obsolete"} if mode == "outcome" else {})))
        # ranking: a human answer that cannot be closed is never hidden behind an obsolete close that can (round 5),
        # and neither is an answer whose walk stopped (round 6, the two cells the R4 review named, and a tie)
        cls.rank = {key: new_id() for key in ("row", "lost", "super", "super_ctl", "missing", "tie")}
        s1_rows += [row("ask", ident, 1, f"ranking: {key}") for key, ident in cls.rank.items()]
        s1_rows.append(row("decision", new_id(), 25, f"Answer to ask {cls.rank['row']}: the user answered", forms["wal>user"]))
        s2_rows += [
            row("ask_resolved", new_id(), 30, "obsolete there", forms["wal>ticket"], ref=cls.rank["row"], outcome="obsolete"),
            row("ask_resolved", new_id(), 31, "obsolete there", forms["wal>ticket"], ref=cls.rank["lost"], outcome="obsolete"),
            row("ask_resolved", new_id(), 40, "obsolete there", forms["wal>lost-user"], ref=cls.rank["lost"],
                outcome="obsolete")]
        # R4 F1 cell 1: an answer row on an unreadable pointer, and a later SUPERSEDES ask that could be closed
        s1_rows.append(row("decision", new_id(), 25, f"Answer to ask {cls.rank['super']}: the user said no",
                           forms["wal>no-entry"]))
        for key in ("super", "super_ctl"):
            s1_rows.append(row("ask", new_id(), 26, f"SUPERSEDES {cls.rank[key]}: the release ask is replaced",
                               "ticket:GoodQA goodqa#777"))
        # R4 F1 cell 2: an outcome close on an unreadable pointer, and an earlier outcome close that could be written
        s2_rows += [
            row("ask_resolved", new_id(), 30, "obsolete there", forms["wal>ticket"], ref=cls.rank["missing"],
                outcome="obsolete"),
            row("ask_resolved", new_id(), 40, "obsolete there", forms["wal>no-entry"], ref=cls.rank["missing"],
                outcome="obsolete")]
        # a tie: two answer rows of one rank, the earlier traced to the user's whole turn, the later untraced
        s1_rows += [row("decision", new_id(), 21, f"Answer to ask {cls.rank['tie']}: the user answered", direct["user"]),
                    row("decision", new_id(), 22, f"Answer to ask {cls.rank['tie']}: the user answered",
                        forms["wal>no-entry"])]
        # round 6, hop zero (R4 F1 one hop earlier): an answer row whose OWN source cannot be walked (none, as the warn
        # policy writes one, empty, not a string, free text) next to an offerable obsolete close of the same ask; and
        # a close elsewhere with no source of its own after an offerable one
        cls.zero = {}
        for key, source in ZERO_SOURCES.items():
            ask = cls.zero[key] = new_id()
            s1_rows.append(row("ask", ask, 1, f"hop zero: {key}"))
            if key.startswith("row:"):
                s1_rows.append(row("decision", new_id(), 24, f"Answer to ask {ask}: the user said no", source))
                s2_rows.append(row("ask_resolved", new_id(), 30, "obsolete there", forms["wal>ticket"], ref=ask,
                                   outcome="obsolete"))
            else:
                s2_rows += [row("ask_resolved", new_id(), 30, "obsolete there", forms["wal>ticket"], ref=ask,
                                outcome="obsolete"),
                            row("ask_resolved", new_id(), 40, "obsolete there", source, ref=ask, outcome="obsolete")]
        cls.s1.write_text(jsonl(s1_rows))
        cls.s2.write_text(jsonl(s2_rows))
        cls.s1_before, cls.s2_before = cls.s1.read_bytes(), cls.s2.read_bytes()

        cls.code, cls.listing = cls.sweep()
        cls.s1_after_listing = cls.s1.read_bytes()  # checked in the four-way test: the listing writes nothing
        assert not cls.listing.get("unread") and not cls.listing.get("problem"), (cls.listing.get("unread"),
                                                                                 cls.listing.get("problem"))
        cls.items = {i["ask"]: i for i in cls.listing["evidence"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def sweep(cls, *args):
        p = subprocess.run([sys.executable, "-I", str(cls.hooks / "ask_sweep.py"), "--session", S1, "--related", S2,
                            *args], env=cls.env, capture_output=True, text=True, timeout=900)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            raise AssertionError("not JSON: %r %r" % (p.stdout[-400:], p.stderr[-400:]))

    def write(self, ask, source, mode):
        """(rc, the writer's JSON refusal or None): one close run by hand through this policy's wal_note.py."""
        argv = [sys.executable, str(self.hooks / "wal_note.py"), "--wal", str(self.s1), "--event", "ask_resolved",
                "--ref", ask, "--note", "by hand", "--source", source] + (["--outcome", "obsolete"] if mode == "outcome" else [])
        p = subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=120)
        try:
            doc = json.loads(p.stderr.strip().splitlines()[-1])
        except (ValueError, IndexError):
            doc = None
        return p.returncode, doc

    def expect(self, name):
        return self.OVERRIDE.get(name, EXPECT[name])

    def expected(self, name, mode):
        """(listed, offered) for one cell, from the literal EXPECT row: an answer row is listed when its source may be
        the user's (human or unknown) and offered only when it is and the answer mode accepts it."""
        state, answer, outcome = self.expect(name)
        if mode == "row":
            return state != N, state == H and answer
        return True, answer if mode == "answer" else outcome

    # ------------------------------------------------------------------ the four-way check, in one ordered test

    def test_every_cell_the_listing_offers_is_written_and_every_other_is_refused_by_the_writer(self):
        offered, manual = [], []
        for ask, (name, mode) in sorted(self.cells.items()):
            listed, offer = self.expected(name, mode)
            item = self.items.get(ask)
            if item is not None:  # carried on by the EXPECTED verdict, so a listing mistake cannot skip the writer checks
                (offered if offer else manual).append((ask, item))
            with self.subTest(form=name, mode=mode):
                self.assertEqual(item is not None, listed, f"{name} {mode} listed")
                if item is None:
                    continue
                self.assertEqual(not item["manual"], offer, f"{name} {mode}: {item.get('action')}")
                if offer:
                    self.assertTrue(item["close"] and item["apply"])
                else:
                    self.assertEqual((item["close"], item["apply"]), (None, None))
                    self.assertTrue(item.get("action"))
                    reason = REASON.get(name)
                    if reason and (mode == "outcome" or name not in OUTCOME_ONLY_REASON) and mode != "row":
                        self.assertIn(reason, item["action"], f"{name} {mode}")
                    if self.expect(name)[0] == U:
                        self.assertIn("could not be traced to its end", item["action"], f"{name} {mode}")
        self.assertEqual(self.s1_after_listing, self.s1_before)  # the listing writes nothing
        # every later byte check is against this test's own start, so a close another test's --apply wrote (on a
        # broken variant) cannot hide this test's own findings
        start = self.s1.read_bytes()

        # 2. the writer refuses each expected-manual close run by hand (once per source and mode), whatever was
        # listed: status REFUSED, and its problem is the one the listing quotes for that cell (R4 F4)
        jobs, seen = [], set()
        for ask, (name, mode) in sorted(self.cells.items()):
            listed, offer = self.expected(name, mode)
            key = (name, "answer" if mode == "row" else mode)
            if listed and not offer and key not in seen:
                seen.add(key)
                jobs.append((ask, name, key[1]))
        with ThreadPoolExecutor(max_workers=8) as pool:
            done = list(pool.map(lambda j: (j, self.write(j[0], self.forms[j[1]], j[2])), jobs))
        for (ask, name, mode), (rc, doc) in done:
            with self.subTest(form=name, mode=mode, writer=True):
                self.assertEqual(rc, 2, f"wal_note wrote {name} {mode}")
                self.assertEqual((doc or {}).get("status"), "REFUSED", doc)
                item = self.items.get(ask)
                if item is not None:
                    self.assertIn(doc["problem"], item["action"])
                if mode == "outcome" and name in WRITER_OUTCOME:
                    self.assertIn(WRITER_OUTCOME[name], doc["problem"])
        self.assertEqual(self.s1.read_bytes(), start)

        # 3. --apply refuses every manual cell (rc 3, the manual reason) and writes nothing
        code, doc = self.sweep("--apply", "--only", *[i["pin"] for _a, i in manual])
        for entry in doc["closed"]:
            name, mode = self.cells[entry["ask"]]
            with self.subTest(form=name, mode=mode, apply_manual=True):
                self.assertEqual(entry["rc"], 3, entry)
                self.assertTrue(entry["refused"].startswith("manual:"), entry)  # not an unread refusal
        self.assertEqual((code, len(doc["closed"])), (1, len(manual)))
        self.assertEqual(self.s1.read_bytes(), start)

        # 4. every offered cell is written by the real wal_note through ask_sweep --apply, although some walks of
        # other asks stopped (an incomplete walk makes only the asks it is evidence for manual)
        self.assertTrue(offered)
        code, doc = self.sweep("--apply", "--only", *[i["pin"] for _a, i in offered])
        self.assertEqual((code, sorted(c["rc"] for c in doc["closed"])), (0, [0] * len(offered)), json.dumps(doc["closed"])[:2000])
        new = [json.loads(x) for x in self.s1.read_bytes()[len(start):].decode().splitlines()]
        self.assertEqual(sorted(r["ref"] for r in new), sorted(a for a, _i in offered))
        for r in new:
            name, mode = self.cells[r["ref"]]
            with self.subTest(form=name, mode=mode, written=True):
                self.assertEqual(r["source"], self.forms[name])
                self.assertEqual(r.get("outcome"), "obsolete" if mode == "outcome" else None)
                self.assertEqual(r.get("closed_by"), "agent" if mode == "outcome" else "ask-sweep")
                self.assertNotIn("decision", r)
        self.assertEqual(self.s2.read_bytes(), self.s2_before)

    def test_every_walk_that_stopped_is_listed_as_incomplete_and_the_listing_exits_2(self):
        # R4 F1: "could not tell" was dropped silently and the listing exited 0
        self.assertEqual(self.code, 2)
        got = {}
        for entry in self.listing["incomplete"]:
            got.setdefault(entry["ask"], set()).update(entry["stops"])
        want = {ask for ask, (name, mode) in self.cells.items() if self.expect(name)[0] == U}
        want |= {self.rank[k] for k in ("super", "missing", "tie")} | set(self.zero.values())
        self.assertEqual(set(got), want)
        for ask, (name, mode) in self.cells.items():
            if ask in want:
                with self.subTest(form=name, mode=mode):
                    self.assertIn(STOP_OF[name], got[ask])
        for key, ask in self.zero.items():
            with self.subTest(hop_zero=key):
                self.assertIn(ZERO_STOP[key], got.get(ask, ()))
        self.assertTrue(STOP_OF.keys() <= set(EXPECT) and {n for n, e in EXPECT.items() if e[0] == U} <= STOP_OF.keys())

    def test_a_human_answer_that_cannot_be_closed_is_never_hidden_behind_an_obsolete_close(self):
        # an answer row that reaches the user's words through a wal: hop outranks an offerable obsolete close
        item = self.items[self.rank["row"]]
        self.assertEqual((item["kind"], item["manual"], item["close"]), ("answer", True, None))
        # an outcome close whose evidence reaches a user turn that no longer resolves still ranks as the user's answer
        item = self.items[self.rank["lost"]]
        self.assertEqual((item["kind"], item["manual"], item["close"]), ("resolved-elsewhere", True, None))
        self.assertEqual(item["evidence"][0]["source"], self.forms["wal>lost-user"])
        self.assertIn("human turn", item["action"])

    def test_an_answer_whose_walk_stopped_is_never_hidden_behind_an_obsolete_close(self):
        # each cell in its own subTest, so each shows its own failure (failing first, round 6)
        start = self.s1.read_bytes()
        with self.subTest(cell="super_ctl"):  # the control: the SUPERSEDES ask alone is offered
            ctl = self.items[self.rank["super_ctl"]]
            self.assertEqual((ctl["kind"], ctl["manual"], bool(ctl["close"])), ("superseded", False, True))
        with self.subTest(cell="super"):  # R4 F1 cell 1: not over an untraced answer row
            item = self.items[self.rank["super"]]
            self.assertEqual((item["kind"], item["manual"], item["close"], item["apply"]), ("answer", True, None, None))
            self.assertEqual([e["kind"] for e in item["evidence"]], ["answer", "superseded"])
            self.assertIn("could not be traced to its end (wal-entry-not-found)", item["action"])
        with self.subTest(cell="missing"):  # R4 F1 cell 2: an untraced outcome close outranks an earlier writable one
            item = self.items[self.rank["missing"]]
            self.assertEqual((item["kind"], item["manual"], item["close"]), ("resolved-elsewhere", True, None))
            self.assertEqual(item["evidence"][0]["source"], self.forms["wal>no-entry"])
            self.assertEqual(item["evidence"][1]["source"], self.forms["wal>ticket"])
        with self.subTest(cell="tie"):  # a tie of rank: the untraced answer comes first, so nothing is closed
            item = self.items[self.rank["tie"]]
            self.assertEqual((item["kind"], item["manual"], item["close"]), ("answer", True, None))
            self.assertEqual([e["source"] for e in item["evidence"]], [self.forms["wal>no-entry"], self.direct["user"]])
        # and --apply refuses each of them, writing nothing
        code, doc = self.sweep("--apply", "--only", *[self.items[self.rank[k]]["pin"] for k in ("super", "missing", "tie")])
        self.assertEqual((code, sorted(c["rc"] for c in doc["closed"])), (1, [3, 3, 3]))
        self.assertEqual(self.s1.read_bytes(), start)

    def test_evidence_whose_own_source_cannot_be_walked_is_never_skipped(self):
        # round 6, hop zero: an answer row with no source, an empty one, a non-string or free text is unknown evidence,
        # ranked ahead of the offerable obsolete close of the same ask; so is a close elsewhere with no source
        start = self.s1.read_bytes()
        for key, ask in sorted(self.zero.items()):
            with self.subTest(hop_zero=key):
                item = self.items.get(ask)
                self.assertIsNotNone(item, "not listed")
                best = item["evidence"][0]
                self.assertEqual(item["kind"], "resolved-elsewhere" if key.startswith("close:") else "answer")
                self.assertEqual((item["manual"], item["close"], best.get("unknown"), best.get("stops")),
                                 (True, None, True, [ZERO_STOP[key]]))
                self.assertIn("could not be traced to its end", item["action"])
                self.assertEqual(item["evidence"][1]["source"], self.forms["wal>ticket"])  # the close it outranks
        code, doc = self.sweep("--apply", "--only", *[self.items[a]["pin"] for a in self.zero.values() if a in self.items])
        self.assertEqual((code, sorted(c["rc"] for c in doc["closed"])), (1, [3] * len(self.zero)))
        self.assertEqual(self.s1.read_bytes(), start)

    def test_an_answer_card_gets_a_close_only_when_the_writer_would_write_it(self):
        # R4 F3: a card is checked by the same precheck as WAL evidence; one holding a credential is never printed
        answered = {a["ask"]: a for a in self.listing["answered"]}
        short = {a["ask"]: a for a in self.listing["short"]}
        self.assertTrue(answered[CARD_OK]["close"])  # the control: a clean card is offered
        self.assertNotIn(CARD_SECRET, answered)
        self.assertIn("credential", short[CARD_SECRET]["reason"])
        self.assertNotIn("source", short[CARD_SECRET])
        self.assertNotIn(FAKE.split("=")[1], json.dumps(self.listing))
        rc, doc = self.write(CARD_SECRET, f'answer:{S1}/{ANS2} "{TS}"', "answer")
        self.assertEqual((rc, (doc or {}).get("status")), (2, "REFUSED"))
        self.assertIn("credential", doc["problem"])
        self.assertNotIn(FAKE.split("=")[1], json.dumps(doc))

    def test_surrounding_whitespace_is_the_same_source_for_the_writer_and_the_listing(self):
        if self.POLICY is not None:
            self.skipTest("policy-independent: runs in Contract")
        # wal_note strips the source before it writes it, so " user:..." is the user: spelling: the verdict in every
        # mode, and the card preference, must be the plain spelling's (a strict reviewer's next spelling case)
        code = ("import json, sys; sys.path.insert(0, sys.argv[1]); import ask_close; out = {}\n"
                "for name, src in json.loads(sys.argv[2]).items():\n"
                "    for mode in ask_close.MODES:\n"
                "        plain = ask_close.close_verdict(src, mode, 'w0000000beef')['problem']\n"
                "        padded = ask_close.close_verdict('  ' + src + '\\n', mode, 'w0000000beef')['problem']\n"
                "        out[name + ' ' + mode] = [plain, padded]\n"
                "    out[name + ' card'] = [ask_close.is_card(src), ask_close.is_card(' ' + src)]\n"
                "print(json.dumps(out))")
        names = ("user", "USER", "user_sp", "answer", "queue", "pasted", "ticket", "file")
        p = subprocess.run([sys.executable, "-I", "-c", code, str(HOOKS), json.dumps({n: self.direct[n] for n in names})],
                           env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-600:])
        out = json.loads(p.stdout)
        self.assertEqual(len(out), len(names) * 4)
        for cell, (plain, padded) in sorted(out.items()):
            with self.subTest(cell=cell):
                self.assertEqual(padded, plain)
        self.assertIsNone(out["user answer"][0])  # not vacuous: the plain spelling is accepted ...
        self.assertTrue(out["USER answer"][0])  # ... and a misspelling refused, padded or not
        self.assertEqual(out["answer card"], [True, True])

    def test_provenance_reads_every_word_as_the_table_says(self):
        if self.POLICY is not None:
            self.skipTest("policy-independent: runs in Contract")
        import ask_close  # noqa: PLC0415
        import provenance  # noqa: PLC0415
        self.assertEqual(set(provenance.SOURCE_WORDS), WORDS)
        for name, source in self.direct.items():
            with self.subTest(form=name):
                self.assertEqual(provenance.claimed_kind(source), provenance.parse_source(source)["kind"])
        for word, rowd in ask_close.TABLE.items():
            self.assertEqual(provenance.SOURCE_WORDS[word], rowd["kind"], word)
        self.assertEqual(set(ask_close.TABLE), set(provenance.SOURCE_WORDS))
        self.assertEqual(ask_close.HUMAN_KINDS, {"user"})
        self.assertEqual(ask_close.CHAT_KINDS, {"user", "pasted"})


class ContractAskOff(Contract):
    """The same cells under an installed policy file with `"ask": "off"` (R4 F2): no policy turns an incomplete walk,
    or outcome evidence that does not resolve, into a close. wal>file-bare is the positive control: the enforce policy
    alone refuses it, so here it is written, which shows this policy file is the one in force."""
    POLICY = "off"
    ONLY = {n for n, e in EXPECT.items() if e[0] == U} | {"wal>ticket", "wal>file-bare", "wal>file-wrong", "ticket"}
    OVERRIDE = {"wal>file-bare": (N, False, True)}


# ---------------------------------------------------------------------- no private list of source kinds

GUARDED = ("ask_evidence.py", "ask_sweep.py", "wal_note.py", "ask_reminders.py")
WORDS = {"user", "uuid", "answer", "queue", "pasted", "mc", "ticket", "wal", "file", "inferred"}  # provenance.SOURCE_WORDS
PATTERN_CALLS = {"startswith", "endswith", "match", "search", "fullmatch", "compile", "findall", "sub", "split"}
# a transcript record's own role or type field ("user", "assistant") is not a source kind
RECORD_FIELD = re.compile(r"""(\.get\(\s*['"](type|role)['"]\s*\)|\[\s*['"](type|role)['"]\s*\])$""")


def private_kind_lists(text: str, name: str) -> list:
    """Every place in this module source that decides on source kinds itself: a source word compared as a string
    (unless it is compared with a record's `type` or `role` field), a collection of two or more source words, or a
    string pattern naming a source word with its colon."""
    named = re.compile(r"(?i)(?<![A-Za-z0-9_])(" + "|".join(sorted(WORDS)) + r")(\\s\*|\s*)(:|\|)")
    found = []
    for node in ast.walk(ast.parse(text, name)):
        if isinstance(node, ast.Compare):
            values = [node.left, *node.comparators]
            others = [ast.unparse(v) for v in values if not isinstance(v, (ast.Constant, ast.Tuple, ast.List, ast.Set))]
            if any(RECORD_FIELD.search(o) for o in others):
                continue
            for value in values:
                if isinstance(value, ast.Constant) and value.value in WORDS:
                    found.append((node.lineno, f"compares with {value.value!r}"))
                if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
                    words = [e.value for e in value.elts if isinstance(e, ast.Constant) and e.value in WORDS]
                    if words:
                        found.append((node.lineno, f"compares with {words}"))
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            words = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                     and (e.value in WORDS or e.value.rstrip(":").lower() in WORDS and e.value.endswith(":"))]
            if len(words) >= 2:
                found.append((node.lineno, f"lists {words}"))
        elif isinstance(node, ast.Call):
            func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            if func in PATTERN_CALLS:
                for arg in ast.walk(ast.Tuple(elts=list(node.args), ctx=ast.Load())):
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and named.search(arg.value):
                        found.append((node.lineno, f"{func}({arg.value[:40]!r})"))
    return found


def _values(node):
    """The strings an expression can evaluate to: a constant, or either branch of `a if cond else b` (never the
    condition's own operands)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, ast.IfExp):
        yield from _values(node.body)
        yield from _values(node.orelse)


def reported_codes(text: str) -> set:
    """Every problem code a module can report: the first argument of Problem(...), a "code" value in a dict, and the
    strings a name `code` is assigned."""
    codes = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Problem" and node.args:
            codes.update(_values(node.args[0]))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "code":
                    codes.update(_values(value))
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "code" for t in node.targets):
            codes.update(_values(node.value))
    return codes


class NoPrivateKindList(unittest.TestCase):
    def test_no_module_that_decides_ask_closes_keeps_its_own_list_of_source_kinds(self):
        for name in GUARDED:
            with self.subTest(module=name):
                self.assertEqual(private_kind_lists((HOOKS / name).read_text(), name), [])

    def test_the_guard_catches_each_form_of_a_private_list(self):
        for line in ('HUMAN = ("user", "pasted")', 'ok = kind == "user"', 'ok = kind in ("ticket", "x")',
                     'ok = head == "user"', 'ok = "wal" != parts[0]', 'ok = s.startswith("user:")',
                     'import re\nok = re.match(r"^(wal:|file:)", s)', 'import re\nH = re.compile(r"(?i)(user|answer|uuid)\\s*:")',
                     'P = ["answer:", "queue:"]'):
            with self.subTest(line=line):
                self.assertNotEqual(private_kind_lists(line + "\n", "probe.py"), [])
        self.assertEqual(private_kind_lists('kinds = {"answer": 1, "terminal": 4}\nx = "manual: read it"\n'
                                            'ok = rec.get("type") == "user"\nok = msg["role"] != "user"\n', "probe.py"), [])


class EveryCodeIsClassified(unittest.TestCase):
    """#170 round 6: a code provenance can report is either an end of the walk at an origin (END_CODES) or a stop
    (STOP_CODES); an unclassified code stops the walk (fail closed) and fails this test until it is classified."""

    def test_every_problem_code_provenance_reports_is_an_end_or_a_stop(self):
        import provenance  # noqa: PLC0415
        codes = reported_codes((HOOKS / "provenance.py").read_text())
        self.assertGreater(len(codes), 30)
        self.assertEqual(codes - provenance.END_CODES - provenance.STOP_CODES, set())
        self.assertEqual(provenance.END_CODES & provenance.STOP_CODES, set())

    def test_the_classifier_fails_closed(self):
        import provenance  # noqa: PLC0415
        self.assertEqual(reported_codes('raise Problem("brand-new", "x")\n'), {"brand-new"})
        self.assertEqual(reported_codes('code = "one-code" if kind == "wal" else "two-code"\nd = {"code": "three"}\n'),
                         {"one-code", "two-code", "three"})
        self.assertTrue(provenance.stops_walk("brand-new", "ticket:GoodQA goodqa#1"))  # unclassified: a stop
        self.assertFalse(provenance.stops_walk("ticket-missing", "ticket:GoodQA goodqa#1"))  # an origin that failed
        self.assertTrue(provenance.stops_walk("bad-syntax", "wal:no-entry-named"))  # a pointer: what it names is unknown
        self.assertTrue(provenance.stops_walk("bad-syntax", "the user said so"))  # a source that names no kind


class StopCoverage(unittest.TestCase):
    """Every stop code once (#170 round 6): each is reached by a contract cell (STOP_OF), by a test here (IN_PROCESS),
    or is named unreachable with its reason (UNREACHABLE)."""

    def test_every_stop_code_has_a_cell_a_test_or_a_reason(self):
        import provenance  # noqa: PLC0415
        covered = set(STOP_OF.values())
        self.assertEqual(provenance.STOP_CODES - covered - IN_PROCESS - set(UNREACHABLE), set())
        self.assertEqual((IN_PROCESS | set(UNREACHABLE)) & covered, set())
        self.assertTrue((IN_PROCESS | set(UNREACHABLE)) <= provenance.STOP_CODES)

    def test_a_scan_past_its_time_budget_is_a_stop_under_any_policy(self):
        import ask_close  # noqa: PLC0415
        import provenance  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "wals" / S2 / "main.jsonl"
            wal.parent.mkdir(parents=True)
            wal.write_text(jsonl([row("decision", "w00000000a01", 1, "obsolete there", "ticket:GoodQA goodqa#777")]))
            source = f"wal:{S2}/main.jsonl#w00000000a01"
            control = ask_close.trace(source, tmp)
            self.assertEqual((control["state"], control["stops"]), ("not-human", []))  # the scan completes
            saved = provenance.SCAN_SECONDS, provenance.load_policy
            provenance.SCAN_SECONDS = -1.0  # every scan is past its budget before it reads a byte
            provenance.load_policy = lambda *_a, **_k: {"wal": {"ask": "off"}}
            try:
                traced = ask_close.trace(source, tmp)
                verdict = ask_close.close_verdict(source, "outcome", "w00000000a02", tmp)
            finally:
                provenance.SCAN_SECONDS, provenance.load_policy = saved
        # the round 6 behaviour is the trace: unknown, so ask_sweep ranks it as a possible answer
        self.assertEqual((traced["state"], traced["maybe_human"], traced["stops"]), ("unknown", True, ["scan-timeout"]))
        # the refusal here comes from the outcome check's own read of the first hop, which predates round 6
        self.assertIn("scan-timeout", verdict["problem"] or "")


if __name__ == "__main__":
    unittest.main()
