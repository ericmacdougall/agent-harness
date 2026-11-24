"""#170 round 5 (main's redesign ruling, CRITICAL class): the contract between the listing and the writer.

ask_sweep.py offers a close only when wal_note.py would write it, and every close it does not offer, wal_note refuses.
Both run ask_close.close_verdict, so agreement alone would be vacuous: each cell below has its expected verdict written
out literally, and the test checks it three ways, with nothing stubbed (real ask_sweep.py, wal_note.py and provenance as
subprocesses under a temporary HOME holding synthetic WALs, a transcript, a ticket cache and a git repository):

1. the listing: offered (a close is printed) or manual (no close, the reason in `action`);
2. the writer: a manual cell's close, run by hand through wal_note.py, must be refused with rc 2 and write nothing;
3. `ask_sweep --apply` on a manual cell refuses with rc 3 and writes nothing;
4. an offered close is applied through `ask_sweep --apply` and must write exactly one row, with no decision.

Cells: every source word and spelling (user:, USER:, `user :`, uuid:, answer:, queue:, pasted:, mc:, ticket:, file:),
each also behind one and two wal: hops, behind inferred:, behind wal: then inferred:, and behind inferred: then wal:; in
both close modes ask_sweep uses (no outcome, and --outcome obsolete); as a related-session close and, for the answer
mode, as an answer row. Plus the edges a strict reviewer raises next: an inferred: backed by a ticket that also quotes the
user or pasted text, a pointer to a user turn that no longer resolves, a missing entry, a cycle, a path outside
~/.claude/wals, a chain deeper than provenance's limit, and the ranking cells (a human answer that cannot be closed is
never hidden behind an obsolete close that can).

The AST guard at the end keeps every private list of source kinds out of the modules that decide ask closes; only
ask_close.TABLE (over provenance.SOURCE_WORDS) holds one.

Run: python3 -I tests/test_ask_close_contract.py
"""
import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
# ask_close and provenance are imported inside the tests that read them, so the cell test (subprocesses only) also runs
# against an older tree for the failing-first evidence

S1 = "aaaaaaaa-1111-4111-8111-00000000c0a1"
S2 = "bbbbbbbb-2222-4222-8222-00000000c0a2"
U1, UP, ANS, ULOST = ("%08d-0000-4000-8000-%012d" % (n, n) for n in (71, 72, 73, 79))
ASK_USE = "toolu_CONTRACT000001"
STAMP = "2026-11-23T10:04:00.000Z"
T1 = "Close the release ask, it is done"
TA = "Yes, close it today please"
TQ = "Close the queued release ask now"
TP = "Ticket notes say the release ask is finished"
TF = "the release ask is obsolete now"
QSHA = hashlib.sha256(TQ.encode()).hexdigest()[:12]
DIRECT = ("user", "USER", "user_sp", "uuid", "answer", "queue", "pasted", "mc", "ticket", "file")

# form: (reaches the user's own words, offered and written with no outcome, offered and written with --outcome obsolete)
EXPECT = {
    "user": (True, True, False), "USER": (True, False, False), "user_sp": (True, False, False),
    "uuid": (True, True, False), "answer": (True, True, False), "queue": (True, True, False),
    "pasted": (False, False, False), "mc": (False, False, False), "ticket": (False, True, True),
    "file": (False, False, True),

    "wal>user": (True, False, False), "wal>USER": (True, False, False), "wal>user_sp": (True, False, False),
    "wal>uuid": (True, False, False), "wal>answer": (True, False, False), "wal>queue": (True, False, False),
    "wal>pasted": (False, False, False), "wal>mc": (False, False, False), "wal>ticket": (False, False, True),
    "wal>file": (False, False, True),

    "wal>wal>user": (True, False, False), "wal>wal>USER": (True, False, False), "wal>wal>user_sp": (True, False, False),
    "wal>wal>uuid": (True, False, False), "wal>wal>answer": (True, False, False), "wal>wal>queue": (True, False, False),
    "wal>wal>pasted": (False, False, False), "wal>wal>mc": (False, False, False), "wal>wal>ticket": (False, False, True),
    "wal>wal>file": (False, False, True),

    "inf>user": (True, False, False), "inf>USER": (True, False, False), "inf>user_sp": (True, False, False),
    "inf>uuid": (True, False, False), "inf>answer": (True, False, False), "inf>queue": (True, False, False),
    "inf>pasted": (False, False, False), "inf>mc": (False, False, False), "inf>ticket": (False, False, False),
    "inf>file": (False, False, False),

    "wal>inf>user": (True, False, False), "wal>inf>USER": (True, False, False), "wal>inf>user_sp": (True, False, False),
    "wal>inf>uuid": (True, False, False), "wal>inf>answer": (True, False, False), "wal>inf>queue": (True, False, False),
    "wal>inf>pasted": (False, False, False), "wal>inf>mc": (False, False, False), "wal>inf>ticket": (False, False, True),
    "wal>inf>file": (False, False, True),

    "wal>wal>inf>user": (True, False, False), "wal>wal>inf>USER": (True, False, False),
    "wal>wal>inf>user_sp": (True, False, False), "wal>wal>inf>uuid": (True, False, False),
    "wal>wal>inf>answer": (True, False, False), "wal>wal>inf>queue": (True, False, False),
    "wal>wal>inf>pasted": (False, False, False), "wal>wal>inf>mc": (False, False, False),
    "wal>wal>inf>ticket": (False, False, True), "wal>wal>inf>file": (False, False, True),

    "inf>wal>user": (True, False, False), "inf>wal>USER": (True, False, False), "inf>wal>user_sp": (True, False, False),
    "inf>wal>uuid": (True, False, False), "inf>wal>answer": (True, False, False), "inf>wal>queue": (True, False, False),
    "inf>wal>pasted": (False, False, False), "inf>wal>mc": (False, False, False), "inf>wal>ticket": (False, False, False),
    "inf>wal>file": (False, False, False),

    # the edges: a backed inferred: that still quotes a chat turn, a user turn that no longer resolves, unreadable,
    # cyclic, outside and too-deep pointers
    "wal>inf>user+ticket": (True, False, False), "wal>inf>pasted+ticket": (False, False, False),
    "wal>lost-user": (True, False, False), "wal>missing": (False, False, False), "wal>cycle": (False, False, False),
    "wal>outside": (False, False, False), "wal^9>ticket": (False, False, False),
}
# why a refused cell is refused, for the classes the reason must name (checked in the listing's `action`)
REASON = {"USER": "lowercase", "user_sp": "lowercase", "pasted": "pasted", "wal>lost-user": "human turn",
          "wal>inf>user+ticket": "human turn", "wal>inf>pasted+ticket": "human turn", "wal>pasted": "human turn",
          "wal>user": "human turn", "wal>queue": "human turn", "wal>missing": "cannot be read",
          "wal>outside": "cannot be read", "wal>cycle": "cycle", "wal^9>ticket": "too-deep"}
OUTCOME_ONLY_REASON = {"wal>user", "wal>queue", "wal>lost-user", "wal>inf>user+ticket", "wal>inf>pasted+ticket",
                       "wal>pasted", "wal>cycle", "wal^9>ticket", "wal>missing", "wal>outside"}


def at(minute):
    return "2026-11-23T10:%02d:00+00:00" % minute


def row(event, ident, minute, note, source=None, **extra):
    out = {"at": at(minute), "event": event, "id": ident, "note": note, **extra}
    if source:
        out["source"] = source
    return out


def jsonl(rows):
    return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)


class Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.home = home = Path(cls.tmp.name)
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
            {"type": "assistant", "uuid": "%08d-0000-4000-8000-%012d" % (74, 74), "timestamp": "2026-11-23T10:03:00Z",
             "message": {"content": [{"type": "tool_use", "id": ASK_USE, "name": "AskUserQuestion", "input": {}}]}},
            {"type": "user", "uuid": ANS, "timestamp": "2026-11-23T10:03:30Z", "sessionId": S1,
             "toolUseResult": {"answers": {"[ask:w0000000fff0] Release?": TA}},
             "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": ASK_USE,
                                                      "content": "answered"}]}},
            {"type": "queue-operation", "operation": "enqueue", "timestamp": STAMP, "sessionId": S1, "content": TQ},
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
        extra = {"wal>inf>user+ticket": f"inferred: from {direct['user']} ; {direct['ticket']} -- both say so",
                 "wal>inf>pasted+ticket": f"inferred: from {direct['pasted']} ; {direct['ticket']} -- both say so",
                 "wal>lost-user": f'user:{S1}/{ULOST} "{T1}"'}
        for name, source in extra.items():
            ident = new_id()
            s2_rows.append(row("decision", ident, 2, "edge row", source))
            forms[name] = pointer + ident
        forms["wal>missing"] = pointer + "w0000000dead"
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
        s1_rows, cls.cells = [], {}
        for name in sorted(forms):
            for mode in ("answer", "outcome", "row"):
                ask = new_id()
                cls.cells[ask] = (name, mode)
                s1_rows.append(row("ask", ask, 1, f"contract cell {name} {mode}"))
                if mode == "row":
                    s1_rows.append(row("decision", new_id(), 20, f"Answer to ask {ask}: the user answered", forms[name]))
                else:
                    s2_rows.append(row("ask_resolved", new_id(), 30, "closed in the successor", forms[name], ref=ask,
                                       **({"outcome": "obsolete"} if mode == "outcome" else {})))
        # ranking: a human answer that cannot be closed is never hidden behind an obsolete close that can
        cls.rank_row, cls.rank_lost = new_id(), new_id()
        s1_rows += [row("ask", cls.rank_row, 1, "ranking: answer row"), row("ask", cls.rank_lost, 1, "ranking: lost user")]
        s1_rows.append(row("decision", new_id(), 25, f"Answer to ask {cls.rank_row}: the user answered", forms["wal>user"]))
        s2_rows += [
            row("ask_resolved", new_id(), 30, "obsolete there", forms["wal>ticket"], ref=cls.rank_row, outcome="obsolete"),
            row("ask_resolved", new_id(), 31, "obsolete there", forms["wal>ticket"], ref=cls.rank_lost, outcome="obsolete"),
            row("ask_resolved", new_id(), 40, "obsolete there", forms["wal>lost-user"], ref=cls.rank_lost, outcome="obsolete")]
        cls.s1.write_text(jsonl(s1_rows))
        cls.s2.write_text(jsonl(s2_rows))
        cls.s1_before, cls.s2_before = cls.s1.read_bytes(), cls.s2.read_bytes()

        code, cls.listing = cls.sweep()
        assert code == 0, (code, cls.listing.get("unread"), cls.listing.get("problem"))
        cls.items = {i["ask"]: i for i in cls.listing["evidence"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def sweep(cls, *args):
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ask_sweep.py"), "--session", S1, "--related", S2, *args],
                           env=cls.env, capture_output=True, text=True, timeout=600)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            raise AssertionError("not JSON: %r %r" % (p.stdout[-400:], p.stderr[-400:]))

    def expected(self, name, mode):
        """(listed, offered) for one cell, from the literal EXPECT row."""
        human, answer, outcome = EXPECT[name]
        if mode == "row":
            return human, human and answer
        return True, answer if mode == "answer" else outcome

    def note(self, ask, name, mode, source):
        argv = [sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.s1), "--event", "ask_resolved", "--ref", ask,
                "--note", "by hand", "--source", source] + (["--outcome", "obsolete"] if mode == "outcome" else [])
        p = subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=120)
        return name, mode, p.returncode, p.stderr

    # ------------------------------------------------------------------ the three-way check, in one ordered test

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
        self.assertEqual(self.s1.read_bytes(), self.s1_before)  # the listing writes nothing

        # 2. the writer refuses each expected-manual close run by hand (once per source and mode), whatever was listed
        jobs, seen = [], set()
        for ask, (name, mode) in sorted(self.cells.items()):
            listed, offer = self.expected(name, mode)
            key = (name, "answer" if mode == "row" else mode)
            if listed and not offer and key not in seen:
                seen.add(key)
                jobs.append((ask, name, key[1], self.forms[name]))
        with ThreadPoolExecutor(max_workers=8) as pool:
            for name, mode, rc, err in pool.map(lambda j: self.note(*j), jobs):
                with self.subTest(form=name, mode=mode, writer=True):
                    self.assertEqual(rc, 2, f"wal_note wrote {name} {mode}: {err[-300:]}")
        self.assertEqual(self.s1.read_bytes(), self.s1_before)

        # 3. --apply refuses every manual cell (rc 3, the manual reason) and writes nothing
        code, doc = self.sweep("--apply", "--only", *[i["pin"] for _a, i in manual])
        for entry in doc["closed"]:
            name, mode = self.cells[entry["ask"]]
            with self.subTest(form=name, mode=mode, apply_manual=True):
                self.assertEqual(entry["rc"], 3, entry)
                self.assertTrue(entry["refused"].startswith("manual:"), entry)  # not an unread refusal
        self.assertEqual((code, len(doc["closed"])), (1, len(manual)))
        self.assertEqual(self.s1.read_bytes(), self.s1_before)

        # 4. every offered cell is written by the real wal_note through ask_sweep --apply
        code, doc = self.sweep("--apply", "--only", *[i["pin"] for _a, i in offered])
        self.assertEqual((code, sorted(c["rc"] for c in doc["closed"])), (0, [0] * len(offered)), json.dumps(doc["closed"])[:2000])
        new = [json.loads(x) for x in self.s1.read_bytes()[len(self.s1_before):].decode().splitlines()]
        self.assertEqual(sorted(r["ref"] for r in new), sorted(a for a, _i in offered))
        for r in new:
            name, mode = self.cells[r["ref"]]
            with self.subTest(form=name, mode=mode, written=True):
                self.assertEqual(r["source"], self.forms[name])
                self.assertEqual(r.get("outcome"), "obsolete" if mode == "outcome" else None)
                self.assertEqual(r.get("closed_by"), "agent" if mode == "outcome" else "ask-sweep")
                self.assertNotIn("decision", r)
        self.assertEqual(self.s2.read_bytes(), self.s2_before)

    def test_a_human_answer_that_cannot_be_closed_is_never_hidden_behind_an_obsolete_close(self):
        # an answer row that reaches the user's words through a wal: hop outranks an offerable obsolete close
        item = self.items[self.rank_row]
        self.assertEqual((item["kind"], item["manual"], item["close"]), ("answer", True, None))
        # an outcome close whose evidence reaches a user turn that no longer resolves still ranks as the user's answer
        item = self.items[self.rank_lost]
        self.assertEqual((item["kind"], item["manual"], item["close"]), ("resolved-elsewhere", True, None))
        self.assertEqual(item["evidence"][0]["source"], self.forms["wal>lost-user"])
        self.assertIn("human turn", item["action"])

    def test_surrounding_whitespace_is_the_same_source_for_the_writer_and_the_listing(self):
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


# ---------------------------------------------------------------------- no private list of source kinds

GUARDED = ("ask_evidence.py", "ask_sweep.py", "wal_note.py", "ask_reminders.py")
WORDS = {"user", "uuid", "answer", "queue", "pasted", "mc", "ticket", "wal", "file", "inferred"}  # provenance.SOURCE_WORDS
PATTERN_CALLS = {"startswith", "endswith", "match", "search", "fullmatch", "compile", "findall", "sub", "split"}


def private_kind_lists(text: str, name: str) -> list:
    """Every place in this module source that decides on source kinds itself: a source word compared as a string, a
    collection of two or more source words, or a string pattern naming a source word with its colon."""
    import re
    named = re.compile(r"(?i)(?<![A-Za-z0-9_])(" + "|".join(sorted(WORDS)) + r")(\\s\*|\s*)(:|\|)")
    found = []
    for node in ast.walk(ast.parse(text, name)):
        # a comparison about a source or its kind (a transcript record's own `type` of "user" is not a source kind)
        if isinstance(node, ast.Compare) and re.search(r"kind|source|prefix|word|origin", ast.unparse(node)):
            for value in [node.left, *node.comparators]:
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


class NoPrivateKindList(unittest.TestCase):
    def test_no_module_that_decides_ask_closes_keeps_its_own_list_of_source_kinds(self):
        for name in GUARDED:
            with self.subTest(module=name):
                self.assertEqual(private_kind_lists((HOOKS / name).read_text(), name), [])

    def test_the_guard_catches_each_form_of_a_private_list(self):
        for line in ('HUMAN = ("user", "pasted")', 'ok = kind == "user"', 'ok = kind in ("ticket", "x")',
                     'ok = s.startswith("user:")', 'import re\nok = re.match(r"^(wal:|file:)", s)',
                     'import re\nH = re.compile(r"(?i)(user|answer|uuid)\\s*:")', 'P = ["answer:", "queue:"]'):
            with self.subTest(line=line):
                self.assertNotEqual(private_kind_lists(line + "\n", "probe.py"), [])
        self.assertEqual(private_kind_lists('kinds = {"answer": 1, "terminal": 4}\nx = "manual: read it"\n'
                                            'ok = rec.get("type") == "user"\n', "probe.py"), [])


if __name__ == "__main__":
    unittest.main()
