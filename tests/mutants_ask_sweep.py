"""#170 repair failing-first evidence: each variant removes one control. The named test module must fail against it and
pass against the real files.

Run: python3 -B tests/mutants_ask_sweep.py   (copies the hooks and tests into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# name: (file, old, new, test module)
MUTANTS = {
    # round 1 controls
    "terminal outranks superseded again": ("ask_sweep.py", '{"answer": 1, "superseded": 3, "terminal": 4}',
                                           '{"answer": 1, "superseded": 4, "terminal": 3}', "tests/test_ask_sweep.py"),
    "a refused close exits 0": ("ask_sweep.py", "        return 1 if any(c[\"rc\"] for c in closed) else 0", "        return 0",
                                "tests/test_ask_sweep_e2e.py"),
    "terminal evidence gets a close": ("ask_sweep.py", '    if best.get("manual"):\n        return None', "    pass",
                                       "tests/test_ask_sweep_e2e.py"),
    "the pin is not checked": ("ask_sweep.py", '            elif item["pin"] != f"{ask}={ref}":', "            elif False:",
                               "tests/test_ask_sweep_e2e.py"),
    "a bare ask id is accepted": ("ask_sweep.py", "            elif not ref:", "            elif False:", "tests/test_ask_sweep_e2e.py"),
    "SUPERSEDES matches a longer id": ("ask_evidence.py", r'''re.escape(ref) + r"\b", record["note"])''', '''re.escape(ref), record["note"])''',
                                       "tests/test_ask_sweep.py"),
    "a symlinked WAL is followed": ("ask_evidence.py", "    if stat.S_ISLNK(info.st_mode):", "    if False:", "tests/test_ask_sweep.py"),
    # not listed: a FIFO or a directory is refused twice (ask_evidence's lstat and safe_input.open_regular_file, with the
    # same code), so removing either check alone is an equivalent variant
    "resolved-elsewhere drops the outcome": ("ask_sweep.py", '"outcome": other.get("outcome") if other.get("outcome") in CLOSE_OUTCOMES else None})',
                                             '"outcome": None})', "tests/test_ask_sweep.py"),
    # round 2 F1: the provenance.py change (the L<n> entry form gets the id form's bounds)
    "provenance reads an L entry outside its folder and past the budget": (
        "provenance.py",
        "            for index, line in safe_input.iter_jsonl_lines(path, MAX_LINE, max_total_bytes=MAX_SCAN_BYTES,\n"
        "                                                           max_seconds=SCAN_SECONDS, allowed_roots=[str(path.parent)]):",
        "            for index, line in safe_input.iter_jsonl_lines(path, MAX_LINE, max_seconds=SCAN_SECONDS):",
        "tests/test_ask_close_outcome.py"),
    # round 2 F2: every early stop of the reader is listed in unread
    "the time-budget stop is silent": ("ask_evidence.py", '                    stop = {"reason": "time-budget", "line": number + 1}\n',
                                       "", "tests/test_ask_evidence.py"),
    "the byte-budget stop is silent": ("ask_evidence.py", '                    stop = {"reason": "byte-budget", "line": number + 1}',
                                       "                    pass", "tests/test_ask_evidence.py"),
    "a skipped long line is silent": ("ask_evidence.py", '                    skipped.setdefault("line-too-long", []).append(number)',
                                      "                    pass", "tests/test_ask_evidence.py"),
    "an unparseable line is silent": ("ask_evidence.py", "                        skipped.setdefault(reason, []).append(number)",
                                      "                        pass", "tests/test_ask_evidence.py"),
    "the size cap is not checked": ("ask_evidence.py", "    if info.st_size > limit:", "    if False:", "tests/test_ask_evidence.py"),
    "an incomplete listing exits 0": ("ask_sweep.py", '    return 2 if result["unread"] or result["incomplete"] else 0',
                                      '    return 2 if result["incomplete"] else 0', "tests/test_ask_sweep.py"),
    "apply ignores an incomplete listing": ("ask_sweep.py", '            elif result["unread"]:', "            elif False:",
                                            "tests/test_ask_sweep.py"),
    # round 2 F3: a printed close is one provenance accepts
    "the old quote swap is back": ("ask_evidence.py", "body.replace('\"', '\\\\\"')", "body.replace('\"', \"'\")",
                                   "tests/test_ask_sweep_quoting.py"),
    "a literal ellipsis is not an elision": ("ask_evidence.py", '    pieces = [piece.strip() for piece in body.split("...")]',
                                             "    pieces = [body]", "tests/test_ask_sweep_quoting.py"),
    "the excerpt is not checked with provenance": (
        "ask_evidence.py",
        '        if provenance.parse_excerpt(quoted) != excerpt or provenance.excerpt_in(turn_text or "", excerpt) is not None:',
        "        if False:", "tests/test_ask_sweep_quoting.py"),
    # round 3 triage (CRITICAL): an elided answer is never closed by the tool
    "an elided answer is closed by the tool": ("ask_sweep.py", "            elif cited[1]:", "            elif False:",
                                               "tests/test_ask_sweep.py"),
    # round 4 ruling (CRITICAL class): WAL evidence is closed only when it cites the user's whole turn, decided by the
    # one shared function for both paths
    "a partial WAL-evidence excerpt is closed": (
        "ask_sweep.py", '    if whole_citation(best["source"], home) is False:', "    if False:", "tests/test_ask_sweep.py"),
    "cites_whole accepts any excerpt": ("ask_evidence.py", "    return bool(whole) and provenance.norm(excerpt) == whole",
                                        "    return True", "tests/test_ask_sweep.py"),
    "cites_whole compares the raw text": ("ask_evidence.py", "    return bool(whole) and provenance.norm(excerpt) == whole",
                                          "    return bool(whole) and excerpt == text", "tests/test_ask_sweep_whole_turn.py"),
    "a cite provenance refuses is offered": (
        "ask_sweep.py", '    return ask_evidence.cites_whole(node.get("excerpt"), node.get("text"))',
        '    return ask_evidence.cites_whole(node.get("excerpt"), node.get("text")) or not node',
        "tests/test_ask_sweep_whole_turn.py"),
    # round 2 F4: a failed run never loses the report, and a rerun names closed asks
    "a timeout raises": ("ask_sweep.py", "    except subprocess.TimeoutExpired:", "    except ZeroDivisionError:", "tests/test_ask_sweep.py"),
    "a closed ask is reported as not listed": ("ask_sweep.py", "            if ask in resolved:", "            if False:",
                                               "tests/test_ask_sweep.py"),
    "the ledger is not read again after a failed run": ("ask_sweep.py",
                                                        '        failed = [(entry, source) for entry, source in ran if entry["rc"]]',
                                                        "        failed = []", "tests/test_ask_sweep.py"),
    # round 2 F5: the guard over the modules ask_sweep depends on can fail
    "ask_sweep reads the main WAL itself": ("ask_sweep.py", "    return ask_evidence.read_asks(main_wal, parse_ts, unread)",
                                            '    open(main_wal, "rb").close()\n    return ask_evidence.read_asks(main_wal, parse_ts, unread)',
                                            "tests/test_ask_sweep.py"),
    "ask_reminders keeps its own read": ("ask_reminders.py", '    return ask_evidence.read_asks(wal_path, parse_ts)["open"]',
                                         '    open(wal_path, "rb").close()\n    return ask_evidence.read_asks(wal_path, parse_ts)["open"]',
                                         "tests/test_ask_sweep.py"),
    # round 2 F6: a human answer outranks an obsolete close elsewhere
    "an obsolete close elsewhere outranks an answer": ("ask_sweep.py", '        return 0 if evidence.get("human") else 2',
                                                       "        return 0", "tests/test_ask_sweep.py"),
    "only the first close of an ask is kept": ("ask_sweep.py", '            resolutions.setdefault(r["ref"], []).append(r)',
                                               '            resolutions.setdefault(r["ref"], [r])', "tests/test_ask_sweep.py"),
    # round 2 F7: one home
    "AH_HOME is not compared": ("ask_sweep.py", "    if configured and Path(configured).expanduser().resolve() != home:",
                                "    if False:", "tests/test_ask_sweep.py"),
    "CLAUDE_CONFIG_DIR is not compared": (
        "ask_sweep.py", '    if config and Path(config).expanduser().resolve() != (home / ".claude").resolve():', "    if False:",
        "tests/test_ask_sweep.py"),
    # round 5 F5: both sides resolved, so a symlinked ~/.claude is one place
    "the .claude side is not resolved": (
        "ask_sweep.py", '    if config and Path(config).expanduser().resolve() != (home / ".claude").resolve():',
        '    if config and Path(config).expanduser().resolve() != home / ".claude":', "tests/test_ask_sweep.py"),
    # round 5 F4: ops_watch reads the main logs through the safe reader's per-line cap
    "ops_watch ignores the line cap": (
        "ops_watch.py", "                for _number, raw in safe_input.iter_jsonl_lines(main_log, RESOLVED_LINE_MAX_BYTES,",
        "                for _number, raw in safe_input.iter_jsonl_lines(main_log, 1 << 30,",
        "tests/test_ops_watch_resolved_asks.py"),
    # round 5 F1/F2 (CRITICAL class): one table and one verdict for the writer and the listing, over the whole tree.
    # Each variant breaks one cell class of tests/test_ask_close_contract.py.
    "an outcome close ignores a chat turn in the tree": (
        "ask_close.py", '        if mode == "outcome" and not exempt and traced["chat"]:', "        if False:",
        "tests/test_ask_close_contract.py"),
    "the listing offers a close the writer refuses": (
        "ask_sweep.py", '    return REFUSED_ACTION.format(verdict["problem"]) if verdict["problem"] else None', "    return None",
        "tests/test_ask_close_contract.py"),
    "an answer elsewhere ranks as obsolete": ("ask_sweep.py", '        return 0 if evidence.get("human") else 2',
                                              "        return 2", "tests/test_ask_close_contract.py"),
    "answer rows need a user: source": (
        "ask_sweep.py", '                  and not still_waiting(note, ident) and walk(source)["human"]):',
        '                  and not still_waiting(note, ident) and source.startswith("user:")):',
        "tests/test_ask_close_contract.py"),
    "queue: is not a user turn": ("provenance.py", '"answer": "user", "queue": "user", "pasted": "pasted"',
                                  '"answer": "user", "queue": "ticket", "pasted": "pasted"', "tests/test_ask_close_contract.py"),
    "pasted: is the user's answer": ("ask_close.py", '"pasted":   {"kind": "pasted", "human": False, "chat": True,',
                                     '"pasted":   {"kind": "pasted", "human": True, "chat": True,', "tests/test_ask_close_contract.py"),
    "pasted: is not a chat turn": ("ask_close.py", '"pasted":   {"kind": "pasted", "human": False, "chat": True,',
                                   '"pasted":   {"kind": "pasted", "human": False, "chat": False,', "tests/test_ask_close_contract.py"),
    "any spelling of a word is accepted": (
        "ask_close.py",
        '    match = re.match(r"^([a-z]+):", (source or "").strip())\n    return match.group(1) if match and match.group(1) in TABLE else None',
        '    match = re.match(r"(?i)^\\s*([a-z]+)\\s*:", source or "")\n'
        '    return match.group(1).lower() if match and match.group(1).lower() in TABLE else None',
        "tests/test_ask_close_contract.py"),
    "wal: backs an answer close": ("ask_close.py", '"wal":      {"kind": "wal", "human": False, "chat": False, "answer": False,',
                                   '"wal":      {"kind": "wal", "human": False, "chat": False, "answer": True,',
                                   "tests/test_ask_close_contract.py"),
    "ticket: cannot back an outcome": (
        "ask_close.py", '"ticket":   {"kind": "ticket", "human": False, "chat": False, "answer": True, "decision": True, "outcome": True},',
        '"ticket":   {"kind": "ticket", "human": False, "chat": False, "answer": True, "decision": True, "outcome": False},',
        "tests/test_ask_close_contract.py"),
    "a wal: hop drops the upstream kinds": (
        "provenance.py", '        result["kinds"] = list(sub["kinds"])  # every kind upstream, also one that failed before it reached the chain',
        "        pass", "tests/test_ask_close_contract.py"),
    "the tree walk skips inferred inputs": ("provenance.py", '        stack.extend(node.get("inputs") or ())', "        pass",
                                            "tests/test_ask_close_contract.py"),
    "an unparseable inferred input claims no kind": (
        "provenance.py", '                result["kinds"].append(claimed_kind(item))  # unparseable, yet it still says what it cites',
        "                pass", "tests/test_ask_close_outcome.py"),
    "the SUPERSEDES exemption is dropped": ("ask_close.py", "    return None, ask_evidence.supersedes(record, ref)",
                                            "    return None, False", "tests/test_ask_sweep_e2e.py"),
    # not listed: the `#<ask id>` pre-check in _outcome_problem is equivalent to the entry read after it (the same id is
    # refused with the same message, and an unreadable path is refused too), like the FIFO case above
    #
    # round 6 (R4 F1/F2, CRITICAL class): "could not tell" is never "no". One variant per cell class of the contract.
    # provenance: where a walk stops
    "a pointer that fails is not a stop": (
        "provenance.py", "    return code not in END_CODES or kind is None or kind in POINTER_KINDS",
        "    return code not in END_CODES or kind is None", "tests/test_ask_close_contract.py"),
    "a source that names no kind is not a stop": (
        "provenance.py", "    return code not in END_CODES or kind is None or kind in POINTER_KINDS",
        "    return code not in END_CODES or kind in POINTER_KINDS", "tests/test_ask_close_contract.py"),
    "every code of an origin ends the walk": (
        "provenance.py", "    return code not in END_CODES or kind is None or kind in POINTER_KINDS",
        "    return kind is None or kind in POINTER_KINDS", "tests/test_ask_close_contract.py"),
    "a wal: hop drops the upstream stops": (
        "provenance.py", '        result["stops"] = list(sub["stops"])  # and every place the walk upstream stopped (#170 round 6)',
        "        pass", "tests/test_ask_close_contract.py"),
    "an entry with no source is not a stop": ("provenance.py", '            result["stops"].append("wal-unsourced")',
                                              "            pass", "tests/test_ask_close_contract.py"),
    "an unparseable inferred input is not a stop": (
        "provenance.py", "                if stops_walk(problem.code, item):  # a pointer or kindless input: what it cites is not known",
        "                if False:", "tests/test_ask_close_contract.py"),
    "a nested or mc: input is not a stop": (
        "provenance.py", "                result[\"stops\"].append(code)  # never walked, so what it reaches is not known (#170 round 6)",
        "                pass", "tests/test_ask_close_contract.py"),
    "an internal error is not a stop": ("provenance.py", '        result["stops"].append("internal")', "        pass",
                                        "tests/test_ask_close_contract.py"),
    # ask_close: the three states and the verdict
    "trace reads unknown as not human": (
        "ask_close.py", '    state = "human" if kinds & HUMAN_KINDS else "unknown" if stops else "not-human"',
        '    state = "human" if kinds & HUMAN_KINDS else "not-human"', "tests/test_ask_close_contract.py"),
    "the verdict ignores a stopped walk": ("ask_close.py", '        if traced["stops"]:', "        if False:",
                                           "tests/test_ask_close_contract.py"),
    "the policy switch turns a stopped walk into a close": (
        "ask_close.py", '        if traced["stops"]:',
        '        if traced["stops"] and provenance.load_policy()["wal"].get("ask", "warn") != "off":',
        "tests/test_ask_close_contract.py"),
    "outcome evidence that does not resolve passes when the policy is off": (
        "ask_close.py", '        if mode == "outcome" and not result.get("ok"):', "        if False:",
        "tests/test_ask_close_contract.py"),
    "an mc: decision in the tree backs an outcome": (
        "ask_close.py", '        if mode == "outcome" and traced["kinds"] & BIND_KINDS:', "        if False:",
        "tests/test_ask_close_contract.py"),
    "precheck skips wal_note's argument checks": (
        "ask_close.py", "        problem = wal_note.argument_problem(note, source, reason)", "        problem = None",
        "tests/test_ask_close_contract.py"),
    "precheck skips the open-ask check": ("ask_close.py", "        if not wal_note.open_ask_exists(wal, ref):",
                                          "        if False:", "tests/test_ask_sweep_incomplete.py"),
    # ask_sweep: ranking, listing and exit
    "unknown ranks as not human": ("ask_sweep.py", '            traced[source] = {"human": t["maybe_human"],',
                                   '            traced[source] = {"human": t["state"] == "human",',
                                   "tests/test_ask_close_contract.py"),
    "an untraced answer does not come first in its rank": (
        "ask_sweep.py", '        found.sort(key=lambda e: (rank(e), not e.get("unknown"), not ask_close.is_card(e["source"]),',
        '        found.sort(key=lambda e: (rank(e), not ask_close.is_card(e["source"]),', "tests/test_ask_close_contract.py"),
    "an untraced best evidence gets the refusal reason only": ("ask_sweep.py", '    if best.get("unknown"):', "    if False:",
                                                               "tests/test_ask_close_contract.py"),
    "incomplete walks are not listed": (
        "ask_sweep.py", '                            for i in result["evidence"] for e in i["evidence"] if e.get("unknown")]',
        '                            for i in result["evidence"] for e in i["evidence"] if False]',
        "tests/test_ask_close_contract.py"),
    "an incomplete walk exits 0": ("ask_sweep.py", '    return 2 if result["unread"] or result["incomplete"] else 0',
                                   '    return 2 if result["unread"] else 0', "tests/test_ask_sweep_incomplete.py"),
    "an answer card skips the precheck": ("ask_sweep.py", '        if verdict["problem"]:\n            result["answered"].remove(item)',
                                          '        if False:\n            result["answered"].remove(item)',
                                          "tests/test_ask_close_contract.py"),
    "an answer row with no source of its own is skipped": (
        "ask_sweep.py", 'r.get("by") != "ask-sweep"\n                  and not still_waiting',
        'r.get("by") != "ask-sweep" and source\n                  and not still_waiting', "tests/test_ask_close_contract.py"),
    "a credential answer is printed":("ask_sweep.py", "            item[\"answer\"] = CREDENTIAL", "            pass",
                                       "tests/test_ask_close_contract.py"),
    # round 7 (main's ruling, option a): a traced answer keeps its answer close beside unknown evidence, nothing else
    "unknown evidence holds back a traced answer close": ("ask_sweep.py", '        if found[0].get("unknown"):',
                                                          "        if False:", "tests/test_ask_close_contract.py"),
    "a close no user words back is kept beside unknown evidence": (
        "ask_sweep.py", ' and bool(evidence.get("human"))', "", "tests/test_ask_close_contract.py"),
    "a traced answer the writer refuses is kept": (
        "ask_sweep.py", "            if keeper is not None and held_back(keeper, ident, home, main_wal) is None:",
        "            if keeper is not None:", "tests/test_ask_close_contract.py"),
    "an outcome close is kept beside unknown evidence": (
        "ask_sweep.py", 'evidence.get("outcome") is None and not evidence.get("unknown")', 'not evidence.get("unknown")',
        "tests/test_ask_close_contract.py"),
    "another unknown walk is kept beside unknown evidence": (
        "ask_sweep.py", ' and not evidence.get("unknown") and ', " and ", "tests/test_ask_close_contract.py"),
    # main's ruling on pr170-r7-scope: the held cells, for every stop code, fail when any completed walk is kept
    "any close whose walk completed is kept beside unknown evidence": (
        "ask_sweep.py", 'return evidence.get("outcome") is None and not evidence.get("unknown") and bool(evidence.get("human"))',
        'return not evidence.get("unknown")', "tests/test_ask_close_contract.py"),
    # not listed: the "tree-too-large" stop in provenance._walk_tree cannot be reached (MAX_RESOLVES caps a tree at
    # far fewer nodes than its bound), and trace's except branch runs only when provenance cannot be imported or
    # resolve() raises, which it never does; both fail closed by construction
}
REAL_TESTS = ["tests/test_ask_sweep.py", "tests/test_ask_evidence.py", "tests/test_ask_sweep_quoting.py",
              "tests/test_ask_close_outcome.py", "tests/test_ask_sweep_e2e.py", "tests/test_ask_reminders.py",
              "tests/test_ask_sweep_whole_turn.py", "tests/test_ask_close_contract.py", "tests/test_ops_watch_resolved_asks.py",
              "tests/test_ask_sweep_incomplete.py"]


def one(job):
    tmp, number, name, change = job
    tree = Path(tmp) / ("t%d" % number)
    shutil.copytree(ROOT / "harness" / "hooks", tree / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "tests", tree / "tests", ignore=shutil.ignore_patterns("__pycache__", "mutants_*"))
    tests = REAL_TESTS
    if change:
        name_of_file, old, new, test = change
        path = tree / "harness" / "hooks" / name_of_file
        text = path.read_text()
        if text.count(old) != 1:
            return name, "BROKEN MUTANT: pattern found %d times" % text.count(old), True
        path.write_text(text.replace(old, new))
        tests = [test]
    failed = False
    for test in tests:
        proc = subprocess.run([sys.executable, "-I", test, "-f"], cwd=str(tree), capture_output=True, text=True, timeout=900)
        failed = failed or proc.returncode != 0
    shutil.rmtree(tree, ignore_errors=True)
    return name, "tests FAIL (killed)" if failed else "tests PASS", failed != (change is not None)


def main():
    survived = []
    with tempfile.TemporaryDirectory() as tmp:
        jobs = [(tmp, n, name, change) for n, (name, change) in enumerate([("(the real files)", None)] + list(MUTANTS.items()))]
        with ThreadPoolExecutor(max_workers=3) as pool:
            for name, verdict, bad in pool.map(one, jobs):
                print("%-48s %s" % (name, verdict), flush=True)
                if bad:
                    survived.append(name)
    print("survivors: %s" % (survived or "none"))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
