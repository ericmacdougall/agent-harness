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
    "an inferred human source is obsolete evidence": ("ask_evidence.py", "    return any(isinstance(s, str) and HUMAN_KIND.search(s) for s in sources)",
                                                      "    return False", "tests/test_ask_close_outcome.py"),
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
    "an incomplete listing exits 0": ("ask_sweep.py", '    return 2 if result["unread"] else 0', "    return 0", "tests/test_ask_sweep.py"),
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
    "an outcome close outranks an answer": (
        "ask_sweep.py", '        return 0 if ask_evidence.human_traced(evidence["source"]) and not evidence.get("outcome") else 2',
        "        return 0", "tests/test_ask_sweep.py"),
    "only the first close of an ask is kept": ("ask_sweep.py", '            resolutions.setdefault(r["ref"], []).append(r)',
                                               '            resolutions.setdefault(r["ref"], [r])', "tests/test_ask_sweep.py"),
    # round 2 F7: one home
    "AH_HOME is not compared": ("ask_sweep.py", "    if configured and Path(configured).expanduser().resolve() != home:",
                                "    if False:", "tests/test_ask_sweep.py"),
    "CLAUDE_CONFIG_DIR is not compared": ("ask_sweep.py", '    if config and Path(config).expanduser().resolve() != home / ".claude":',
                                          "    if False:", "tests/test_ask_sweep.py"),
}
REAL_TESTS = ["tests/test_ask_sweep.py", "tests/test_ask_evidence.py", "tests/test_ask_sweep_quoting.py",
              "tests/test_ask_close_outcome.py", "tests/test_ask_sweep_e2e.py", "tests/test_ask_reminders.py"]


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
