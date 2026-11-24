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
    "terminal outranks superseded again": ("ask_sweep.py", '"superseded": 2, "terminal": 3}', '"terminal": 2, "superseded": 3}',
                                           "tests/test_ask_sweep.py"),
    "a refused close exits 0": ("ask_sweep.py", "        return 1 if any(c[\"rc\"] for c in closed) else 0", "        return 0",
                                "tests/test_ask_sweep_e2e.py"),
    "terminal evidence gets a close": ("ask_sweep.py", '    if best.get("manual"):\n        return None', "    pass",
                                       "tests/test_ask_sweep_e2e.py"),
    "the pin is not checked": ("ask_sweep.py", '            elif item["pin"] != f"{ask}={ref}":', "            elif False:",
                               "tests/test_ask_sweep_e2e.py"),
    "a bare ask id is accepted": ("ask_sweep.py", "            elif not ref:", "            elif False:", "tests/test_ask_sweep_e2e.py"),
    "SUPERSEDES matches a longer id": ("ask_evidence.py", r'''re.escape(ref) + r"\b", record["note"])''', '''re.escape(ref), record["note"])''',
                                       "tests/test_ask_sweep.py"),
    "a symlinked WAL is followed": ("ask_evidence.py", "        if stat.S_ISLNK(info.st_mode):", "        if False:", "tests/test_ask_sweep.py"),
    # not listed: a FIFO is refused twice (ask_evidence and safe_input.open_regular_file, same code), so either variant alone is equivalent
    "an inferred human source is obsolete evidence": ("ask_evidence.py", "    return any(isinstance(s, str) and HUMAN_KIND.search(s) for s in sources)",
                                                      "    return False", "tests/test_ask_close_outcome.py"),
    "resolved-elsewhere drops the outcome": ("ask_sweep.py", '"outcome": other.get("outcome") if other.get("outcome") in CLOSE_OUTCOMES else None})',
                                             '"outcome": None})', "tests/test_ask_sweep.py"),
}


def one(job):
    tmp, number, name, change = job
    tree = Path(tmp) / ("t%d" % number)
    shutil.copytree(ROOT / "harness" / "hooks", tree / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "tests", tree / "tests", ignore=shutil.ignore_patterns("__pycache__", "mutants_*"))
    tests = ["tests/test_ask_sweep.py", "tests/test_ask_close_outcome.py", "tests/test_ask_sweep_e2e.py"]
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
