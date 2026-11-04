#!/usr/bin/env python3
"""Run the ledger mutants in testdata/mutants/LEDGER.jsonl against disposable copies of this checkout.

Each mutant is an exact, single-occurrence string replacement. For every mutant the runner:
  1. copies the tracked and untracked-unignored files into a fresh scratch directory (the checkout is
     never edited in place, so an interrupted run cannot leave a mutant behind);
  2. runs the named test unmutated and requires it to pass (the control);
  3. applies the replacement, requires the package to build (go vet / py_compile), and requires the
     named test to FAIL by name. A build failure or a missing test name is reported as INVALID, not KILLED.
Exit 0 only when every mutant is KILLED. Usage:
  python3 testdata/mutants/run_mutants.py [--work DIR] [--only ID ...] [--timeout SECONDS]
"""

import argparse
import json
import os
import py_compile
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = Path(__file__).resolve().with_name("LEDGER.jsonl")


def copy_tree(dest: Path):
    listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            capture_output=True, check=True).stdout.split(b"\0")
    for name in filter(None, listed):
        src = ROOT / os.fsdecode(name)
        if not src.is_file():
            continue
        target = dest / os.fsdecode(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)


def run(cmd, cwd, timeout):
    try:
        out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return out.returncode, out.stdout + out.stderr
    except subprocess.TimeoutExpired as error:
        return 124, f"timeout after {timeout}s: {error}"


def test_cmd(m):
    if m["kind"] == "go":
        return ["go", "test", "-count=1", "-run", f"^{m['test']}$", m["package"]], "."
    return [sys.executable, "-m", "unittest", m["test"]], m["package"]


def build_ok(m, tree, timeout):
    if m["kind"] == "go":
        return run(["go", "vet", m["package"]], tree, timeout)
    try:
        py_compile.compile(str(tree / m["file"]), doraise=True)
        return 0, ""
    except py_compile.PyCompileError as error:
        return 1, str(error)


def failed_by_name(m, code, output):
    if code == 0 or code == 124:
        return False
    name = m["test"].rsplit(".", 1)[-1]
    if m["kind"] == "go":
        return f"--- FAIL: {name}" in output
    return f"FAIL: {name}" in output or f"ERROR: {name}" in output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default=str(Path.home() / ".agent-harness" / "scratch" / "ledger-mutants"))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()
    mutants = [json.loads(line) for line in SPEC.read_text().splitlines() if line.strip()]
    if args.only:
        mutants = [m for m in mutants if m["id"] in args.only]
    if not mutants:
        print("no mutants selected", file=sys.stderr)
        return 2
    work = Path(args.work)
    results = []
    for m in mutants:
        started = time.monotonic()
        tree = work / m["id"]
        shutil.rmtree(tree, ignore_errors=True)
        tree.mkdir(parents=True)
        try:
            copy_tree(tree)
            cmd, sub = test_cmd(m)
            code, out = run(cmd, tree / sub, args.timeout)
            if code != 0:
                results.append({"id": m["id"], "status": "INVALID", "why": "control test fails unmutated",
                                "tail": out[-800:]})
                continue
            path = tree / m["file"]
            text = path.read_text()
            if text.count(m["old"]) != 1:
                results.append({"id": m["id"], "status": "INVALID", "why": "target string not unique/absent"})
                continue
            path.write_text(text.replace(m["old"], m["new"], 1))
            code, out = build_ok(m, tree, args.timeout)
            if code != 0:
                results.append({"id": m["id"], "status": "INVALID", "why": "mutant does not build", "tail": out[-800:]})
                continue
            code, out = run(cmd, tree / sub, args.timeout)
            status = "KILLED" if failed_by_name(m, code, out) else "SURVIVED"
            results.append({"id": m["id"], "status": status, "test": m["test"], "exit": code,
                            "seconds": round(time.monotonic() - started, 1),
                            **({} if status == "KILLED" else {"tail": out[-800:]})})
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        print(json.dumps(results[-1]), flush=True)
    killed = sum(r["status"] == "KILLED" for r in results)
    print(json.dumps({"mutants": len(results), "killed": killed}))
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
