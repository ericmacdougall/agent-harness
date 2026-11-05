#!/usr/bin/env python3
"""Run a repository's whole test suite and write a machine-readable report (GoodQA #14582, baseline-compare finish).

  suite_report.py --repo R --out report.json [--nonce N]

It runs the same discovery as `python3 -m unittest discover -s tests` in R and records, in one JSON file written
atomically only AFTER the run finished: the commit (HEAD) and whether the tracked tree was clean, the Python version,
the number of tests run and skipped, and the EXACT ids of every failing or erroring test (an import failure is an id
too). `complete` is true only for a run that reached the end; a crash, a kill or a test that exits the interpreter
leaves no report, so a missing or incomplete report never counts as a result. Failures are recorded, not signalled:
the exit code is 0 for any completed run, 4 when the runner itself could not run.

The report is the only accepted source of a baseline (test_scope.py run-baseline) and the only thing deliver.py
--baseline-compare compares. The nonce keeps a stale or foreign report out; it does not protect against code in the tested
tree that itself writes a report (such a tree could equally neuter its own tests), so the guarantee is against accident,
not against a hostile tree. Stdlib only; Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

SCHEMA = 1
RUNNER = "suite_report"
RUNNER_VERSION = 1
WHOLE_SUITE_COMMAND = "python3 -m unittest discover -s tests"


def _case_id(test) -> str:
    """The id of the test method, so skipped subTests of one test count once (testsRun counts the method once)."""
    case = getattr(test, "test_case", test)
    try:
        return str(case.id())
    except Exception:  # noqa: BLE001
        return str(case)


class Collect(unittest.TextTestResult):
    """Remembers the exact id of every failing, erroring and unexpectedly passing test."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bad_ids: list = []

    def _note(self, test):
        try:
            self.bad_ids.append(str(test.id()))
        except Exception:  # noqa: BLE001 - a holder without an id still counts
            self.bad_ids.append(str(test))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._note(test)

    def addError(self, test, err):
        super().addError(test, err)
        self._note(test)

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._note(test)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._note(subtest)


def _git(repo: str, *args: str) -> str:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home()), "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0"}
    done = subprocess.run(["git", "-C", repo, "-c", "core.fsmonitor=false", *args], capture_output=True, text=True,
                          timeout=60, env=env)
    if done.returncode != 0:
        raise OSError(f"git {args[0]} failed")
    return done.stdout


def write_report(path: Path, report: dict) -> None:
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(str(tmp), str(path))


def _tree_state(repo: str, start: str = "tests") -> tuple:
    """(HEAD, clean). Clean means no tracked change, no untracked file, no assume-unchanged or skip-worktree entry hiding a
    change, and no git-ignored .py file under the start directory (an ignored file would add tests that are not in the
    commit). Other ignored files are excepted."""
    head = _git(repo, "rev-parse", "HEAD").strip()
    dirty = _git(repo, "status", "--porcelain", "--untracked-files=all").strip()
    hidden = [line for line in _git(repo, "ls-files", "-v").splitlines() if line[:1].islower() or line[:1] == "S"]
    ignored = [name for name in _git(repo, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", start).split("\0")
               if name.endswith(".py")]
    return head, not dirty and not hidden and not ignored


def run_suite(repo: str, start: str = "tests") -> dict:
    """Discover and run; returns the report dict (complete only when the run reached its end)."""
    repo = str(Path(repo).resolve())
    sys.dont_write_bytecode = True
    head, clean = _tree_state(repo, start)
    started = time.time()
    os.chdir(repo)
    start_dir = str(Path(repo) / start)
    # Import environment of `python3 -m unittest discover -s tests` run in the repo: the repo (cwd) and the start
    # directory come first, and THIS helper's own directory (sys.path[0] for a script) is not importable by the tests.
    here = str(Path(__file__).resolve().parent)
    sys.path[:] = [repo, start_dir] + [p for p in sys.path if p not in ("", here, repo, start_dir)]
    suite = unittest.TestLoader().discover(start_dir)
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=Collect)
    result = runner.run(suite)
    head_after, _ = _tree_state(repo, start)
    changed = head_after != head or bool(_git(repo, "status", "--porcelain", "--untracked-files=no").strip())
    return {
        "schema": SCHEMA, "kind": "suite-report", "runner": RUNNER, "runner_version": RUNNER_VERSION,
        "command": WHOLE_SUITE_COMMAND, "whole_suite": True, "start": start, "head": head, "clean": clean,
        "python": "%d.%d.%d" % sys.version_info[:3], "host": socket.gethostname().split(".")[0],
        "ran": int(result.testsRun), "skipped": min(len({_case_id(t) for t, _ in result.skipped}), int(result.testsRun)), "failures": len(result.failures),
        "errors": len(result.errors), "unexpected_successes": len(result.unexpectedSuccesses),
        "failing_ids": sorted(set(result.bad_ids)), "failing_count": len(result.bad_ids),
        "started_at": started, "ended_at": time.time(),
        # a run that moved HEAD or modified tracked files while it ran does not describe one commit
        "complete": not changed, "changed_during_run": changed}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--nonce", default="")
    ap.add_argument("--start", default="tests")
    args = ap.parse_args(argv)
    out = Path(args.out)
    try:
        report = run_suite(args.repo, args.start)
        report["nonce"] = args.nonce
        write_report(out, report)
    except Exception as exc:  # noqa: BLE001 - no report on any runner failure
        print(f"suite_report: could not complete ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 4
    print(json.dumps({k: report[k] for k in ("head", "clean", "ran", "failing_count", "complete")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
