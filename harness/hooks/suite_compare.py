#!/usr/bin/env python3
"""Run the whole suite through suite_report.py and compare it with the recorded baseline (GoodQA #14582).

Shared by deliver.py (finish / --resolve-baseline) and integrate_local.py (--resolve-journal) so both apply exactly one
rule: the checked tree's failing test ids must be an exact-id subset of the failing ids of the complete suite baseline
recorded for exactly `expected_sha`, the run must be complete and whole-suite, and it must run at least as many
(non-skipped) tests as the baseline did. No other outcome passes. Stdlib only; Python 3.9 compatible.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_REPORT = 1_000_000
WHOLE_SUITE_ARGV = ["python3", "-m", "unittest", "discover", "-s", "tests"]


class CompareFailure(Exception):
    """The comparison did not pass; problems are human-readable reasons, facts are extra bounded evidence."""

    def __init__(self, problems, **facts):
        super().__init__("; ".join(problems[:6]))
        self.problems, self.facts = list(problems), facts


def read_private_json(path: Path):
    """The report file, only if it is a regular 0600 file owned by us, at most MAX_REPORT bytes."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_REPORT):
            raise OSError("unsafe report file")
        return json.loads(os.read(fd, MAX_REPORT + 1))
    finally:
        os.close(fd)


def scrub_store_env():
    """The store location and host come from the policy, never from the caller's environment (deliver.py does the same)."""
    for name in ("HARNESS_TEST_SCOPE_ROOT", "HARNESS_TEST_SCOPE_HOST"):
        os.environ.pop(name, None)


def bound_by_pinned(repo, failing_ids, ran: int, active: int, pinned_sha: str) -> list:
    """When the commit being checked is not the generation's pinned original HEAD (a recovery re-pin), whatever is accepted
    must still stay within the pinned HEAD's complete baseline: no failing id outside it and no fewer tests. A regression can
    therefore never become a known failure by recording a new baseline. CompareFailure when the pinned HEAD has none."""
    import test_scope
    pinned, why = test_scope.baseline_suite_for(baseline_record_for(repo, pinned_sha), pinned_sha)
    if pinned is None:
        raise CompareFailure(["the pinned original HEAD has no complete suite baseline to bound the result with: " + "; ".join(why)])
    if host_problem(pinned):
        raise CompareFailure(["pinned HEAD baseline: " + host_problem(pinned)])
    if waiver_problem(pinned):
        raise CompareFailure(["pinned HEAD baseline: " + waiver_problem(pinned)])
    problems = []
    new = sorted(i for i in failing_ids if i not in set(pinned["failing_ids"]))
    if new:
        problems.append(f"{len(new)} failing test(s) are not in the baseline of the pinned HEAD: " + ", ".join(new[:10]))
    if ran < pinned["ran"]:
        problems.append(f"the suite ran {ran} tests, fewer than the pinned HEAD baseline's {pinned['ran']}")
    pinned_active = pinned["ran"] - pinned.get("skipped", 0)
    if active < pinned_active:
        problems.append(f"the suite ran {active} non-skipped tests, fewer than the pinned HEAD baseline's {pinned_active}")
    return problems


def host_problem(suite: dict):
    """A baseline is a failure set of one machine; comparing another machine's run with it would accept or reject by host."""
    here = socket.gethostname().split(".")[0]
    recorded = suite.get("host")
    if recorded != here:
        return (f"the baseline was recorded on host {recorded!r} but this run is on {here!r}: run the finish on the host "
                "that recorded it (the dev2 delivery clone)")
    return None


def waiver_problem(suite: dict):
    """A baseline recorded with --accept-new-failures turned a regression into a known failure. Nothing may be accepted
    against it unless the result is also bounded by a different, pinned HEAD's baseline (there is no general waiver)."""
    note = suite.get("note")
    if isinstance(note, dict) and note.get("accepted_new_failures"):
        return ("the baseline accepted new failures (" + ", ".join(map(str, note["accepted_new_failures"][:3]))
                + "): a regression cannot become a known failure; fix them, or bound the result by the pinned HEAD's baseline")
    return None


def baseline_provenance(suite: dict) -> dict:
    """Why/how the baseline was recorded, so a waiver or replacement is visible in every receipt."""
    return {key: suite[key] for key in ("report_sha256", "note", "replaces", "host", "python") if key in suite}


def head_of(repo) -> str:
    done = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30,
                          env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home()),
                               "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    return done.stdout.strip() if done.returncode == 0 else ""


def baseline_record_for(repo, sha: str):
    """The recorded baseline for exactly sha from the test-scope store; CompareFailure when the store is unreachable."""
    import test_scope
    ctx = test_scope.repo_context(str(repo))
    got = test_scope.store_call(test_scope.load_policy(), ["baseline-get", f"--repo-id={ctx['repo_id']}", f"--main-sha={sha}"])
    if got is None:
        raise CompareFailure(["the test-scope store is unreachable, so no baseline can be verified"])
    _code, data = got
    return data.get("record") if isinstance(data, dict) else None


def preflight(repo, sha: str, pinned_sha=None) -> dict:
    """Before any effect: a complete suite baseline for exactly sha must exist. Returns its suite block."""
    import test_scope
    suite, problems = test_scope.baseline_suite_for(baseline_record_for(repo, sha), sha)
    if suite is None:
        raise CompareFailure(problems)
    if host_problem(suite):
        raise CompareFailure([host_problem(suite)])
    if not (pinned_sha and pinned_sha != sha) and waiver_problem(suite):
        raise CompareFailure([waiver_problem(suite)])
    return suite


def run_compare(repo, expected_sha: str, timeout, report_dir, run_fn, log, pinned_sha=None) -> dict:
    """Run suite_report.py in repo (never trusting an old report: a fresh nonce is issued and the file is removed first)
    and compare. run_fn(repo, argv, timeout=, discard_output=, sink=) is integrate_local.run. Returns the result dict."""
    import test_scope
    report_dir = Path(report_dir)
    report_path = report_dir / "suite-report.json"
    # The baseline is read once, before the long run, so a replacement during the run cannot change what is compared.
    base_record = baseline_record_for(repo, expected_sha)
    base_suite, base_problems = test_scope.baseline_suite_for(base_record, expected_sha)
    if base_suite is None:
        raise CompareFailure(base_problems)
    if host_problem(base_suite):
        raise CompareFailure([host_problem(base_suite)])
    if not (pinned_sha and pinned_sha != expected_sha) and waiver_problem(base_suite):
        raise CompareFailure([waiver_problem(base_suite)])
    try:
        os.unlink(report_path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise CompareFailure([f"the previous suite report could not be removed ({error.__class__.__name__})"]) from None
    nonce = secrets.token_hex(16)
    command = ["python3", str(HERE / "suite_report.py"), "--repo", str(repo), "--out", str(report_path), "--nonce", nonce]
    log.header(command)
    try:
        result = run_fn(repo, command, timeout=timeout, discard_output=True, sink=log)
    except subprocess.TimeoutExpired:
        raise CompareFailure([f"the suite exceeded {timeout} seconds (use a larger --check-timeout; a full run took about 30 "
                              "minutes on a busy dev2)"], **log.facts()) from None
    except OSError as error:
        raise CompareFailure([f"the suite runner could not start ({error.__class__.__name__}: {str(error)[:120]})"],
                             **log.facts()) from None
    if result.returncode:
        raise CompareFailure([f"the suite runner exited {result.returncode}: the suite crashed or stopped early"], **log.facts())
    try:
        report = read_private_json(report_path)
    except (OSError, ValueError):
        raise CompareFailure(["no readable suite report was produced"], **log.facts()) from None
    if not isinstance(report, dict) or report.get("nonce") != nonce:
        raise CompareFailure(["the suite report is not from this run"], **log.facts())
    head = head_of(repo)
    if not head:
        raise CompareFailure(["the checked checkout's HEAD could not be read"], **log.facts())
    outcome = test_scope.compare_suite(report, base_record, expected_sha, head)
    if not outcome["ok"]:
        raise CompareFailure(outcome["problems"], baseline_sha=expected_sha, checked_ran=outcome["checked_ran"],
                             baseline_ran=outcome["baseline_ran"], **log.facts())
    if pinned_sha and pinned_sha != expected_sha:
        problems = bound_by_pinned(repo, report["failing_ids"], report["ran"], outcome["checked_active"], pinned_sha)
        if problems:
            raise CompareFailure(problems, baseline_sha=expected_sha, checked_ran=outcome["checked_ran"],
                                 baseline_ran=outcome["baseline_ran"], **log.facts())
    summary = {key: outcome[key] for key in ("baseline_sha", "baseline_ran", "checked_ran", "accepted_failing_ids")}
    summary.update(source="run", checked_head=head, baseline_active=outcome["baseline_active"],
                   checked_active=outcome["checked_active"], pinned_sha=pinned_sha,
                   bounded_by_pinned=bool(pinned_sha and pinned_sha != expected_sha),
                   baseline_provenance=baseline_provenance(base_suite))
    return summary


def accept_recorded(repo, sha: str, pinned_sha: str | None = None) -> dict:
    """--use-recorded-baseline: the already-recorded real suite run at exactly sha is the evidence. When pinned_sha (the
    generation's pinned original HEAD) differs from sha, the recorded failing ids must be a subset of the ones recorded
    for pinned_sha, so a regression can never be turned into a known failure by re-baselining."""
    import test_scope
    suite, problems = test_scope.baseline_suite_for(baseline_record_for(repo, sha), sha)
    if suite is None:
        raise CompareFailure(problems)
    if host_problem(suite):
        raise CompareFailure([host_problem(suite)])
    if not (pinned_sha and pinned_sha != sha) and waiver_problem(suite):
        raise CompareFailure([waiver_problem(suite)])
    if pinned_sha and pinned_sha != sha:
        problems = bound_by_pinned(repo, suite["failing_ids"], suite["ran"], suite["ran"] - suite.get("skipped", 0), pinned_sha)
        if problems:
            raise CompareFailure(problems)
    return {"baseline_sha": sha, "baseline_ran": suite["ran"], "checked_ran": suite["ran"],
            "accepted_failing_ids": sorted(suite["failing_ids"]), "source": "recorded", "checked_head": sha,
            "baseline_active": suite["ran"] - suite.get("skipped", 0), "checked_active": suite["ran"] - suite.get("skipped", 0),
            "pinned_sha": pinned_sha, "bounded_by_pinned": bool(pinned_sha and pinned_sha != sha), "baseline_provenance": baseline_provenance(suite)}
