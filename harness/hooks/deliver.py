#!/usr/bin/env python3
"""Publish a reviewed feature, then explicitly deliver its merged or local result.

PR readiness and checkout delivery are separate durable phases. State belongs to
one original checkout and task, independently of HOME or an agent session. No
command merges a remote PR or executes text from the run kit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

from github_identity import github_repository, repository_name
from git_safety import git_environment, require_safe_source
from integrate_local import (ALLOWED_GIT_ENV, CheckInterpreterError, CheckLog, ExternalApplyError,
                             OriginalScope, acquire_scope_lock, approved_check, approved_prepare, focused_unittest, redact_output,
                             require_check_interpreters,
                             checkout_identity, git_common_directory, journal_key,
                             fsync_directory, private_directory, read_journal, run as run_check,
                             scope_key, valid_identity_text, write_journal)
from process import cleanup_discarded
import wal as wal_log


OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TASK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
# A full test suite routinely needs minutes; Git/GitHub commands keep --timeout.
DEFAULT_CHECK_TIMEOUT = 1800
MAX_CHECK_TIMEOUT = 7200
MAX_OUTPUT = 1_000_000
MAX_PRIVATE = 32_768
GH_FIELDS = "number,state,headRefOid,headRefName,baseRefName,url,isDraft,mergeCommit,isCrossRepository,headRepository,headRepositoryOwner"
PHASES = {"INITIAL", "PUBLISHING", "PR_LOOKUP", "PR_CREATING", "PR_READY", "REMOTE_BLOCKED",
          "REMOTE_UNCERTAIN", "LOCAL_READY", "REMOTE_APPLYING", "LOCAL_APPLYING",
          "RESOLVED_BASELINE", "DELIVERED", "LOCAL_DELIVERED", "POLICY_BLOCKED"}
SETTLED = {"PR_READY", "REMOTE_BLOCKED", "LOCAL_READY", "RESOLVED_BASELINE",
           "DELIVERED", "LOCAL_DELIVERED", "POLICY_BLOCKED"}


# Delivery targets that are far behind origin or carry a huge staged/untracked set are almost
# always a stale or corrupted checkout (the 77k staged adds / 40k behind case); refuse early with
# a specific hint instead of a generic "dirty" failure or a status timeout. mode: refuse | warn.
TARGET_POLICY = {"mode": "refuse", "max_behind": 1000, "max_staged": 5000, "max_untracked": 5000,
                 "timeout": 30}


class DeliveryError(Exception):
    def __init__(self, status, message, *, code=3, **facts):
        super().__init__(message)
        self.status, self.message, self.code, self.facts = status, message, code, facts


def report(status, message, **facts):
    print(json.dumps({"status": status, "message": message, **facts}, sort_keys=True))


def bounded(command, *, cwd=None, env=None, timeout=30, limit=MAX_OUTPUT):
    """Bound a child process group and output without echoing its private output."""
    code, output, _ = bounded_with_stderr(command, cwd=cwd, env=env, timeout=timeout, limit=limit)
    return code, output


def bounded_with_stderr(command, *, cwd=None, env=None, timeout=30, limit=MAX_OUTPUT, stderr_limit=0):
    """Like bounded, optionally keeping the first stderr_limit bytes.

    stderr is drained through a pipe and the excess discarded, so a child that
    floods stderr neither blocks, fills the disk, nor grows our memory.
    """
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE if stderr_limit else subprocess.DEVNULL,
                               start_new_session=True)
    data, errors, deadline = bytearray(), bytearray(), time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as poller:
            poller.register(process.stdout, selectors.EVENT_READ, "out")
            if stderr_limit:
                poller.register(process.stderr, selectors.EVENT_READ, "err")
            while poller.get_map():
                remaining = deadline - time.monotonic()
                ready = poller.select(remaining) if remaining > 0 else []
                if not ready:
                    raise DeliveryError("BLOCKED_LOCAL", "Delivery command timed out")
                for key, _ in ready:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        poller.unregister(key.fileobj)
                    elif key.data == "err":
                        errors.extend(chunk[:max(0, stderr_limit - len(errors))])
                    else:
                        data.extend(chunk)
                        if len(data) > limit:
                            raise DeliveryError("BLOCKED_LOCAL", "Delivery command output exceeded limit",
                                                reason="OUTPUT_LIMIT")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeliveryError("BLOCKED_LOCAL", "Delivery command timed out")
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise DeliveryError("BLOCKED_LOCAL", "Delivery command timed out") from None
        return code, bytes(data).decode("utf-8", "replace"), bytes(errors).decode("utf-8", "replace")
    except BaseException as failure:
        # A reaped leader says nothing about descendants that still hold stdout.
        # Reuse the shared bounded TERM/grace/KILL and discarded-output cleanup.
        try:
            cleanup_discarded(process)
        except (OSError, subprocess.TimeoutExpired):
            failure.cleanup_incomplete = True
        raise
    finally:
        process.stdout.close()
        if process.stderr:
            process.stderr.close()


def git(repo, *args, timeout=30):
    return bounded(["git", "-C", str(repo), *args], env=git_environment(), timeout=timeout)


def git_value(repo, *args, timeout=30):
    code, value = git(repo, *args, timeout=timeout)
    value = value.removesuffix("\n")
    if code or not value:
        raise DeliveryError("BLOCKED_LOCAL", "Git state could not be verified")
    return value


def valid_oid(value):
    if not isinstance(value, str) or not OID.fullmatch(value):
        raise DeliveryError("BLOCKED_POLICY", "Expected commit must be a full Git object ID", code=2)
    return value


def require_arguments(args, *names):
    if any(getattr(args, name, None) is None for name in names):
        raise DeliveryError("BLOCKED_POLICY", "Required delivery arguments are missing", code=2)


def snapshot(repo, branch, *, require_clean=True):
    if (repo.is_symlink() or not repo.is_dir()
            or Path(git_value(repo, "rev-parse", "--show-toplevel")).resolve() != repo.resolve()):
        raise DeliveryError("BLOCKED_POLICY", "Checkout must be a Git worktree root", code=2)
    code, _ = git(repo, "check-ref-format", "--branch", branch)
    if code or git_value(repo, "symbolic-ref", "--quiet", "--short", "HEAD") != branch:
        raise DeliveryError("BLOCKED_LOCAL", "Checkout branch changed or is invalid")
    try:
        require_safe_source(repo, git_environment(), timeout=15)
    except OSError:
        raise DeliveryError("BLOCKED_LOCAL", "Checkout Git metadata is unsafe or unverifiable") from None
    if require_clean:
        code, status = git(repo, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                           "status", "--porcelain=v1", "-z", "--untracked-files=all")
        if code or status:
            raise DeliveryError("BLOCKED_LOCAL", "Checkout is dirty or cannot be inspected")
    return valid_oid(git_value(repo, "rev-parse", "HEAD"))


def _count_entries(repo, label, *args):
    """Count NUL-separated entries of a git listing; a truncated or timed-out listing is 'too many'."""
    try:
        code, output = bounded(["git", "-C", str(repo), "-c", "core.fsmonitor=false",
                                "-c", "core.untrackedCache=false", *args, "-z"],
                               env=git_environment(), timeout=TARGET_POLICY["timeout"], limit=MAX_OUTPUT)
    except DeliveryError:
        return None
    if code:
        return -1  # git refused the listing (ownership, corrupt index): never read as "zero"
    return output.count("\0")


def target_preflight(original, branch, mode=None):
    """Refuse (or warn) before anything is published when the original checkout is a bad target.

    Runs before require_safe_source on purpose (a huge index would otherwise time out the strict
    snapshot first). Only read-only listings run here: no filters, fsmonitor, untracked cache or hooks.
    """
    mode = mode or TARGET_POLICY["mode"]
    original = Path(original)
    if original.is_symlink() or not original.is_dir():
        return []  # later source/original checks report the precise refusal; [] keeps warn-mode callers iterable
    problems = []
    for label, limit_name, args in (
            ("staged", "max_staged", ("diff", "--cached", "--name-only")),
            ("untracked", "max_untracked", ("ls-files", "--others", "--exclude-standard"))):
        count = _count_entries(original, label, *args)
        if count == -1:
            problems.append((f"original checkout {label} paths could not be listed by git",
                             "TARGET_UNREADABLE",
                             "run `git status` in the original checkout to see the error (ownership, "
                             "corrupt index) and fix it before delivering"))
        elif count is None or count > TARGET_POLICY[limit_name]:
            shown = "more than the inspectable bound" if count is None else str(count)
            problems.append((f"original checkout has {shown} {label} paths (limit {TARGET_POLICY[limit_name]})",
                             f"HUGE_{label.upper()}",
                             "this looks like a corrupted or abandoned checkout; use a clean checkout of the "
                             "target branch, or inspect and clear the index before delivering"))
    code, behind = git(original, "rev-list", "--count", f"HEAD..refs/remotes/origin/{branch}",
                       timeout=TARGET_POLICY["timeout"]) if _safe_branch(branch) else (1, "")
    if code:
        # No usable origin/<branch> tracking ref: the behind check cannot run. Say so rather than
        # passing silently; the count is only as fresh as the last fetch either way.
        print("WARNING: behind-origin check skipped (no refs/remotes/origin/<branch> tracking ref; "
              "fetch first to enable it)", file=sys.stderr)
    elif behind.strip().isdigit() and int(behind) > TARGET_POLICY["max_behind"]:
        problems.append((f"original checkout is {int(behind)} commits behind origin/{branch} "
                         f"(limit {TARGET_POLICY['max_behind']})", "ORIGINAL_BEHIND",
                         f"for a new generation, update it first (git -C <original> pull --ff-only) and rebase the "
                         f"feature onto origin/{branch}; to resume an in-flight generation, do not move the original: "
                         f"use --reconcile-only or --target-policy warn"))
    if not problems:
        return []
    message = "; ".join(item[0] for item in problems)
    if mode == "warn":
        print("WARNING: " + message, file=sys.stderr)
        # The caller records these bypassed checks in the WAL, the generation and the output.
        return [{"reason": item[1], "message": item[0][:300]} for item in problems]
    raise DeliveryError("BLOCKED_POLICY", "Original checkout is not a sane delivery target: " + message, code=2,
                        reason=problems[0][1], hint="; ".join(item[2] for item in problems))


def _safe_branch(branch):
    return valid_identity_text(branch) and not branch.startswith("-")


def ancestry(repo, older, newer):
    code, _ = git(repo, "merge-base", "--is-ancestor", valid_oid(older), valid_oid(newer))
    if code not in (0, 1):
        raise DeliveryError("BLOCKED_LOCAL", "Git ancestry could not be verified")
    return code == 0


def regular_bytes(path, limit=MAX_PRIVATE):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > limit):
                raise OSError("private metadata is unsafe")
            data = os.read(fd, limit + 1)
            if len(data) > limit:
                raise OSError("private metadata exceeds limit")
            return data
        finally:
            os.close(fd)
    except OSError:
        raise DeliveryError("RECOVERY_REQUIRED", "Private input is missing, unsafe, or exceeds its limit") from None


IGNORED_GIT_ENV = ("GIT_EDITOR", "GIT_SEQUENCE_EDITOR")
SCRUBBED_ENV = ("HARNESS_TEST_SCOPE_ROOT", "HARNESS_TEST_SCOPE_HOST")  # would redirect the focused-check gate


def private_json(path):
    try:
        value = json.loads(regular_bytes(path))
    except (ValueError, UnicodeError):
        raise DeliveryError("RECOVERY_REQUIRED", "Private metadata is invalid") from None
    if not isinstance(value, dict) or any(not valid_identity_text(key) for key in value):
        raise DeliveryError("RECOVERY_REQUIRED", "Private metadata is invalid")
    for item in value.values():
        if isinstance(item, str) and not valid_identity_text(item):
            raise DeliveryError("RECOVERY_REQUIRED", "Private metadata text is invalid")
    return value


def kit_digest(path):
    data = regular_bytes(path, 16_384)
    try:
        kit = json.loads(data)
    except (ValueError, UnicodeError):
        raise DeliveryError("BLOCKED_POLICY", "Run kit is not valid UTF-8 JSON", code=2) from None
    if not isinstance(kit, dict) or set(kit) - {"run", "test", "watch", "logs", "stop"}:
        raise DeliveryError("BLOCKED_POLICY", "Run kit fields are invalid", code=2)
    for name in ("run", "test", "watch", "logs", "stop"):
        value = kit.get(name)
        if name in {"run", "test", "watch"} or name in kit:
            if (not valid_identity_text(value) or not 1 <= len(value.strip()) <= 1024
                    or any(ord(char) < 32 for char in value)):
                raise DeliveryError("BLOCKED_POLICY", "Run kit needs useful run, test, and watch instructions", code=2)
    return hashlib.sha256(data).hexdigest()


def approved_commands(values, *, prepare=False, allow_focused=False):
    if not values and not prepare:
        raise DeliveryError("BLOCKED_POLICY", "At least one focused check is required", code=2)
    commands = []
    for value in values:
        try:
            argv = shlex.split(value)
        except ValueError:
            raise DeliveryError("BLOCKED_POLICY", "Check command could not be parsed", code=2) from None
        if not (approved_prepare(argv) if prepare else approved_check(argv, allow_focused)):
            raise DeliveryError("BLOCKED_POLICY", "Check command is not approved", code=2)
        commands.append(argv)
    return commands


def focused_proof(flow, focused):
    """test_scope.py's approval of each focused check: it names every test mapped to the changed files and their
    dependents, and a finished passing full run is on record for the frozen source head. Nothing is accepted without it."""
    try:
        import test_scope
    except ImportError:
        raise DeliveryError("BLOCKED_POLICY", "Focused checks need test_scope.py, which is not installed", code=2) from None
    approvals = []
    for argv in focused:
        failure = None
        for repo in (flow.state.get("source"), str(flow.original)):
            if not repo:
                continue
            try:
                approvals.append(test_scope.approve_focused(str(repo), flow.state["baseline"], flow.state["source_head"], argv))
                break
            except test_scope.Refused as refused:
                raise DeliveryError("BLOCKED_POLICY", "Focused check is not approved: " + refused.message, code=2) from None
            except (OSError, ValueError, subprocess.SubprocessError):
                failure = True  # this checkout lacks the commits; try the next one
        else:
            raise DeliveryError("BLOCKED_POLICY", "Focused check proof could not be verified" if failure else
                                "Focused check proof needs a source or original checkout", code=2)
    return approvals


def focused_recheck(flow, target):
    """Remote delivery checks out the merge TARGET, which can carry other people's commits on top of the delta: the
    focused tests must still cover everything mapped for baseline..target."""
    if not getattr(flow, "focused_checks", None):
        return
    import test_scope
    try:
        required = {"tests." + t for t in test_scope.focused_scope(str(flow.original), flow.state["baseline"], target)["tests"]}
    except (OSError, ValueError, subprocess.SubprocessError):
        raise DeliveryError("BLOCKED_POLICY", "Focused check coverage of the merge target could not be verified", code=2) from None
    for approval in flow.focused_checks:
        missing = sorted(required - set(approval.get("tests", [])))
        if missing:
            raise DeliveryError("BLOCKED_POLICY", "Focused check does not cover tests mapped to the merge target: "
                                + " ".join(missing[:8]) + "; run a whole-suite check", code=2)


# --baseline-compare (GoodQA #14582): the whole-suite check passes when its failing test ids are an exact-id subset of the
# failing ids of the complete suite baseline recorded for exactly the pinned original HEAD. Active only for one finish.
ACTIVE_COMPARE: dict = {}
WHOLE_SUITE_ARGV = ["python3", "-m", "unittest", "discover", "-s", "tests"]
MAX_SUITE_REPORT = 1_000_000


def checks_digest(preparations, checks):
    parts = [preparations, checks] + (["baseline-compare"] if ACTIVE_COMPARE else [])
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def compare_failure(problems, **facts):
    return DeliveryError("DELIVERED_CHECK_FAILED", "Baseline comparison failed: " + "; ".join(problems[:6]),
                         check_status="baseline-compare", baseline_compare_problems=problems[:20], **facts)


def helper_source():
    """Which code produced a baseline-compare receipt: this helper's tree and its git HEAD."""
    tree = Path(__file__).resolve().parent.parent.parent
    code, head = git(tree, "rev-parse", "HEAD")
    return {"tree": str(tree), "head": head.strip() if not code else "unknown"}


def baseline_record_for(repo, sha):
    """The recorded baseline for exactly sha from the test-scope store (None when absent or unreachable)."""
    import test_scope
    ctx = test_scope.repo_context(str(repo))
    got = test_scope.store_call(test_scope.load_policy(), ["baseline-get", f"--repo-id={ctx['repo_id']}", f"--main-sha={sha}"])
    if got is None:
        raise compare_failure(["the test-scope store is unreachable, so no baseline can be verified"])
    _code, data = got
    return data.get("record") if isinstance(data, dict) else None


def run_suite_compare(repo, log, timeout, log_directory):
    """Run the whole suite through suite_report.py (never trusting a report that was already there) and compare."""
    import test_scope
    plan = ACTIVE_COMPARE
    sha = plan["expected_sha"]
    report_path = Path(log_directory) / "suite-report.json"
    try:
        os.unlink(report_path)
    except FileNotFoundError:
        pass
    nonce = secrets.token_hex(16)
    command = ["python3", str(Path(__file__).with_name("suite_report.py")), "--repo", str(repo), "--out", str(report_path),
               "--nonce", nonce]
    log.header(command)
    try:
        result = run_check(repo, command, timeout=timeout, discard_output=True, sink=log)
    except subprocess.TimeoutExpired:
        raise compare_failure([f"the suite exceeded {timeout} seconds"], **log.facts()) from None
    except (CheckInterpreterError, OSError) as error:
        raise compare_failure([f"the suite runner could not start ({error.__class__.__name__})"], **log.facts()) from None
    if result.returncode:
        raise compare_failure([f"the suite runner exited {result.returncode}: the suite crashed or stopped early"], **log.facts())
    try:
        report = json.loads(regular_bytes(report_path, MAX_SUITE_REPORT))
    except (DeliveryError, ValueError, OSError):
        raise compare_failure(["no readable suite report was produced"], **log.facts()) from None
    if not isinstance(report, dict) or report.get("nonce") != nonce:
        raise compare_failure(["the suite report is not from this run"], **log.facts())
    code, head = git(repo, "rev-parse", "HEAD")
    if code:
        raise compare_failure(["the checked checkout's HEAD could not be read"])
    outcome = test_scope.compare_suite(report, baseline_record_for(repo, sha), sha, head.strip())
    if not outcome["ok"]:
        raise compare_failure(outcome["problems"], baseline_sha=sha, checked_ran=outcome["checked_ran"],
                              baseline_ran=outcome["baseline_ran"], **log.facts())
    plan["result"] = {key: outcome[key] for key in ("baseline_sha", "baseline_ran", "checked_ran", "accepted_failing_ids")}
    plan["result"].update(source="run", checked_head=head.strip(), helper=helper_source())


def accept_recorded_baseline(repo, sha):
    """--use-recorded-baseline (resolve only): the already-recorded real suite run at exactly this HEAD is the evidence."""
    import test_scope
    record = baseline_record_for(repo, sha)
    suite, problems = test_scope.baseline_suite_for(record, sha)
    if suite is None:
        raise compare_failure(problems)
    ACTIVE_COMPARE["result"] = {"baseline_sha": sha, "baseline_ran": suite["ran"], "checked_ran": suite["ran"],
                                "accepted_failing_ids": sorted(suite["failing_ids"]), "source": "recorded", "checked_head": sha,
                                "helper": helper_source()}


CHECK_FACTS = ("check_log", "check_tail", "check_log_truncated", "check_status")


def check_facts(error):
    """Carry only the bounded check evidence across recovery wrappers."""
    facts = getattr(error, "facts", None) or {}
    return {name: facts[name] for name in CHECK_FACTS if name in facts}


def run_checks(repo, preparations, checks, timeout, log_directory):
    # Output goes to an owner-only bounded log; failures report its path and a
    # redacted tail, so a failed delivery check is diagnosable without rerunning.
    try:
        log = CheckLog(log_directory)
    except OSError:
        raise DeliveryError("DELIVERED_CHECK_FAILED", "Check log could not be created", check_status="log") from None
    try:
        for command in (*preparations, *([] if ACTIVE_COMPARE else checks)):
            log.header(command)
            try:
                result = run_check(repo, command, timeout=timeout, discard_output=True, sink=log)
            except subprocess.TimeoutExpired:
                log.close()
                raise DeliveryError("DELIVERED_CHECK_FAILED", f"Delivered checkout check exceeded {timeout} seconds",
                                    check_status="timeout", **log.facts()) from None
            except CheckInterpreterError as error:
                log.close()
                raise DeliveryError("DELIVERED_CHECK_FAILED", str(error), check_status="interpreter",
                                    **log.facts()) from None
            except OSError:
                log.close()
                raise DeliveryError("DELIVERED_CHECK_FAILED", "Delivered checkout check could not complete",
                                    check_status="error", **log.facts()) from None
            if result.returncode:
                log.close()
                raise DeliveryError("DELIVERED_CHECK_FAILED", "Delivered checkout check failed",
                                    check_status=f"exit {result.returncode}", **log.facts())
        if ACTIVE_COMPARE and not ACTIVE_COMPARE.get("recorded_only"):
            run_suite_compare(repo, log, timeout, log_directory)
        elif ACTIVE_COMPARE:
            accept_recorded_baseline(repo, ACTIVE_COMPARE["expected_sha"])
    finally:
        log.close()


def origin_destination(repo):
    code, fetch = git(repo, "remote", "get-url", "--all", "origin")
    if code:
        code, remotes = git(repo, "remote")
        if code or "origin" in remotes.splitlines():
            raise DeliveryError("BLOCKED_POLICY", "Origin configuration cannot be inspected", code=2)
        raise DeliveryError("REMOTE_BLOCKED", "Origin is not configured; local work can continue", code=4)
    code, push = git(repo, "remote", "get-url", "--push", "--all", "origin")
    if code or len(fetch.splitlines()) != 1 or len(push.splitlines()) != 1:
        raise DeliveryError("BLOCKED_POLICY", "Origin has ambiguous fetch or push destinations", code=2)
    try:
        repository = github_repository(fetch.removesuffix("\n"))
        if github_repository(push.removesuffix("\n")) != repository:
            raise ValueError
    except ValueError:
        raise DeliveryError("BLOCKED_POLICY", "Origin is unsupported or fetch and push identities differ", code=2) from None
    return repository, fetch.removesuffix("\n")


def matching_origins(source, original, expected=None):
    destinations, failures = [], []
    for repo in (source, original):
        try:
            destinations.append(origin_destination(repo))
        except DeliveryError as error:
            failures.append(error)
    if failures:
        # A missing origin cannot conceal the other checkout's policy refusal.
        raise next((error for error in failures if error.code == 2), failures[0])
    (source_repo, _), (original_repo, original_url) = destinations
    if source_repo != original_repo or (expected is not None and source_repo != expected):
        raise DeliveryError("BLOCKED_POLICY", "Feature and original repository identities differ", code=2)
    return source_repo, original_url


class Workflow:
    """An owner-only task lock and generation state outside scratch journals."""
    def __init__(self, args):
        require_arguments(args, "original", "original_branch")
        if not isinstance(args.task, str) or not TASK.fullmatch(args.task):
            raise DeliveryError("BLOCKED_POLICY", "Task identifier is invalid", code=2)
        self.args, self.original, self.branch = args, args.original.expanduser().absolute(), args.original_branch
        if not valid_identity_text(self.branch):
            raise DeliveryError("BLOCKED_POLICY", "Original branch is invalid", code=2)
        snapshot(self.original, self.branch)
        self.identity = checkout_identity(self.original)
        self.common, self.common_info = git_common_directory(self.original, 30)
        self.scope = scope_key(self.identity, self.branch)
        self.task = hashlib.sha256(args.task.encode()).hexdigest()
        path = self.common
        for name in ("agent-harness", "delivery-workflows", self.scope, self.task):
            path = path / name
            private_directory(path)
        self.root = path
        self.root_info = path.stat()
        self.fd, self.state, self.generation = None, None, None

    def __enter__(self):
        self.fd = acquire_scope_lock(self.root, self.identity, self.branch)
        if self.fd is None:
            raise DeliveryError("BUSY", "Another session owns this workflow task")
        try:
            self.assert_context()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *unused):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def assert_context(self):
        common, info = git_common_directory(self.original, 30)
        root = private_directory(self.root)
        if (self.fd is None or checkout_identity(self.original) != self.identity or common != self.common
                or (info.st_dev, info.st_ino) != (self.common_info.st_dev, self.common_info.st_ino)
                or (root.st_dev, root.st_ino) != (self.root_info.st_dev, self.root_info.st_ino)):
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow checkout or private state identity changed")
        locked = os.fstat(self.fd)
        lock_path = self.root / "locks" / self.scope
        named = os.stat(lock_path, follow_symlinks=False)
        if (locked.st_dev, locked.st_ino) != (named.st_dev, named.st_ino) or named.st_nlink != 1:
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow lock identity changed")

    @property
    def directory(self):
        return self.root / "generations" / self.generation

    @property
    def receipt(self):
        return self.directory / "receipt" / "journal.json"

    def _pointer(self):
        path = self.root / "journal.json"
        if not os.path.lexists(path):
            return None
        value = private_json(path)
        if (set(value) != {"schema", "task", "scope", "generation"}
                or type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("task") != self.task or value.get("scope") != self.scope
                or not isinstance(value.get("generation"), str) or not HEX32.fullmatch(value["generation"])):
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow generation pointer is invalid")
        return value["generation"]

    def load(self):
        self.assert_context()
        current = self._pointer()
        requested = getattr(self.args, "generation", None)
        if requested is not None and (not isinstance(requested, str) or not HEX32.fullmatch(requested)):
            raise DeliveryError("BLOCKED_POLICY", "Generation identifier is invalid", code=2)
        if requested is not None and requested != current:
            raise DeliveryError("STALE_GENERATION", "Generation was superseded; no work was changed")
        if current is None:
            return None
        self.generation = current
        private_directory(self.root / "generations")
        private_directory(self.directory)
        self.state = private_json(self.directory / "journal.json")
        self.validate_state(self.state)
        return self.state

    def validate_state(self, value):
        fields = {"schema", "kind", "task", "scope", "generation", "original", "original_dev", "original_ino",
                  "branch", "source", "source_branch", "source_head", "baseline", "kit_digest", "repository",
                  "phase", "pr_number", "target", "merge_head", "guard_key", "local_key", "checks_digest", "apply_base"}
        strings = ("kind", "task", "scope", "generation", "original", "branch", "source", "source_branch",
                   "source_head", "baseline", "kit_digest", "repository", "phase")
        if (set(value) != fields or type(value.get("schema")) is not int or value["schema"] != 1
                or any(not valid_identity_text(value.get(name)) for name in strings)
                or value["kind"] != "delivery_workflow" or value["task"] != self.task
                or value["scope"] != self.scope or value["generation"] != self.generation
                or value["original"] != str(self.original) or value["branch"] != self.branch
                or any(type(value.get(name)) is not int for name in ("original_dev", "original_ino"))
                or (value["original_dev"], value["original_ino"]) != self.identity
                or not Path(value["source"]).is_absolute() or value["phase"] not in PHASES
                or not OID.fullmatch(value["source_head"]) or not OID.fullmatch(value["baseline"])
                or len(value["source_head"]) != len(value["baseline"]) or not HEX64.fullmatch(value["kit_digest"])):
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow scope metadata is invalid")
        try:
            if value["repository"] and repository_name(value["repository"]) != value["repository"]:
                raise ValueError
        except ValueError:
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow repository metadata is invalid") from None
        for name in ("target", "merge_head", "apply_base"):
            item = value[name]
            if item is not None and (not isinstance(item, str) or not OID.fullmatch(item)
                                     or len(item) != len(value["baseline"])):
                raise DeliveryError("RECOVERY_REQUIRED", "Workflow object metadata is invalid")
        for name in ("guard_key", "local_key", "checks_digest"):
            item = value[name]
            if item is not None and (not isinstance(item, str) or not HEX64.fullmatch(item)):
                raise DeliveryError("RECOVERY_REQUIRED", "Workflow recovery metadata is invalid")
        number = value["pr_number"]
        if number is not None and (type(number) is not int or not 1 <= number <= 2**53):
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow PR metadata is invalid")

    def create(self, source, source_branch, source_head, baseline, kit, repository, phase):
        if self.state is not None and self.state["phase"] not in SETTLED:
            raise DeliveryError("RECOVERY_REQUIRED", "Previous generation has an uncertain or unresolved outcome")
        self.generation = secrets.token_hex(16)
        private_directory(self.root / "generations")
        private_directory(self.directory)
        self.state = {"schema": 1, "kind": "delivery_workflow", "task": self.task, "scope": self.scope,
                      "generation": self.generation, "original": str(self.original),
                      "original_dev": self.identity[0], "original_ino": self.identity[1], "branch": self.branch,
                      "source": str(source), "source_branch": source_branch, "source_head": source_head,
                      "baseline": baseline, "kit_digest": kit, "repository": repository, "phase": phase,
                      "pr_number": None, "target": None, "merge_head": None, "guard_key": None,
                      "local_key": None, "checks_digest": None, "apply_base": None}
        self.validate_state(self.state)
        write_journal(self.directory, self.state, first=True)
        self.assert_context()
        write_journal(self.root, {"schema": 1, "task": self.task, "scope": self.scope,
                                  "generation": self.generation},
                      first=not os.path.lexists(self.root / "journal.json"))
        return self.state

    def save(self, **changes):
        self.assert_state()
        value = {**self.state, **changes}
        self.validate_state(value)
        write_journal(self.directory, value)
        self.state = value

    def assert_state(self):
        self.assert_context()
        if (self._pointer() != self.generation
                or private_json(self.directory / "journal.json") != self.state):
            raise DeliveryError("RECOVERY_REQUIRED", "Workflow generation or state changed during delivery")

    def facts(self):
        facts = {"generation": self.generation, "state": str(self.directory / "journal.json"),
                 "checkout": str(self.original), "source_head": self.state["source_head"]}
        if getattr(self, "focused_checks", None):
            facts["focused_checks"] = self.focused_checks
        if ACTIVE_COMPARE.get("result"):
            facts["baseline_compare"] = ACTIVE_COMPARE["result"]
        overrides = self.target_overrides()
        if overrides:
            facts["target_policy_overrides"] = overrides
        waivers, total = self.policy_waivers()
        if waivers is None:
            # A record that exists but cannot be read must not look like "no waivers".
            facts["commit_policy_waivers_unreadable"] = True
        elif waivers:
            facts["commit_policy_waivers"] = waivers
            if total > len(waivers):
                facts["commit_policy_waivers_total"] = total
        return facts

    def target_overrides(self):
        """Every --target-policy warn run recorded for this generation (see record_target_override)."""
        path = self.directory / TARGET_OVERRIDE_RECORD
        if not os.path.lexists(path):
            return []
        try:
            items = json.loads(regular_bytes(path, WAIVER_RECORD_LIMIT)).get("overrides", [])
            return items if isinstance(items, list) else [{"mode": "unreadable"}]
        except (OSError, ValueError, DeliveryError, AttributeError):
            return [{"mode": "unreadable"}]

    def policy_waivers(self):
        """Waivers the checked range used, so a reviewer of the prepare output sees every bypass.

        Returns (items, total): ([], 0) when no record exists (local-only or pre-gate generations),
        (None, 0) when a record exists but is unreadable or holds a malformed item, and at most 50
        items with the full count otherwise.
        """
        path = self.directory / COMMIT_POLICY_RECORD
        if not os.path.lexists(path):
            return [], 0
        try:
            # The record also holds exclude/ticket lists; allow far more than the 50 waivers shown.
            record = json.loads(regular_bytes(path, WAIVER_RECORD_LIMIT))
            items = record.get("waivers", [])
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                return None, 0
            return [{"kind": sanitize_gh_text(str(item.get("kind", "")), 40),
                     "subject": sanitize_gh_text(str(item.get("subject", "")), 64),
                     "id": sanitize_gh_text(str(item.get("id", "")), 64),
                     "wal": os.path.basename(sanitize_gh_text(str(item.get("wal", "")), 200))}
                    for item in items[:50]], len(items)
        except (OSError, ValueError, DeliveryError, AttributeError, TypeError):
            return None, 0

    def complete(self, mode, head, digest):
        self.save(target=head, checks_digest=digest)
        self.assert_context()
        data = {"schema": 1, "kind": "delivery_receipt", "scope": self.scope, "task": self.task,
                "generation": self.generation, "source_head": self.state["source_head"], "head": head,
                "mode": mode, "repository": self.state["repository"], "pr_number": self.state["pr_number"],
                "checks_digest": digest, "guard_key": self.state["guard_key"]}
        if getattr(self, "focused_checks", None):
            data["focused_checks"] = self.focused_checks  # the test_scope approval of each focused check
        if ACTIVE_COMPARE.get("result"):
            data["baseline_compare"] = ACTIVE_COMPARE["result"]  # baseline sha, both test counts, the accepted failing ids
        private_directory(self.receipt.parent)
        write_journal(self.receipt.parent, data, first=True)
        self.save(phase="DELIVERED" if mode == "remote" else "LOCAL_DELIVERED", target=head,
                  checks_digest=digest)

    def completed(self):
        if not os.path.lexists(self.receipt):
            if self.state["phase"] in {"DELIVERED", "LOCAL_DELIVERED"}:
                raise DeliveryError("RECOVERY_REQUIRED", "Completed workflow receipt is missing")
            return None
        value = private_json(self.receipt)
        expected = {"schema", "kind", "scope", "task", "generation", "source_head", "head", "mode",
                    "repository", "pr_number", "checks_digest", "guard_key"}
        extra = value.get("focused_checks", [])
        compare = value.get("baseline_compare", {})
        if (not isinstance(extra, list) or len(extra) > 20 or any(not isinstance(item, dict) for item in extra)
                or not isinstance(compare, dict) or set(value) - {"focused_checks", "baseline_compare"} != expected or type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("kind") != "delivery_receipt" or value.get("scope") != self.scope
                or value.get("task") != self.task or value.get("generation") != self.generation
                or value.get("source_head") != self.state["source_head"]
                or value.get("repository") != self.state["repository"]
                or value.get("pr_number") != self.state["pr_number"]
                or value.get("guard_key") != self.state["guard_key"]
                or not isinstance(value.get("head"), str) or not OID.fullmatch(value["head"])
                or len(value["head"]) != len(self.state["baseline"])
                or not isinstance(value.get("mode"), str) or value["mode"] not in {"remote", "local"}
                or value.get("head") != self.state["target"]
                or value.get("checks_digest") != self.state["checks_digest"]
                or type(value.get("pr_number")) is not type(self.state["pr_number"])
                or not isinstance(value.get("checks_digest"), str) or not HEX64.fullmatch(value["checks_digest"])):
            raise DeliveryError("RECOVERY_REQUIRED", "Completed workflow receipt is invalid")
        current = snapshot(self.original, self.branch)
        if not ancestry(self.original, value["head"], current):
            raise DeliveryError("RECHECK_REQUIRED", "Historical delivery is absent from current checkout", head=current)
        return {**value, "current_head": current}


def gh(*args, timeout=30, stderr_limit=0):
    env = git_environment()
    env.update({"GH_PROMPT_DISABLED": "1", "GH_HOST": "github.com", "GIT_TERMINAL_PROMPT": "0"})
    if stderr_limit:
        # Mutating calls (pr create) classify launch, budget and mid-run errors themselves, so
        # raw exceptions propagate and the result is (code, stdout, bounded stderr).
        return bounded_with_stderr(["gh", *args], env=env, timeout=min(timeout, 30), stderr_limit=stderr_limit)
    try:
        return bounded(["gh", *args], env=env, timeout=min(timeout, 30))
    except OSError:
        raise DeliveryError("REMOTE_BLOCKED", "GitHub command could not complete", code=4) from None
    except DeliveryError as error:
        raise DeliveryError("REMOTE_UNCERTAIN", "GitHub command exceeded its output or time budget",
                            code=4, **error.facts) from None


GH_STDERR_LIMIT = 4096
GH_HINT_LIMIT = 300
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|.)")
# Anything ambiguous, transient or from a later step (labels, reviewers) may have happened after
# GitHub already created the PR, so it can never be a definite verdict.
GH_TRANSIENT = re.compile(r"(?i)(?:timed? ?out|timeout|deadline exceeded|connection (?:reset|refused|closed)|"
                          r"broken pipe|\beof\b|temporar|try again|rate limit|too many requests|\b429\b|"
                          r"something went wrong|internal server error|\b50[0234]\b|bad gateway|"
                          r"service unavailable|no such host|network is unreachable|\btls\b|"
                          r"could not add|could not request|after (?:creating|the pull request)|"
                          # A PR that already exists is positive evidence of a create, never "nothing created",
                          # even when an eventually consistent `gh pr list` does not show it yet.
                          r"already exists)")
# Failures GitHub reports before creating anything. Every pattern is anchored to the start of a line
# in gh's own message shape (after gh's fixed prefixes), never to free words such as "not found" or
# to phrases that could appear mid-line next to an echoed branch, label or later-step message.
_GH_LINE = r"(?im)^\s*(?:(?:pull request create failed|aborted|error|gh|graphql)\s*:\s*)*"
GH_DEFINITE = (
    (re.compile(_GH_LINE + r"(?:to get started with github cli, please run:\s+gh auth login|http 401\b|"
                           r"bad credentials|authentication required)"),
     "GitHub authentication failed; run `gh auth login` for this host, then re-run prepare with --new-generation"),
    (re.compile(_GH_LINE + r"(?:http 403\b|resource not accessible)"),
     "GitHub denied write access to this repository; check the account's write access, then re-run prepare with --new-generation"),
    (re.compile(_GH_LINE + r"(?:base ref must be a branch|could not resolve to a (?:ref|branch)\b)"),
     "The base branch does not exist on GitHub; push it or pass the right --original-branch, then re-run with --new-generation"),
    (re.compile(_GH_LINE + r"(?:http 404\b|could not resolve to a repository\b)"),
     "GitHub cannot find the repository (or you cannot see it); check origin and access, then re-run with --new-generation"),
    (re.compile(_GH_LINE + r"(?:validation failed|http 422\b|no commits between|you must first push)"),
     "GitHub rejected the PR as invalid (for example no commits between base and head); fix it, then re-run with --new-generation"),
)


def sanitize_gh_text(text, limit=GH_HINT_LIMIT):
    """One bounded printable line of gh stderr: escapes and controls stripped, secrets redacted."""
    text = ANSI.sub(" ", text[:GH_STDERR_LIMIT])
    # Controls first: they could otherwise split a token and defeat the redaction patterns.
    text = "".join(char for char in text if char.isprintable() or char in " \t\r\n")
    return " ".join(redact_output(text).split())[:limit]


def classify_gh_failure(code, error_text):
    """Return a hint for a failure GitHub reported before acting, or None when completion is unknown."""
    # gh echoes "Creating draft pull request for <branch> into <base>"; the branch name is not evidence.
    error_text = ANSI.sub("", error_text[:GH_STDERR_LIMIT])
    # Any transient phrase anywhere, including the echoed line, keeps the outcome uncertain.
    if GH_TRANSIENT.search(error_text):
        return None
    # Split on "\n" only: str.splitlines() would also break on \r, \v, \f, \x1c-\x1e, \x85 and
    #   and so promote a mid-line phrase to a line start when the lines are rejoined.
    error_text = "\n".join(line for line in error_text.split("\n") if not line.lstrip().startswith("Creating "))
    if code == 4:
        return GH_DEFINITE[0][1]
    for pattern, hint in GH_DEFINITE:
        if pattern.search(error_text):
            return hint
    return None


def gh_json(*args, timeout=30):
    try:
        code, output = gh(*args, timeout=timeout)
    except DeliveryError as error:
        if error.facts.get("reason") == "OUTPUT_LIMIT":
            raise DeliveryError("BLOCKED_POLICY", "GitHub query response exceeded its bounded contract", code=2) from None
        raise
    if code:
        raise DeliveryError("REMOTE_BLOCKED", "GitHub could not be queried", code=4)
    try:
        return json.loads(output)
    except (ValueError, UnicodeError):
        raise DeliveryError("BLOCKED_POLICY", "GitHub returned an invalid query response", code=2) from None


def pr_identity(pr, repository, branch):
    """Refuse fork, repository, URL, or branch aliases before considering a PR."""
    if not isinstance(pr, dict):
        return False
    owner, name = repository.split("/")
    head_repo, head_owner, number = pr.get("headRepository"), pr.get("headRepositoryOwner"), pr.get("number")
    return (type(number) is int and 1 <= number <= 2**53
            and pr.get("isCrossRepository") is False
            and isinstance(head_repo, dict) and isinstance(head_repo.get("name"), str)
            and head_repo["name"].lower() == name
            and isinstance(head_owner, dict) and isinstance(head_owner.get("login"), str)
            and head_owner["login"].lower() == owner
            and pr.get("headRefName") == branch
            and isinstance(pr.get("url"), str)
            and pr["url"].lower() == f"https://github.com/{repository}/pull/{number}")


def matching_pr(state, timeout):
    listing = gh_json("pr", "list", "-R", state["repository"], "--head", state["source_branch"],
                      "--state", "all", "--limit", "101", "--json", GH_FIELDS, timeout=timeout)
    if not isinstance(listing, list) or len(listing) > 100:
        raise DeliveryError("BLOCKED_POLICY", "PR enumeration is invalid or exceeds its bounded page", code=2)
    matches = []
    for pr in listing:
        if isinstance(pr, dict):
            owner, name = state["repository"].split("/")
            head_repo, head_owner = pr.get("headRepository"), pr.get("headRepositoryOwner")
            if (pr.get("isCrossRepository") is True
                    or isinstance(head_repo, dict) and isinstance(head_repo.get("name"), str)
                    and head_repo["name"].lower() != name
                    or isinstance(head_owner, dict) and isinstance(head_owner.get("login"), str)
                    and head_owner["login"].lower() != owner):
                continue  # Same-name fork branches cannot be this reviewed head.
        if (not isinstance(pr, dict) or not isinstance(pr.get("state"), str)
                or pr["state"] not in {"OPEN", "MERGED", "CLOSED"}
                or not pr_identity(pr, state["repository"], state["source_branch"])):
            raise DeliveryError("BLOCKED_POLICY", "Feature branch PR identity is ambiguous", code=2)
        if pr["state"] == "CLOSED":
            continue
        exact = pr.get("headRefOid") == state["source_head"] and pr.get("baseRefName") == state["branch"]
        if exact:
            matches.append(pr)
        elif pr["state"] == "OPEN" or pr.get("headRefOid") == state["source_head"]:
            raise DeliveryError("BLOCKED_POLICY", "Open or matching-head PR has another reviewed scope", code=2)
        # A prior merged generation on a reused owner branch is history.
    if len(matches) > 1:
        raise DeliveryError("BLOCKED_POLICY", "Feature has multiple matching PRs", code=2)
    return matches[0] if matches else None


def checked_body(path):
    body = regular_bytes(path)
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise DeliveryError("BLOCKED_POLICY", "PR body must be UTF-8", code=2) from None
    if (not text.strip() or "\0" in text
            or re.search(r"(?i)(?:gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|\b(?:token|password|secret|access[_-]?key)\s*[=:]\s*\S+)", text)):
        raise DeliveryError("BLOCKED_POLICY", "PR body is empty, invalid, or appears to contain a credential", code=2)
    return body


def transport(original, url, repository, arguments, timeout, *, objects=None, negotiation_tips=()):
    """Use a private bare transport, preserving normal global auth but no repo config."""
    try:
        with tempfile.TemporaryDirectory(prefix="agent-harness-transport-") as raw:
            root = Path(raw)
            empty = root / "template"
            empty.mkdir(mode=0o700)
            object_format = git_value(original, "rev-parse", "--show-object-format")
            if object_format not in {"sha1", "sha256"}:
                raise DeliveryError("BLOCKED_POLICY", "Repository object format is unsupported", code=2)
            env = git_environment()
            bare = root / "transport.git"
            code, _ = bounded(["git", "init", "--bare", "--quiet", f"--template={empty}",
                               f"--object-format={object_format}", str(bare)], env=env, timeout=timeout)
            if code:
                raise DeliveryError("REMOTE_BLOCKED", "Isolated remote transport could not be prepared", code=4)
            remote = "harness-" + secrets.token_hex(8)
            prefix = ["git", "-C", str(bare), "-c", f"remote.{remote}.url={url}",
                      "-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true",
                      "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                      "-c", "fetch.writeCommitGraph=false"]
            code, effective = bounded([*prefix, "ls-remote", "--get-url", "--", remote], env=env, timeout=timeout)
            if code or effective.removesuffix("\n") != url or github_repository(url) != repository:
                raise DeliveryError("BLOCKED_POLICY", "Isolated transport destination changed", code=2)
            if objects is not None:
                named = Path(git_value(original, "rev-parse", "--path-format=absolute", "--git-path", "objects"))
                if named.is_symlink() or named.resolve() != objects:
                    raise DeliveryError("RECOVERY_REQUIRED", "Original object store changed")
                info = objects.stat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                    raise DeliveryError("RECOVERY_REQUIRED", "Original object store is unsafe")
                pinned = (info.st_dev, info.st_ino)
                env["GIT_OBJECT_DIRECTORY"] = str(objects)
                if arguments[0] != "fetch":
                    raise DeliveryError("BLOCKED_POLICY", "Borrowed object storage is restricted to fetching", code=2)
                current = valid_oid(git_value(original, "rev-parse", "HEAD"))
                tips = []
                for tip in dict.fromkeys((current, *negotiation_tips)):
                    valid_oid(tip)
                    status, kind = git(original, "cat-file", "-t", tip, timeout=timeout)
                    if status == 0 and kind.removesuffix("\n") == "commit":
                        tips.append("--negotiation-tip=" + tip)
                # No refs in this temporary repository describe the original's
                # other branches. Maintenance must never inspect its real store.
                command = [*prefix, "fetch", "--no-auto-maintenance", *tips, remote, *arguments[1:]]
            else:
                command = [*prefix, *arguments[:1], remote, *arguments[1:]]
            code, output = bounded(command, env=env, timeout=timeout)
            if objects is not None and (objects.stat().st_dev, objects.stat().st_ino) != pinned:
                raise DeliveryError("RECOVERY_REQUIRED", "Original object store changed during fetch")
            return code, output
    except ValueError:
        raise DeliveryError("BLOCKED_POLICY", "Remote transport identity is unsupported", code=2) from None


def published_ref(original, url, state, timeout):
    code, output = transport(original, url, state["repository"],
                             ["ls-remote", "refs/heads/" + state["source_branch"]], timeout)
    if code:
        raise DeliveryError("REMOTE_UNCERTAIN", "Publication outcome cannot yet be reconciled", code=4)
    rows = output.splitlines()
    if not rows:
        return None
    expected_ref = "refs/heads/" + state["source_branch"]
    fields = rows[0].split() if len(rows) == 1 else []
    if (len(fields) != 2 or fields[1] != expected_ref or not OID.fullmatch(fields[0])
            or len(fields[0]) != len(state["source_head"])):
        raise DeliveryError("BLOCKED_POLICY", "Published branch identity is invalid", code=2)
    if fields[0] != state["source_head"]:
        raise DeliveryError("BLOCKED_POLICY", "Remote feature tip differs; review a new branch generation",
                            code=2, observed_remote_head=fields[0])
    return state["source_head"]


def require_remote_base(flow, url):
    """The PR base must exist on the remote; fail before any push or PR create when it does not."""
    ref = "refs/heads/" + flow.branch
    try:
        code, output = transport(flow.original, url, flow.state["repository"], ["ls-remote", ref], flow.args.timeout)
    except DeliveryError as error:
        if error.status == "BLOCKED_POLICY":
            raise
        code, output = 1, ""
    if code:
        # ls-remote is read-only and runs before any push or PR create, so nothing was published:
        # this is the same settled, definite pre-publication block as a failed publisher preflight.
        flow.save(phase="REMOTE_BLOCKED")
        raise DeliveryError("REMOTE_BLOCKED", "Remote base branch could not be checked; nothing was published",
                            code=4, reason="BASE_CHECK_UNAVAILABLE",
                            hint="Check network and credentials for origin, then re-run prepare with "
                                 "--new-generation, or finish --mode local", **flow.facts())
    # ls-remote tail-matches, so demand the exact ref name.
    found = [row.split("\t")[-1] for row in output.splitlines() if row.strip()]
    if ref not in found:
        raise DeliveryError("BLOCKED_POLICY", "The base branch does not exist on the remote; nothing was pushed",
                            code=2, reason="BASE_BRANCH_MISSING", base_branch=flow.branch[:200],
                            hint="Push the base branch (git push origin <branch>) or pass the correct "
                                 "--original-branch, then re-run prepare", **flow.facts())


def source_inputs(args):
    require_arguments(args, "source", "original", "original_branch", "expected_source_head",
                      "expected_original_head", "kit_file")
    source, original = args.source.expanduser().absolute(), args.original.expanduser().absolute()
    source_head, baseline = valid_oid(args.expected_source_head), valid_oid(args.expected_original_head)
    if source.is_symlink() or original.is_symlink() or source.resolve() == original.resolve():
        raise DeliveryError("BLOCKED_POLICY", "Feature and original must be distinct worktrees", code=2)
    branch = git_value(source, "symbolic-ref", "--quiet", "--short", "HEAD")
    if branch == args.original_branch or snapshot(source, branch) != source_head:
        raise DeliveryError("BLOCKED_POLICY", "Source branch or reviewed HEAD changed", code=2)
    if snapshot(original, args.original_branch) != baseline:
        raise DeliveryError("BLOCKED_LOCAL", "Original checkout changed since scope capture")
    return source, branch, source_head, baseline, kit_digest(args.kit_file)


def verify_source(flow):
    state = flow.state
    source = Path(state["source"])
    if snapshot(source, state["source_branch"]) != state["source_head"]:
        raise DeliveryError("BLOCKED_POLICY", "Prepared source changed; review a new generation", code=2)
    return source


def record_pr(flow, pr):
    flow.save(phase="PR_READY", pr_number=pr["number"])
    report("PR_READY", "Feature and PR verified; original checkout has not been delivered",
           pr=pr["url"], **flow.facts())
    return 0


def prepare_pr(flow, title, body):
    try:
        existing = matching_pr(flow.state, flow.args.timeout)
    except DeliveryError as error:
        if flow.state["phase"] in {"PR_CREATING", "REMOTE_UNCERTAIN"}:
            flow.save(phase="REMOTE_UNCERTAIN")
            raise DeliveryError("REMOTE_UNCERTAIN", "A failed lookup cannot settle an in-flight create",
                                code=4, **flow.facts()) from None
        if error.status == "BLOCKED_POLICY":
            flow.save(phase="POLICY_BLOCKED")
        elif flow.state["phase"] == "PR_LOOKUP" and error.status == "REMOTE_BLOCKED":
            flow.save(phase="REMOTE_BLOCKED")
        elif flow.state["phase"] != "PR_LOOKUP":
            flow.save(phase="REMOTE_UNCERTAIN")
        raise
    if existing:
        return record_pr(flow, existing)
    if flow.state["phase"] in {"PR_CREATING", "REMOTE_UNCERTAIN"}:
        flow.save(phase="REMOTE_UNCERTAIN")
        raise DeliveryError("REMOTE_UNCERTAIN", "An in-flight create cannot be disproved by temporary PR absence",
                            code=4, **flow.facts())
    staged = flow.directory / (".pr-body-" + secrets.token_hex(12))
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        flow.save(phase="PR_CREATING")
        try:
            code, _, error_text = gh("pr", "create", "-R", flow.state["repository"],
                                     "--head", flow.state["source_branch"], "--base", flow.branch, "--draft",
                                     "--title", title, "--body-file", str(staged),
                                     timeout=flow.args.timeout, stderr_limit=GH_STDERR_LIMIT)
        except (FileNotFoundError, PermissionError) as launch:
            if launch.filename != "gh":
                flow.save(phase="REMOTE_UNCERTAIN")
                raise DeliveryError("REMOTE_UNCERTAIN", "PR creation outcome requires later positive reconciliation",
                                    code=4, **flow.facts()) from None
            flow.save(phase="REMOTE_BLOCKED")
            raise DeliveryError("REMOTE_BLOCKED", "GitHub CLI (gh) could not be started",
                                code=4, hint="Install gh and run `gh auth login`, then re-run prepare with --new-generation",
                                **flow.facts()) from None
        except (DeliveryError, OSError):
            flow.save(phase="REMOTE_UNCERTAIN")
            raise DeliveryError("REMOTE_UNCERTAIN", "PR creation outcome requires later positive reconciliation",
                                code=4, **flow.facts()) from None
        if code:
            gh_error = sanitize_gh_text(error_text)
            hint = classify_gh_failure(code, error_text)
            # Under REMOTE_UNCERTAIN a new generation is refused, so drop the "re-run" advice.
            likely = hint.split(", then re-run")[0] if hint else None
            try:
                already = matching_pr(flow.state, flow.args.timeout)
            except DeliveryError:
                already = None
                hint = None  # cannot disprove a create that landed; stay uncertain
            if already:
                return record_pr(flow, already)
            if hint is None:
                flow.save(phase="REMOTE_UNCERTAIN")
                # Auth or repository errors usually break the follow-up lookup too; keep the likely
                # cause visible, but absence is unproven, so this stays uncertain.
                raise DeliveryError("REMOTE_UNCERTAIN", "PR creation failed without a definite GitHub verdict",
                                    code=4, gh_exit=code, gh_error=gh_error,
                                    hint=(("Likely cause: " + likely + ". ") if likely else "")
                                    + "Check `gh pr list`, then run prepare --reconcile-only",
                                    **flow.facts())
            flow.save(phase="REMOTE_BLOCKED")
            raise DeliveryError("REMOTE_BLOCKED", "GitHub refused to create the PR; nothing was created",
                                code=4, gh_exit=code, gh_error=gh_error, hint=hint, **flow.facts())
    finally:
        staged.unlink(missing_ok=True)
    try:
        found = matching_pr(flow.state, flow.args.timeout)
    except DeliveryError:
        flow.save(phase="REMOTE_UNCERTAIN")
        raise DeliveryError("REMOTE_UNCERTAIN", "PR creation outcome requires exact remote reconciliation",
                            code=4, **flow.facts()) from None
    if not found:
        flow.save(phase="REMOTE_UNCERTAIN")
        raise DeliveryError("REMOTE_UNCERTAIN", "PR creation is not yet visible; local fallback remains blocked",
                            code=4, **flow.facts())
    return record_pr(flow, found)


COMMIT_POLICY_RECORD = "commit-policy.json"
TARGET_OVERRIDE_RECORD = "target-policy-overrides.json"
TARGET_OVERRIDE_LIMIT = 20


def record_target_override_in_wal(args, bypassed):
    """Append the operator's --target-policy warn and what it bypassed to the WAL, or refuse to run."""
    override = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": "warn",
                "task": str(getattr(args, "task", ""))[:120], "bypassed": bypassed}
    names = ", ".join(item["reason"] for item in bypassed) or "none (no check was exceeded)"
    record = {"at": override["at"], "event": "risk", "id": "w" + secrets.token_hex(6),
              "note": f"deliver.py prepare --target-policy warn for task {override['task']}: bypassed {names}",
              "target_policy_override": override}
    try:
        wal_log.append(args.wal.expanduser().absolute(), record)
    except (OSError, ValueError):
        raise DeliveryError("BLOCKED_POLICY", "--target-policy warn could not be recorded in the WAL; nothing was done",
                            code=2, reason="TARGET_OVERRIDE_UNRECORDED",
                            hint="pass a per-session WAL path under ~/.claude/wals") from None
    return override


def record_target_override(flow, override):
    """Keep every warn-mode run of this generation beside its journal (the journal schema is fixed)."""
    path = flow.directory / TARGET_OVERRIDE_RECORD
    history = []
    if os.path.lexists(path):
        try:
            history = json.loads(regular_bytes(path, WAIVER_RECORD_LIMIT)).get("overrides", [])
        except (OSError, ValueError, DeliveryError, AttributeError):
            history = [{"mode": "unreadable-previous-record"}]
    history = (history if isinstance(history, list) else [])[-(TARGET_OVERRIDE_LIMIT - 1):] + [override]
    _write_private_json(path, {"schema": 1, "generation": flow.generation, "overrides": history})
WAIVER_RECORD_LIMIT = 1_048_576


def commit_policy_gate(source, original_branch, branch, head, baseline, title, body, local_only):
    """Refuse a new generation whose owner commits, PR text, or tickets break the policy.

    The range is the owner's own work: head minus baseline minus the tracked
    upstream tip, so upstream commits written by others are never judged here.
    Runs only before a generation is created; re-entry never repeats network checks.
    """
    try:
        import commit_policy
        policy = commit_policy.load_policy()
    except (ImportError, OSError, ValueError):
        raise DeliveryError("BLOCKED_COMMIT_POLICY", "Commit policy could not be loaded; refusing to publish",
                            code=2) from None
    tip_ref = f"refs/remotes/origin/{original_branch}"
    tip = commit_policy.git(source, "rev-parse", "-q", "--verify", tip_ref + "^{commit}", check=False).strip()
    exclude = [tip] if OID.match(tip) else []
    try:
        result = commit_policy.check_range(str(source), baseline, head, policy, branch=branch,
                                           verify_tickets=True, exclude=exclude)
    except (OSError, subprocess.TimeoutExpired):
        raise DeliveryError("BLOCKED_COMMIT_POLICY", "Commit range could not be inspected", code=2) from None
    origin = commit_policy.git(source, "remote", "get-url", "origin", check=False).strip() or None
    pr_problems = [] if local_only or policy.get("enforcement") == "off" else commit_policy.validate_pr(
        title, body.decode("utf-8", "replace"), policy,
        tickets_required=commit_policy.tickets_required_for(origin, policy))
    text = commit_policy.format_report(result)
    if pr_problems and policy.get("enforcement") != "warn":
        text += "\n  PR title/body (GitHub squash uses them as the final commit message):\n" + "\n".join(
            "      - " + item for item in pr_problems)
    warn = policy.get("enforcement") == "warn"
    if not warn and (result["status"] == "BLOCKED" or pr_problems):
        raise DeliveryError("BLOCKED_COMMIT_POLICY", "Commit messages, PR text or tickets break the commit policy; "
                            "fix them and run prepare again", code=2, commit_policy=text)
    if not warn and result["status"] == "UNVERIFIED":
        raise DeliveryError("TICKETS_UNVERIFIED", "Referenced tickets could not be verified (ticket system "
                            "unreachable); retry, or record a tickets waiver for this head", code=6,
                            commit_policy=text)
    if result["waivers"] or result.get("warnings") or warn and result["status"] != "PASS":
        print(text, file=sys.stderr)
    return {"exclude": exclude, "waivers": result["waivers"], "warnings": result.get("warnings", []),
            "tickets": [item["ticket"] for item in result["tickets"]]}


COMMIT_POLICY_PENDING = "commit-policy-pending.json"


def _write_private_json(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
        handle.flush()
        os.fsync(handle.fileno())


def stage_policy_record(flow, record, source_head, baseline):
    """Written before the generation exists, so a crash cannot lose the checked range."""
    private_directory(flow.root)
    _write_private_json(flow.root / COMMIT_POLICY_PENDING,
                        {"schema": 1, "source_head": source_head, "baseline": baseline, **record})


def write_policy_record(flow, record):
    _write_private_json(flow.directory / COMMIT_POLICY_RECORD, {"schema": 1, "generation": flow.generation, **record})
    (flow.root / COMMIT_POLICY_PENDING).unlink(missing_ok=True)


def ticket_updates(flow, stage, head, pr_url=None):
    """Comment delivery evidence on each referenced ticket; never undoes a delivery.

    Exit 5 from finish means delivered with a ticket update still pending.
    """
    try:
        return _ticket_updates(flow, stage, head, pr_url)
    except Exception as error:  # delivery already completed; report, never mask it
        return {"status": "PENDING", "error": type(error).__name__,
                "retry": "re-run the same deliver.py finish command (idempotent)"}


def _ticket_updates(flow, stage, head, pr_url):
    try:
        record = json.loads(regular_bytes(flow.directory / COMMIT_POLICY_RECORD))
    except (OSError, ValueError, DeliveryError):
        record = None
    if record is None:
        # Crash between staging and the generation write: adopt the staged record only
        # when it describes exactly this generation's range.
        try:
            staged = json.loads(regular_bytes(flow.root / COMMIT_POLICY_PENDING))
        except (OSError, ValueError, DeliveryError):
            staged = None
        if (isinstance(staged, dict) and staged.get("source_head") == flow.state["source_head"]
                and staged.get("baseline") == flow.state["baseline"]):
            record = {**staged, "generation": flow.generation}
    if record is None:
        # Neither record nor staged record: the generation was prepared before the policy.
        return {"status": "NOT_APPLICABLE", "reason": "generation predates the commit policy"}
    if record.get("generation") != flow.generation or not record.get("tickets"):
        return {"status": "NOT_APPLICABLE", "reason": "no referenced tickets"}
    import commit_policy
    policy = commit_policy.load_policy()
    lines = [f"- Mode: {flow.args.mode}", f"- Delivered head: `{head}`",
             f"- Source head: `{flow.state['source_head']}` on `{flow.state['source_branch']}`"]
    if pr_url:
        lines.append(f"- PR: {pr_url}")
    for check in flow.args.check:
        lines.append(f"- Check passed: `{check}`")
    lines.append("- Deploy: not observed by deliver.py; post deploy evidence with "
                 "`commit_policy.py notify --stage deployed`")
    for item in record.get("waivers", []):
        lines.append(f"- Waiver used: {item['kind']} {item['subject'][:12]} (id {item['id']})")
    for item in record.get("warnings", []):
        lines.append(f"- Not verified (project out of the credential's scope): {item['ticket']}")
    results = commit_policy.notify(str(flow.original), flow.state["baseline"], flow.state["source_head"], policy,
                                   operation_seed=flow.generation, evidence="\n".join(lines), stage=stage,
                                   exclude=record.get("exclude", []))
    pending = [item for item in results if item["status"] not in commit_policy.NOTIFY_DONE]
    retry = (f"python3 {Path(__file__).with_name('commit_policy.py')} notify --repo {flow.original} "
             f"--base {flow.state['baseline']} --head {flow.state['source_head']} --seed {flow.generation} "
             f"--stage {stage} --evidence '<delivery evidence>'"
             + "".join(f" --exclude {tip}" for tip in record.get("exclude", [])))
    return {"status": "PENDING" if pending else "UPDATED", "tickets": results,
            **({"retry": retry} if pending else {})}


def prepare(args):
    if getattr(args, "reconcile_only", False):
        return reconcile(args)
    override = None
    if args.original is not None and isinstance(args.original_branch, str):
        # Effective mode: the per-run flag, else the source default; either way warn must be recorded.
        mode = getattr(args, "target_policy", None) or TARGET_POLICY["mode"]
        if mode == "warn" and getattr(args, "wal", None) is None:
            raise DeliveryError("BLOCKED_POLICY", "--target-policy warn requires --wal so the override is recorded",
                                code=2, reason="TARGET_OVERRIDE_UNRECORDED",
                                hint="pass --wal <your session WAL under ~/.claude/wals>, or drop --target-policy warn")
        # Before any strict snapshot, so a huge dirty set gets a specific message, not a status timeout.
        bypassed = target_preflight(args.original.expanduser().absolute(), args.original_branch, mode)
        if mode == "warn":
            override = record_target_override_in_wal(args, bypassed)
    source, branch, head, baseline, kit = source_inputs(args)
    local_only = getattr(args, "local_only", False)
    title, body = "", b""
    if not local_only:
        require_arguments(args, "pr_title", "pr_body_file")
        title, body = args.pr_title, checked_body(args.pr_body_file)
        if (not valid_identity_text(title) or not 1 <= len(title.strip()) <= 200
                or any(ord(char) < 32 for char in title)):
            raise DeliveryError("BLOCKED_POLICY", "PR title is invalid", code=2)
    origin_error, repository, url = None, "", ""
    if not local_only:
        try:
            repository, url = matching_origins(source, args.original.expanduser().absolute())
        except DeliveryError as error:
            if error.status != "REMOTE_BLOCKED":
                raise
            origin_error = error
    with Workflow(args) as flow:
        state = flow.load()
        if state is not None and not getattr(args, "new_generation", False):
            if (state["source"] != str(source) or state["source_branch"] != branch
                    or state["source_head"] != head or state["baseline"] != baseline
                    or state["kit_digest"] != kit or (state["phase"] == "LOCAL_READY") != local_only
                    or state["repository"] != repository):
                raise DeliveryError("BLOCKED_POLICY", "Prepared scope differs; explicitly request a new generation", code=2)
        else:
            policy_record = commit_policy_gate(source, args.original_branch, branch, head, baseline,
                                               title, body, local_only)
            phase = "LOCAL_READY" if local_only else ("REMOTE_BLOCKED" if origin_error else "INITIAL")
            stage_policy_record(flow, policy_record, head, baseline)
            flow.create(source, branch, head, baseline, kit, repository, phase)
            write_policy_record(flow, policy_record)
            state = flow.state
        if override is not None:
            record_target_override(flow, override)
        if state["phase"] == "LOCAL_READY":
            report("LOCAL_READY", "Explicit local-only generation prepared", **flow.facts())
            return 0
        if state["phase"] == "REMOTE_BLOCKED":
            report("REMOTE_BLOCKED", "Remote publication blocked; reviewed local delivery remains available", **flow.facts())
            return 4
        if state["phase"] == "POLICY_BLOCKED":
            raise DeliveryError("BLOCKED_POLICY", "Prior policy refusal requires a new reviewed generation",
                                code=2, **flow.facts())
        if state["phase"] in {"DELIVERED", "LOCAL_DELIVERED"}:
            raise DeliveryError("ALREADY_PREPARED", "Generation is delivered; use finish for its receipt or start a new generation")
        if state["phase"] == "PR_READY":
            found = matching_pr(state, args.timeout)
            if not found or found["number"] != state["pr_number"]:
                raise DeliveryError("BLOCKED_POLICY", "Prepared PR no longer matches its scope", code=2)
            return record_pr(flow, found)
        if state["phase"] not in {"INITIAL", "PUBLISHING", "PR_LOOKUP", "PR_CREATING", "REMOTE_UNCERTAIN"}:
            raise DeliveryError("RECOVERY_REQUIRED", "Generation has pending checkout recovery", **flow.facts())
        if state["phase"] == "INITIAL":
            require_remote_base(flow, url)
            flow.save(phase="PUBLISHING")
            try:
                code, output = bounded([sys.executable, str(Path(__file__).with_name("publish_feature.py")),
                                        "--repo", str(source), "--branch", branch,
                                        "--original-branch", flow.branch, "--expected-head", head,
                                        "--expected-repository", repository, "--timeout", str(args.timeout)],
                                       # At most 24 sequential bounded Git waits,
                                       # including source guards and the one-deadline LFS scan.
                                       timeout=24 * args.timeout + 30)
                published = json.loads(output)
                if not isinstance(published, dict):
                    raise ValueError
            except (OSError, DeliveryError, ValueError):
                pass  # Durable PUBLISHING intent requires exact reconciliation.
            else:
                if (code == 0 and published.get("status") == "PUSHED"
                        and published.get("repository") == repository):
                    flow.save(phase="PR_LOOKUP")
                elif published.get("status") == "BLOCKED_POLICY":
                    flow.save(phase="POLICY_BLOCKED")
                    raise DeliveryError("BLOCKED_POLICY", "Publisher refused the pinned repository or source policy", code=2)
                elif code == 4 and published.get("push_rejected") is True:
                    flow.save(phase="POLICY_BLOCKED")
                    try:
                        published_ref(flow.original, url, flow.state, args.timeout)
                    except DeliveryError as error:
                        if error.status == "BLOCKED_POLICY":
                            raise
                    raise DeliveryError("BLOCKED_POLICY", "Remote refused the push; review a new branch generation",
                                        code=2, **flow.facts())
                elif code == 4 and published.get("push_attempted") is False:
                    flow.save(phase="REMOTE_BLOCKED")
                    raise DeliveryError("REMOTE_BLOCKED", "Publisher preflight failed before any push attempt",
                                        code=4, **flow.facts())
                else:
                    pass  # A failed push can still have reached the remote.
        if flow.state["phase"] == "PUBLISHING":
            try:
                published = published_ref(flow.original, url, flow.state, args.timeout)
            except DeliveryError as error:
                raise DeliveryError("REMOTE_UNCERTAIN", "Publisher completion is not yet positively verified",
                                    code=4, **{**flow.facts(), **error.facts}) from None
            if published is None:
                raise DeliveryError("REMOTE_UNCERTAIN", "An in-flight remote write cannot be disproved by temporary absence",
                                    code=4, **flow.facts())
            # Exact publication reconciled; any previous create is queried before another is attempted.
            flow.save(phase="PR_LOOKUP")
        if snapshot(source, branch) != head or snapshot(flow.original, flow.branch) != baseline:
            raise DeliveryError("RECHECK_REQUIRED", "Checkout moved during publication; inspect its remote outcome", **flow.facts())
        matching_origins(source, flow.original, repository)
        return prepare_pr(flow, title, body)


def github_target(repository, branch, timeout):
    data = gh_json("api", f"repos/{repository}/git/ref/heads/{quote(branch, safe='/')}", timeout=timeout)
    if (not isinstance(data, dict) or not isinstance(data.get("object"), dict)
            or data["object"].get("type") != "commit"):
        raise DeliveryError("REMOTE_BLOCKED", "GitHub branch target is invalid", code=4)
    return valid_oid(data["object"].get("sha"))


def verify_remote_pr(flow):
    state = flow.state
    if not state["repository"] or state["pr_number"] is None:
        raise DeliveryError("BLOCKED_POLICY", "Remote finish requires a verified PR_READY generation", code=2)
    pr = gh_json("pr", "view", str(state["pr_number"]), "-R", state["repository"], "--json", GH_FIELDS,
                 timeout=flow.args.timeout)
    if (not pr_identity(pr, state["repository"], state["source_branch"])
            or pr.get("number") != state["pr_number"] or pr.get("headRefOid") != state["source_head"]
            or pr.get("baseRefName") != flow.branch or not isinstance(pr.get("state"), str)
            or pr["state"] not in {"OPEN", "MERGED", "CLOSED"}):
        raise DeliveryError("BLOCKED_POLICY", "GitHub PR no longer matches the reviewed scope", code=2)
    return pr


def fetch_target(flow, url, target):
    named = Path(git_value(flow.original, "rev-parse", "--path-format=absolute", "--git-path", "objects"))
    if named.is_symlink():
        raise DeliveryError("BLOCKED_POLICY", "Symlinked object stores are unsupported", code=2)
    objects = named.resolve(strict=True)
    code, _ = transport(flow.original, url, flow.state["repository"],
                        ["fetch", "--no-tags", "--no-write-fetch-head", valid_oid(target)],
                        flow.args.timeout, objects=objects,
                        negotiation_tips=(flow.state["baseline"], flow.state["source_head"]))
    if code or git_value(flow.original, "cat-file", "-t", target) != "commit":
        raise DeliveryError("REMOTE_BLOCKED", "Exact verified target could not be fetched", code=4)
    flow.assert_context()


def task_generation_digest(flow):
    return hashlib.sha256("\0".join((flow.scope, flow.task, flow.generation)).encode()).hexdigest()


def observed_head(original):
    try:
        return valid_oid(git_value(original, "rev-parse", "HEAD"))
    except (DeliveryError, OSError):
        return None


def recovery_error(flow, message, base, *, journal=None, cause=None, evidence=None):
    head = observed_head(flow.original)
    facts = {**flow.facts(), **(evidence or {}), "head": head,
             "original_advanced": head is not None and head != base}
    if journal is not None:
        facts["recovery_journal"] = str(journal)
    if cause is not None:
        facts["cause"] = cause
    return DeliveryError("RECOVERY_REQUIRED", message, **facts)


def external_guard(flow, scope):
    key = flow.state["guard_key"]
    if key is None:
        return None
    guard = scope.load_external(key, task_generation_digest(flow))
    record = guard.record
    if record["phase"] == "resolved" and record["resolved_by"] == "operator":
        flow.save(phase="RESOLVED_BASELINE")
        raise DeliveryError("RESOLVED_BASELINE", "Recovery baseline accepted; review and prepare a new generation",
                            head=observed_head(flow.original), **flow.facts())
    if record["phase"] != "resolved":
        raise recovery_error(flow, "Pending external apply requires explicit tested-baseline resolution",
                             guard.base, journal=guard.journal)
    if (record["resolved_by"] != "workflow" or guard.target != flow.state["target"]
            or guard.base != flow.state["apply_base"]):
        raise recovery_error(flow, "External apply proof does not match this generation", guard.base,
                             journal=guard.journal)
    return guard


def verify_remote_descendant(flow, url, target, *, observed=None):
    """Prove a later advertised tip without applying its unrelated work."""
    observed = observed or github_target(flow.state["repository"], flow.branch, flow.args.timeout)
    if observed != target:
        fetch_target(flow, url, observed)
        if not ancestry(flow.original, target, observed):
            raise DeliveryError("RECHECK_REQUIRED", "Remote branch no longer contains the pinned target")
    return observed


def resume_binding(flow):
    """Pin the unchanged workflow files as well as their parsed metadata."""
    flow.assert_state()
    directories = (flow.root / "generations", flow.directory)
    files = (flow.root / "journal.json", flow.directory / "journal.json")
    return (tuple((info.st_dev, info.st_ino) for info in (path.lstat() for path in directories)),
            tuple((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                   info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                  for info in (path.lstat() for path in files)))


def resume_executor():
    """Record the followup executor without rewriting historical source bindings."""
    hooks = Path(__file__).resolve().parent
    names = ("deliver.py", "integrate_local.py", "process.py", "git_safety.py")
    observed = {name: (hooks / name).read_bytes() for name in names}
    revision = None
    if hooks.name == "hooks" and hooks.parent.name == "harness":
        repo = hooks.parent.parent
        code, top = git(repo, "rev-parse", "--show-toplevel")
        if code == 0 and Path(top.strip()).resolve() == repo:
            head = git_value(repo, "rev-parse", "--verify", "HEAD^{commit}")
            storage = git_value(repo, "rev-parse", "--show-object-format")
            code, tree = git(repo, "ls-tree", "-z", head, "--", *("harness/hooks/" + name for name in names))
            tracked = {}
            for entry in tree.split("\0"):
                if entry:
                    metadata, path = entry.split("\t", 1)
                    mode, kind, oid = metadata.split()
                    if mode in {"100644", "100755"} and kind == "blob":
                        tracked[path] = oid
            algorithm = {"sha1": hashlib.sha1, "sha256": hashlib.sha256}.get(storage)
            # Git blob IDs bind raw bytes, independently of index flags or
            # repository clean/textconv filters. HEAD alone proves no content.
            if (code == 0 and algorithm is not None and all(
                    stat.S_ISREG((hooks / name).lstat().st_mode)
                    and tracked.get("harness/hooks/" + name) == algorithm(
                        b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
                    and (hooks / name).read_bytes() == data for name, data in observed.items())
                    and git_value(repo, "rev-parse", "--verify", "HEAD^{commit}") == head):
                revision = head
    return {"protocol": "remote-resume-v1", "revision": revision,
            "helpers_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in observed.items()}}


def resume_remote_finish(flow, preparations, checks):
    """Resume only the same pending transaction already at its pinned target."""
    args, state = flow.args, flow.state
    digest = checks_digest(preparations, checks)
    if (state["phase"] != "REMOTE_APPLYING" or state["guard_key"] is None
            or state["checks_digest"] != digest or state["local_key"] is not None
            or any(state[name] is None for name in ("target", "merge_head", "apply_base", "pr_number"))):
        raise recovery_error(flow, "Resume requires the exact pending remote transaction",
                             state["apply_base"] or state["baseline"])
    with OriginalScope(flow.original, flow.branch, args.timeout) as scope:
        guard = scope.load_external(state["guard_key"], task_generation_digest(flow), create=False)
        if (guard.record["phase"] not in {"reserved", "applying"}
                or guard.target != state["target"] or guard.base != state["apply_base"]
                or not ancestry(flow.original, state["baseline"], guard.base)):
            raise recovery_error(flow, "Resume guard does not match the pending transaction",
                                 state["apply_base"], journal=guard.journal)
        binding = resume_binding(flow)

        def revalidate():
            if (resume_binding(flow) != binding
                    or kit_digest(args.kit_file) != state["kit_digest"]):
                raise recovery_error(flow, "Resume workflow or run kit changed", state["apply_base"])
            scope.validate_external(guard)

        revalidate()
        repository, url = origin_destination(flow.original)
        if repository != state["repository"]:
            raise DeliveryError("BLOCKED_POLICY", "Original repository changed since prepare", code=2)
        pr = verify_remote_pr(flow)
        merge = pr.get("mergeCommit")
        if (pr["state"] != "MERGED" or not isinstance(merge, dict)
                or merge.get("oid") != state["merge_head"]):
            raise recovery_error(flow, "Merged PR proof does not match the pending transaction", state["apply_base"])
        fetch_target(flow, url, state["target"])
        if not ancestry(flow.original, state["merge_head"], state["target"]):
            raise recovery_error(flow, "Merged PR is absent from the pinned target", state["apply_base"])
        verify_remote_descendant(flow, url, state["target"])
        revalidate()
        attempts = flow.directory / "resumes"
        private_directory(attempts)
        attempt = attempts / secrets.token_hex(16)
        attempt.mkdir(mode=0o700)
        fsync_directory(attempts)
        start = {"schema": 1, "kind": "delivery_resume", "generation": flow.generation,
                 "guard_key": guard.key, "target": guard.target, "checks_digest": digest,
                 "kit_digest": state["kit_digest"], "reason": args.resume_reason,
                 "executor": resume_executor()}
        private_directory(attempt / "start")
        write_journal(attempt / "start", start, first=True)
        try:
            revalidate()
            focused_recheck(flow, guard.target)
            run_checks(flow.original, preparations, checks, args.check_timeout, flow.directory / "checks")
            revalidate()
            if origin_destination(flow.original)[0] != state["repository"]:
                raise DeliveryError("BLOCKED_POLICY", "Original repository changed after checks", code=2)
            final_pr = verify_remote_pr(flow)
            final_merge = final_pr.get("mergeCommit")
            if (final_pr["state"] != "MERGED" or not isinstance(final_merge, dict)
                    or final_merge.get("oid") != state["merge_head"]):
                raise DeliveryError("RECHECK_REQUIRED", "Merged PR proof changed after resume checks")
            observed = verify_remote_descendant(flow, url, state["target"])
            revalidate()
            guard = scope.complete_external(guard)
            revalidate()
            flow.complete("remote", state["target"], digest)
        except (DeliveryError, ExternalApplyError, OSError, subprocess.TimeoutExpired) as error:
            # An incomplete attempt is evidence for diagnosis, never cached success.
            raise recovery_error(flow, "Resume did not complete; preserved transaction requires inspection",
                                 state["apply_base"], journal=guard.journal,
                                 cause=error.status if isinstance(error, DeliveryError) else None,
                                 evidence=check_facts(error)) from None
        private_directory(attempt / "final")
        write_journal(attempt / "final", {"schema": 1, "kind": "delivery_resume_result",
                      "generation": flow.generation, "status": "DELIVERED", "target": state["target"]}, first=True)
        tickets = ticket_updates(flow, "merged", state["target"])
        report("DELIVERED", "Pending remote delivery passed fresh checks at its pinned target",
               head=state["target"], receipt=str(flow.receipt), resume_record=str(attempt / "final" / "journal.json"),
               remote_observed_head=observed, ticket_updates=tickets, **flow.facts())
        return 5 if tickets["status"] == "PENDING" else 0


def remote_finish(flow, preparations, checks):
    args, state = flow.args, flow.state
    if state["phase"] not in {"PR_READY", "REMOTE_APPLYING"}:
        raise DeliveryError("BLOCKED_POLICY", "Remote finish requires a PR_READY generation", code=2)
    if state["phase"] == "REMOTE_APPLYING" and state["guard_key"] is None:
        raise recovery_error(flow, "Unbound interrupted apply requires explicit tested-baseline resolution",
                             state["apply_base"])
    # Operator recovery accepts a baseline, never a delivery receipt.
    if state["phase"] == "REMOTE_APPLYING" and state["guard_key"] is not None:
        with OriginalScope(flow.original, flow.branch, args.timeout) as scope:
            external_guard(flow, scope)
    repository, url = origin_destination(flow.original)
    if repository != state["repository"]:
        raise DeliveryError("BLOCKED_POLICY", "Original repository changed since prepare", code=2)
    pr = verify_remote_pr(flow)
    if pr["state"] == "CLOSED":
        raise DeliveryError("BLOCKED_POLICY", "PR was closed; review its scope before another generation", code=2)
    if pr["state"] != "MERGED":
        source = verify_source(flow)
        matching_origins(source, flow.original, state["repository"])
        report("PR_READY", "PR has not merged; original checkout remains pending", pr=pr["url"], **flow.facts())
        return 4
    merge = pr.get("mergeCommit")
    if not isinstance(merge, dict):
        raise DeliveryError("REMOTE_BLOCKED", "Merged PR has no verifiable merge commit", code=4)
    merge_head = valid_oid(merge.get("oid"))
    current_target = github_target(state["repository"], flow.branch, args.timeout)
    if state["phase"] == "REMOTE_APPLYING":
        target = state["target"]
        if state["merge_head"] != merge_head:
            raise recovery_error(flow, "In-flight remote target changed; reconcile the pinned attempt",
                                 state["apply_base"])
    else:
        target = current_target
    fetch_target(flow, url, target)
    if not ancestry(flow.original, merge_head, target):
        raise DeliveryError("BLOCKED_POLICY", "PR merge commit is absent from the remote target", code=2)
    verify_remote_descendant(flow, url, target, observed=current_target)
    digest, guard = checks_digest(preparations, checks), None
    with OriginalScope(flow.original, flow.branch, args.timeout) as scope:
        try:
            current = snapshot(flow.original, flow.branch)
            if not ancestry(flow.original, state["baseline"], current) or not ancestry(flow.original, current, target):
                raise DeliveryError("BLOCKED_LOCAL", "Original checkout diverges from the verified target", head=current)
            if flow.state["phase"] == "REMOTE_APPLYING" and flow.state["guard_key"] is not None:
                guard = external_guard(flow, scope)
            if guard is None:
                if flow.state["phase"] == "REMOTE_APPLYING" and current != flow.state["apply_base"]:
                    raise recovery_error(flow, "Original changed during an interrupted external apply",
                                         flow.state["apply_base"])
                if origin_destination(flow.original)[0] != state["repository"]:
                    raise DeliveryError("BLOCKED_POLICY", "Original repository changed before sync", code=2)
                verify_remote_descendant(flow, url, target)
                flow.save(phase="REMOTE_APPLYING", target=target, merge_head=merge_head,
                          apply_base=current, checks_digest=digest)
                guard = scope.reserve_external(base=current, target=target, task_digest=task_generation_digest(flow))
                flow.save(guard_key=guard.key)
                if snapshot(flow.original, flow.branch) != current:
                    raise DeliveryError("RECHECK_REQUIRED", "Original changed before fast-forward")
                if current != target:
                    code, _ = git(flow.original, "merge", "--ff-only", "--no-overwrite-ignore",
                                  "--no-autostash", target, timeout=args.timeout)
                    if code:
                        raise DeliveryError("BLOCKED_LOCAL", "Protected fast-forward was refused")
            if snapshot(flow.original, flow.branch) != target:
                raise DeliveryError("DELIVERED_CHECK_FAILED", "Original changed during sync")
            focused_recheck(flow, target)
            run_checks(flow.original, preparations, checks, args.check_timeout, flow.directory / "checks")
            if snapshot(flow.original, flow.branch) != target:
                raise DeliveryError("DELIVERED_CHECK_FAILED", "Checks changed the delivered checkout")
            if origin_destination(flow.original)[0] != state["repository"]:
                raise DeliveryError("BLOCKED_POLICY", "Original repository changed after sync", code=2)
            final_pr = verify_remote_pr(flow)
            final_merge = final_pr.get("mergeCommit")
            if (final_pr["state"] != "MERGED" or not isinstance(final_merge, dict)
                    or final_merge.get("oid") != merge_head):
                raise DeliveryError("RECHECK_REQUIRED", "Merged PR proof changed after sync")
            observed_remote = verify_remote_descendant(flow, url, target)
            guard = scope.complete_external(guard)
            flow.complete("remote", target, digest)
        except ExternalApplyError as error:
            owned = None
            if flow.state["guard_key"] is None and error.journal is not None:
                key = error.journal.parent.name
                if HEX64.fullmatch(key):
                    try:
                        owned = scope.load_external(key, task_generation_digest(flow))
                    except ExternalApplyError:
                        pass
                    else:
                        flow.save(guard_key=owned.key)
            if error.reservation_started is False and owned is None:
                # Explicit no-write proof permits retry; a known older own
                # artifact still requires recovery. Absence alone proves none.
                flow.save(phase="PR_READY", target=None, merge_head=None, apply_base=None,
                          guard_key=None, checks_digest=None)
            raise recovery_error(flow, "External apply could not complete; inspect its preserved recovery state",
                                 flow.state["apply_base"] or current, journal=error.journal) from None
        except (DeliveryError, OSError, subprocess.TimeoutExpired) as error:
            if flow.state["phase"] == "REMOTE_APPLYING":
                raise recovery_error(flow, "External apply requires recovery; no completion was recorded",
                                     flow.state["apply_base"], journal=guard.journal if guard else None,
                                     cause=error.status if isinstance(error, DeliveryError) else "IO_FAILURE",
                                     evidence=check_facts(error)) from None
            raise
    tickets = ticket_updates(flow, "merged", target, pr["url"])
    report("DELIVERED", "Merged PR is present in the checked original checkout", head=target,
           receipt=str(flow.receipt), pr=pr["url"], remote_observed_head=observed_remote,
           ticket_updates=tickets, **flow.facts())
    return 5 if tickets["status"] == "PENDING" else 0


def local_completion(flow, preparations, checks):
    """Reconcile the child's journal while holding the shared original lock."""
    from integrate_local import scan_journals
    with OriginalScope(flow.original, flow.branch, flow.args.timeout) as scope:
        blocked_path, blocked, completed = scan_journals(scope.root, flow.original, scope.identity,
                                                        flow.branch, flow.state["local_key"], flow.args.timeout)
        if blocked_path is not None:
            raise recovery_error(flow, "Local integration has unresolved recovery state", flow.state["baseline"],
                                 journal=blocked_path / "journal.json")
        if completed is not None and completed.get("phase") == "resolved":
            flow.save(phase="RESOLVED_BASELINE")
            raise DeliveryError("RESOLVED_BASELINE", "Local recovery baseline accepted; prepare a new reviewed generation",
                                head=observed_head(flow.original), **flow.facts())
        current = snapshot(flow.original, flow.branch)
        if (completed is None and not ancestry(flow.original, flow.state["source_head"], flow.state["baseline"])):
            return False
        if not ancestry(flow.original, flow.state["source_head"], current):
            raise recovery_error(flow, "Local delivery is absent from current checkout", flow.state["baseline"])
        run_checks(flow.original, preparations, checks, flow.args.check_timeout, flow.directory / "checks")
        if snapshot(flow.original, flow.branch) != current:
            raise recovery_error(flow, "Local checks changed the delivered checkout", flow.state["baseline"])
        flow.complete("local", current, checks_digest(preparations, checks))
        tickets = ticket_updates(flow, "delivered-local", current)
        flow.ticket_exit = 5 if tickets["status"] == "PENDING" else 0
        report("LOCAL_DELIVERED", "Checked local integration complete; remote publication remains outstanding",
               head=current, receipt=str(flow.receipt), ticket_updates=tickets, **flow.facts())
        return True


def local_finish(flow, preparations, checks):
    state = flow.state
    if state["phase"] not in {"REMOTE_BLOCKED", "LOCAL_READY", "LOCAL_APPLYING"}:
        raise DeliveryError("BLOCKED_POLICY", "Local finish requires explicit local-only mode or settled remote failure", code=2)
    source = Path(state["source"])
    key = journal_key(flow.identity, flow.branch, state["baseline"], state["source_branch"], state["source_head"])
    if state["phase"] == "LOCAL_APPLYING":
        if state["local_key"] != key:
            raise DeliveryError("RECOVERY_REQUIRED", "Local attempt identity changed")
        if local_completion(flow, preparations, checks):
            return getattr(flow, "ticket_exit", 0)
    verify_source(flow)
    if git_common_directory(source, 30)[0] != flow.common:
        raise DeliveryError("BLOCKED_POLICY", "Local delivery requires worktrees of the same repository", code=2)
    current = snapshot(flow.original, flow.branch)
    if current != state["baseline"]:
        raise recovery_error(flow, "Original changed before local delivery; inspect its prior attempt", state["baseline"])
    flow.save(phase="LOCAL_APPLYING", local_key=key, apply_base=current,
              checks_digest=checks_digest(preparations, checks))
    if ancestry(flow.original, state["source_head"], state["baseline"]):
        if local_completion(flow, preparations, checks):
            return getattr(flow, "ticket_exit", 0)
    # A fresh generation must let the child retire an older resolved tuple.
    # Only resumed generations interpret their resolved journal as acceptance.
    # The child owns the original scope lock; the parent holds only its task lock.
    command = [sys.executable, str(Path(__file__).with_name("integrate_local.py")), "--repo", str(flow.original),
               "--original-branch", flow.branch, "--expected-head", current, "--source", state["source_branch"],
               "--expected-source-head", state["source_head"],
               "--timeout", str(flow.args.timeout), "--check-timeout", str(flow.args.check_timeout)]
    for name in ("prepare", "check"):
        for value in getattr(flow.args, name):
            command.extend(("--" + name, value))
    if getattr(flow, "focused_checks", None):
        command.append("--allow-focused-checks")  # only after focused_proof approved every focused check
    try:
        # Each preparation/check gets its check deadline; Git steps keep --timeout.
        code, output = bounded(command, timeout=2 * (len(checks) + len(preparations)) * flow.args.check_timeout
                               + 10 * flow.args.timeout + 15)
        result = json.loads(output)
        if not isinstance(result, dict):
            raise ValueError
    except (DeliveryError, OSError, ValueError):
        raise recovery_error(flow, "Local integration outcome requires journal reconciliation", current) from None
    if code or result.get("status") not in {"INTEGRATED", "ALREADY_INTEGRATED"}:
        raise recovery_error(flow, "Local integration did not complete; inspect its recovery journal", current,
                             journal=result.get("journal") if isinstance(result.get("journal"), str) else None)
    if not local_completion(flow, preparations, checks):
        raise recovery_error(flow, "Local helper has no verified completion proof", current)
    return getattr(flow, "ticket_exit", 0)


def configure_compare(args, checks, state):
    """Validate --baseline-compare (and --use-recorded-baseline) and arm ACTIVE_COMPARE; refuses everything it does not
    fully understand. Without the flag nothing here runs and an exit-0 check stays required."""
    ACTIVE_COMPARE.clear()
    if getattr(args, "use_recorded_baseline", False) and not getattr(args, "baseline_compare", False):
        raise DeliveryError("BLOCKED_POLICY", "--use-recorded-baseline needs --baseline-compare", code=2)
    if not getattr(args, "baseline_compare", False):
        return
    if args.resolve_baseline is None and args.mode != "remote":
        raise DeliveryError("BLOCKED_POLICY", "--baseline-compare supports remote delivery and --resolve-baseline, not local mode", code=2)
    if getattr(args, "resume", False):
        raise DeliveryError("BLOCKED_POLICY", "--baseline-compare does not apply to --resume", code=2)
    if checks != [WHOLE_SUITE_ARGV]:
        raise DeliveryError("BLOCKED_POLICY", "--baseline-compare needs exactly one check, the whole suite "
                            "'python3 -m unittest discover -s tests'; a focused, partial or other check is refused", code=2)
    if getattr(args, "use_recorded_baseline", False) and args.resolve_baseline is None:
        raise DeliveryError("BLOCKED_POLICY", "--use-recorded-baseline applies only to --resolve-baseline", code=2)
    expected = valid_oid(args.resolve_baseline) if args.resolve_baseline is not None else state["baseline"]
    ACTIVE_COMPARE.update(expected_sha=expected, recorded_only=bool(getattr(args, "use_recorded_baseline", False)))


def finish(args):
    preparations, checks = approved_commands(args.prepare, prepare=True), approved_commands(args.check, allow_focused=True)
    focused = [argv for argv in checks if not approved_check(argv)]  # accepted syntactically; proven below
    try:
        return _finish(args, preparations, checks, focused)
    finally:
        ACTIVE_COMPARE.clear()


def _finish(args, preparations, checks, focused):
    try:
        # Before any checkout effect: a bare python3 that resolves to an
        # unsupported interpreter would only fail after the fast-forward.
        require_check_interpreters(checks)
    except CheckInterpreterError as error:
        raise DeliveryError("BLOCKED_POLICY", str(error), code=2) from None
    with Workflow(args) as flow:
        state = flow.load()
        if state is None:
            raise DeliveryError("BLOCKED_POLICY", "Prepared generation is missing", code=2)
        if args.kit_file is not None and kit_digest(args.kit_file) != state["kit_digest"]:
            raise DeliveryError("BLOCKED_POLICY", "Run kit changed since prepare", code=2)
        configure_compare(args, checks, state)
        if focused and args.resolve_baseline is not None:
            raise DeliveryError("BLOCKED_POLICY", "A recovery baseline needs a whole-suite check, not a focused one", code=2)
        flow.focused_checks = focused_proof(flow, focused) if focused else []
        if args.resolve_baseline is not None:
            return resolve_baseline(flow, preparations, checks)
        if args.resume:
            return resume_remote_finish(flow, preparations, checks)
        old = flow.completed()
        if old is not None:
            if old["mode"] != args.mode:
                raise DeliveryError("BLOCKED_POLICY", "Generation was delivered using another mode", code=2)
            # Idempotent: a repeat retries any pending ticket comment without duplicating it.
            tickets = ticket_updates(flow, "delivered-local" if args.mode == "local" else "merged", old["head"])
            report("ALREADY_DELIVERED", "Historical delivery remains present; no new remote work was synchronized",
                   head=old["head"], current_head=old["current_head"], receipt=str(flow.receipt),
                   remote_publication="outstanding" if args.mode == "local" else "previously_merged",
                   ticket_updates=tickets, **flow.facts())
            return 5 if tickets["status"] == "PENDING" else 0
        if state["phase"] == "RESOLVED_BASELINE":
            raise DeliveryError("RESOLVED_BASELINE", "Baseline accepted; review and prepare a new generation", **flow.facts())
        return remote_finish(flow, preparations, checks) if args.mode == "remote" else local_finish(flow, preparations, checks)



def resolve_baseline(flow, preparations, checks):
    """Settle an interrupted workflow after actual shared barriers are resolved."""
    from integrate_local import scan_journals
    if flow.state["phase"] not in {"REMOTE_APPLYING", "LOCAL_APPLYING"}:
        raise DeliveryError("BLOCKED_POLICY", "Only an interrupted apply can accept a new baseline", code=2)
    confirmed = valid_oid(flow.args.resolve_baseline)
    if len(confirmed) != len(flow.state["baseline"]):
        raise DeliveryError("BLOCKED_POLICY", "Baseline object format differs from the reviewed scope", code=2)
    with OriginalScope(flow.original, flow.branch, flow.args.timeout) as scope:
        blocked, _, _ = scan_journals(scope.root, flow.original, scope.identity, flow.branch,
                                      "0" * 64, flow.args.timeout)
        if blocked is not None:
            raise recovery_error(flow, "Resolve actual shared recovery journals before accepting this workflow baseline",
                                 flow.state["baseline"], journal=blocked / "journal.json")
        if snapshot(flow.original, flow.branch) != confirmed:
            raise DeliveryError("RECOVERY_REQUIRED", "Confirmed baseline HEAD changed")
        try:
            run_checks(flow.original, preparations, checks, flow.args.check_timeout, flow.directory / "checks")
        except DeliveryError as error:
            raise DeliveryError("RECOVERY_REQUIRED", "Baseline checks did not validate the confirmed checkout",
                                **check_facts(error)) from None
        if snapshot(flow.original, flow.branch) != confirmed:
            raise DeliveryError("RECOVERY_REQUIRED", "Baseline checks changed the confirmed checkout")
        # save rereads both the exact generation pointer and loaded state.
        flow.save(phase="RESOLVED_BASELINE")
    report("RESOLVED_BASELINE", "Tested baseline accepted; review and prepare a new generation before delivery",
           head=confirmed, **flow.facts())
    return 0


def reconcile(args):
    if getattr(args, "new_generation", False) or getattr(args, "local_only", False):
        raise DeliveryError("BLOCKED_POLICY", "Reconciliation cannot create or supersede a generation", code=2)
    with Workflow(args) as flow:
        state = flow.load()
        if state is None:
            raise DeliveryError("BLOCKED_POLICY", "No prepared generation to reconcile", code=2)
        if state["phase"] not in {"PUBLISHING", "PR_LOOKUP", "PR_CREATING", "REMOTE_UNCERTAIN", "PR_READY"}:
            report("RECONCILED", "Stored generation has no uncertain remote publication", phase=state["phase"], **flow.facts())
            return 0
        for name, expected in (("expected_source_head", state["source_head"]),
                               ("expected_original_head", state["baseline"])):
            provided = getattr(args, name, None)
            if provided is not None and provided != expected:
                raise DeliveryError("BLOCKED_POLICY", "Reconciliation cannot substitute reviewed scope", code=2)
        if args.kit_file is not None and kit_digest(args.kit_file) != state["kit_digest"]:
            raise DeliveryError("BLOCKED_POLICY", "Reconciliation cannot substitute the reviewed run kit", code=2)
        repository, url = origin_destination(flow.original)
        if repository != state["repository"]:
            raise DeliveryError("BLOCKED_POLICY", "Original repository changed before reconciliation", code=2)
        if state["phase"] == "PUBLISHING":
            try:
                observed = published_ref(flow.original, url, state, args.timeout)
            except DeliveryError as error:
                raise DeliveryError("REMOTE_UNCERTAIN", "Publisher completion is not yet positively verified",
                                    code=4, **{**flow.facts(), **error.facts}) from None
            if observed is None:
                raise DeliveryError("REMOTE_UNCERTAIN", "Temporary ref absence cannot settle an in-flight push",
                                    code=4, **flow.facts())
            flow.save(phase="PR_LOOKUP")
            state = flow.state
        try:
            found = verify_remote_pr(flow) if state["pr_number"] is not None else matching_pr(state, args.timeout)
        except DeliveryError as error:
            if state["phase"] in {"PR_CREATING", "REMOTE_UNCERTAIN"}:
                flow.save(phase="REMOTE_UNCERTAIN")
                raise DeliveryError("REMOTE_UNCERTAIN", "A failed lookup cannot settle an in-flight create",
                                    code=4, **flow.facts()) from None
            if error.status == "BLOCKED_POLICY":
                flow.save(phase="POLICY_BLOCKED")
            if error.status == "REMOTE_BLOCKED":
                raise DeliveryError("REMOTE_UNCERTAIN", "Remote PR visibility cannot yet be reconciled",
                                    code=4, **flow.facts()) from None
            raise
        if found is not None:
            if found["state"] == "CLOSED":
                raise DeliveryError("BLOCKED_POLICY", "Known PR is closed; it cannot become local fallback", code=2)
            return record_pr(flow, found)
        if state["phase"] in {"PR_CREATING", "REMOTE_UNCERTAIN"}:
            flow.save(phase="REMOTE_UNCERTAIN")
            raise DeliveryError("REMOTE_UNCERTAIN", "No positive PR completion is visible; fallback remains blocked",
                                code=4, **flow.facts())
        try:
            observed = published_ref(flow.original, url, state, args.timeout)
        except DeliveryError as error:
            if error.status == "BLOCKED_POLICY":
                flow.save(phase="POLICY_BLOCKED")
            raise
        if state["phase"] == "PR_LOOKUP":
            # These durable phases precede any PR-create call. Positive push
            # completion plus a complete lookup settles only that known stage.
            flow.save(phase="REMOTE_BLOCKED")
            report("REMOTE_BLOCKED", "The completed push stage has no PR-create attempt; local delivery remains available",
                   **flow.facts())
            return 4
        flow.save(phase="REMOTE_UNCERTAIN")
        raise DeliveryError("REMOTE_UNCERTAIN", "No positive remote completion is visible; fallback remains blocked",
                            code=4, **flow.facts())


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    for name in ("prepare", "finish"):
        part = sub.add_parser(name)
        part.add_argument("--task", required=True, help="Stable owner task name; state is checkout-scoped")
        part.add_argument("--original", type=Path, required=True)
        part.add_argument("--original-branch", required=True)
        part.add_argument("--generation", help="Require this exact current generation")
        part.add_argument("--kit-file", type=Path,
                          help="mode-0600 run kit, e.g. ~/.agent-harness/work/<session-id>/<task>/kit.json (not /tmp)")
        part.add_argument("--timeout", type=int, default=120, help="Seconds for each Git and GitHub command")
    prep = sub.choices["prepare"]
    prep.add_argument("--source", type=Path)
    prep.add_argument("--expected-source-head")
    prep.add_argument("--expected-original-head")
    prep.add_argument("--pr-title")
    prep.add_argument("--pr-body-file", type=Path,
                      help="mode-0600 PR body, e.g. ~/.agent-harness/work/<session-id>/<task>/pr-body.md")
    prep.add_argument("--reconcile-only", action="store_true", help="Query a pending remote outcome without publishing or changing checkout")
    prep.add_argument("--local-only", action="store_true", help="Explicitly choose guarded local delivery")
    prep.add_argument("--target-policy", choices=("refuse", "warn"), default=None,
                      help="Original-checkout sanity preflight: refuse (default) or warn and continue; "
                           "warn is per run, needs --wal, and is recorded in the WAL, the generation and the output")
    prep.add_argument("--wal", type=Path, default=None,
                      help="Session WAL (~/.claude/wals/<session>/<name>.jsonl) that records a --target-policy warn run")
    prep.add_argument("--new-generation", action="store_true", help="Supersede only a settled generation")
    end = sub.choices["finish"]
    finish_mode = end.add_mutually_exclusive_group(required=True)
    finish_mode.add_argument("--mode", choices=("remote", "local"))
    finish_mode.add_argument("--resolve-baseline", help="Accept only this full clean tested HEAD; never delivery")
    end.add_argument("--check", action="append", default=[])
    end.add_argument("--prepare", action="append", default=[])
    end.add_argument("--check-timeout", type=int, default=DEFAULT_CHECK_TIMEOUT,
                     help="Seconds allowed for each preparation and check command (default 1800)")
    end.add_argument("--baseline-compare", action="store_true",
                     help="Pass the whole-suite check when its failing test ids are an exact subset of the complete suite "
                          "baseline recorded for exactly the pinned original HEAD (test_scope.py run-baseline); no waiver")
    end.add_argument("--use-recorded-baseline", action="store_true",
                     help="With --resolve-baseline --baseline-compare: accept the recorded real suite run at that HEAD without re-running")
    end.add_argument("--resume", action="store_true", help="Explicitly resume this pending remote delivery at its pinned target")
    end.add_argument("--resume-reason", help="Bounded private explanation for resuming an interrupted attempt")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600 seconds")
    if args.phase == "finish" and not 1 <= args.check_timeout <= MAX_CHECK_TIMEOUT:
        parser.error(f"--check-timeout must be between 1 and {MAX_CHECK_TIMEOUT} seconds")
    if args.phase == "finish":
        if args.resume and (args.mode != "remote" or not args.generation or args.kit_file is None):
            parser.error("--resume requires --mode remote, --generation and --kit-file")
        if args.resume:
            if (not valid_identity_text(args.resume_reason) or not 1 <= len(args.resume_reason.strip()) <= 512
                    or any(ord(char) < 32 for char in args.resume_reason)):
                parser.error("--resume requires a nonempty reason of at most 512 characters without control characters")
        elif args.resume_reason is not None:
            parser.error("--resume-reason requires --resume")
    return args


def main():
    args = parse_args()
    try:
        # Editor variables never route git (every git call here passes -m or -F), and Claude Code sessions export
        # GIT_EDITOR, so drop them for this process and its children instead of refusing the whole run.
        for name in IGNORED_GIT_ENV + SCRUBBED_ENV:
            os.environ.pop(name, None)
        bad = sorted(name for name in os.environ if name.startswith("GIT_") and name not in ALLOWED_GIT_ENV)
        if bad:
            raise DeliveryError("BLOCKED_POLICY", "Unsupported Git routing environment: " + ", ".join(bad[:5]), code=2)
        return prepare(args) if args.phase == "prepare" else finish(args)
    except DeliveryError as error:
        report(error.status, error.message, **error.facts)
        return error.code
    except ExternalApplyError as error:
        report("RECOVERY_REQUIRED", "Original scope is busy, unsafe, or needs explicit recovery",
               recovery_journal=str(error.journal) if error.journal else None)
        return 3
    except (OSError, subprocess.TimeoutExpired):
        report("RECOVERY_REQUIRED", "Delivery operation could not complete; inspect its preserved private state")
        return 3


if __name__ == "__main__":
    sys.exit(main())
