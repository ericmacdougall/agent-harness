#!/usr/bin/env python3
"""bg_job: launch a background job and learn its REAL outcome (GoodQA #14513 and #14472).

Why this exists. Two incidents with the same root cause: a shell chain reported success without evidence.
  * `cmd1; nohup suite & echo started` printed "started" although cmd1 had failed; two reruns never ran (1.5 h lost).
  * A background wait loop exited 0 because its last command was `ls`; a garbage-collected systemd transient unit
    even reports Result=success after it failed.
This helper replaces both: STARTED is printed only after evidence, and `wait` returns the exit status that a wrapper
wrote atomically to a status file. Anything unproven fails closed.

  bg_job.py launch --name N --log L --deadline S [--dir D] -- ARGV...
      Starts ARGV (an argv list, never a shell string) in a new session, stdout and stderr appended to L, behind a
      wrapper that records the exit status. Prints `STARTED name=N pid=P ...` and exits 0 only when the wrapper PID is
      alive, the log exists and the log has grown, all within S seconds. Otherwise `FAILED_TO_START reason=...`,
      exit 3, and the job it started is stopped (only the process group it created).
  bg_job.py wait --name N [--timeout S] [--dir D]
      exit 0 only when the status file says the job exited 0. Exit 1: the job ran and failed (EXIT_STATUS=n).
      Exit 2: no trustworthy status (missing, garbled, wrong job, or dead with no status) -> fail closed.
      Exit 3: timeout while still running.
  bg_job.py status --name N [--dir D]
      Prints RUNNING / EXITED status=n / LOST / ... (exit 0 for a readable record, 2 otherwise).

Records live in --dir, else $BG_JOB_DIR, else $AGENT_HARNESS_TASK_DIR/bg-jobs, else ./.bg-jobs. A record holds the
PID, start time, log path, status path, argv hash and a nonce. PID liveness is proven by the process command line
carrying the nonce, so a reused PID is not mistaken for the job.

Not for secrets: argv is stored in the record. Per-stage pipeline status: use `set -o pipefail`, or write each stage
to its own file; `X=$(a | b)` followed by PIPESTATUS gives only the assignment's status.

Stdlib only; Python 3.9+.
"""

from __future__ import annotations

import argparse
import hashlib
import fcntl
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safe_input  # noqa: E402  (bounded reads of files we did not just write)

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_RECORD_BYTES = 64 * 1024
EXIT_OK, EXIT_JOB_FAILED, EXIT_UNPROVEN, EXIT_TIMEOUT = 0, 1, 2, 3
EXIT_FAILED_TO_START = 3
EXIT_USAGE = 64


def job_dir(arg):
    if arg:
        return os.path.abspath(arg)
    if os.environ.get("BG_JOB_DIR"):
        return os.path.abspath(os.environ["BG_JOB_DIR"])
    if os.environ.get("AGENT_HARNESS_TASK_DIR"):
        return os.path.join(os.path.abspath(os.environ["AGENT_HARNESS_TASK_DIR"]), "bg-jobs")
    return os.path.abspath(".bg-jobs")


def argv_hash(argv):
    return hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode("utf-8")).hexdigest()


def atomic_write_json(path, obj):
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(obj, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)  # atomic: a reader sees the old file or the whole new one
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path):
    """(object, None) or (None, reason). Bounded; a directory, FIFO or huge file is a reason, not a hang."""
    if not os.path.lexists(path):
        return None, "missing"
    try:
        raw = safe_input.read_bounded(path, MAX_RECORD_BYTES)
    except (safe_input.InputRejected, OSError) as exc:
        return None, "unreadable: %s" % exc
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "garbled"
    if not isinstance(obj, dict):
        return None, "garbled"
    return obj, None


def pid_is_job(pid, nonce):
    """True only when PID is alive AND its command line is our wrapper carrying this job's nonce."""
    if not isinstance(pid, int) or isinstance(pid, bool) or not 1 < pid < 2 ** 31:
        return False
    if not isinstance(nonce, str) or not re.match(r"^[0-9a-f]{32}$", nonce):
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # alive but not ours; the command-line check below decides
    try:
        out = subprocess.run(["ps", "-ww", "-p", str(pid), "-o", "command="], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return False
    return ("_run" in out) and (nonce in out)


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_group(pid, nonce, own=False):
    """Stop a job's process group. `own` is True only for the launcher, which created the group and is still the
    wrapper's parent, so the group id cannot belong to anyone else. Otherwise the wrapper's identity is proven first.
    SIGKILL follows the grace period whenever the group still has members, even after the wrapper itself died
    (a SIGTERM-ignoring job outlives its wrapper)."""
    if not own and not pid_is_job(pid, nonce):
        return
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return
    for sig, wait in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        end = time.time() + wait
        while time.time() < end and group_alive(pid):
            time.sleep(0.05)
        if not group_alive(pid):
            return


def read_status(record):
    """(exit_code, None) or (None, reason). Validates shape, type and that it belongs to this job."""
    obj, why = read_json(record["status"])
    if obj is None:
        return None, why
    code = obj.get("exit")
    if obj.get("nonce") != record["nonce"]:
        return None, "status belongs to another job"
    if isinstance(code, bool) or not isinstance(code, int):
        return None, "garbled"
    return code, None


def load_record(directory, name):
    if not NAME_RE.match(name or ""):
        return None, "bad job name"
    obj, why = read_json(os.path.join(directory, name + ".json"))
    if obj is None:
        return None, "no job record (%s)" % why
    for key in ("pid", "nonce", "status", "log", "argv_sha256"):
        if key not in obj:
            return None, "job record incomplete"
    if obj.get("failed"):
        return None, "job failed to start (%s)" % str(obj["failed"])[:120]
    pid = obj["pid"]
    if (isinstance(pid, bool) or not isinstance(pid, int) or not 1 < pid < 2 ** 31
            or not isinstance(obj["nonce"], str) or not re.match(r"^[0-9a-f]{32}$", obj["nonce"])
            or not isinstance(obj["status"], str) or not isinstance(obj["log"], str)):
        return None, "job record invalid"
    return obj, None


def cmd_run(args):
    """Wrapper (internal). Runs the job, then publishes its real exit status atomically."""
    started = time.time()
    code, note = 127, ""
    try:
        fd = os.open(args.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError as exc:
        atomic_write_json(args.status, {"exit": 126, "nonce": args.nonce, "note": "log not creatable: %s" % exc.strerror,
                                        "start": started, "end": time.time()})
        return 126
    try:
        try:
            child = subprocess.Popen(args.argv, stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.STDOUT)
            rc = child.wait()
            code = rc if rc >= 0 else 128 - rc  # killed by signal n -> 128+n, as shells report
            note = "signal %d" % -rc if rc < 0 else ""
        except OSError as exc:
            code, note = 127, "exec failed: %s" % exc.strerror
    finally:
        os.close(fd)
        atomic_write_json(args.status, {"exit": code, "nonce": args.nonce, "note": note, "start": started,
                                        "end": time.time()})
    return code


def cmd_launch(args):
    if not NAME_RE.match(args.name):
        print("FAILED_TO_START reason=bad job name (use letters, digits, . _ -)")
        return EXIT_USAGE
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("FAILED_TO_START reason=no command given after --")
        return EXIT_USAGE
    if not math.isfinite(args.deadline) or args.deadline <= 0 or args.deadline > 3600:
        print("FAILED_TO_START reason=deadline must be 1..3600 seconds")
        return EXIT_USAGE
    directory = job_dir(args.dir)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    lock = open(os.path.join(directory, args.name + ".lock"), "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("FAILED_TO_START reason=another launch of %s is in progress" % args.name)
        return EXIT_FAILED_TO_START
    return _launch_locked(args, argv, directory)  # the lock lives as long as this process holds `lock`


def _launch_locked(args, argv, directory):
    old, _ = load_record(directory, args.name)
    if old and pid_is_job(old.get("pid"), old.get("nonce", "")):
        print("FAILED_TO_START reason=job %s is already running (pid %s)" % (args.name, old["pid"]))
        return EXIT_FAILED_TO_START
    log = os.path.abspath(args.log)
    nonce = uuid.uuid4().hex
    status = os.path.join(directory, args.name + ".status")
    for stale in (status,):
        try:
            os.unlink(stale)  # only this job's own status path, inside the job dir
        except FileNotFoundError:
            pass
    try:
        before = os.stat(log).st_size
    except OSError:
        before = None  # not existing yet: creating it is part of the proof
    wrapper = [sys.executable, os.path.abspath(__file__), "_run", "--log", log, "--status", status,
               "--nonce", nonce, "--"] + argv
    proc = subprocess.Popen(wrapper, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True, close_fds=True)
    try:
        atomic_write_json(os.path.join(directory, args.name + ".json"),
                          {"name": args.name, "pid": proc.pid, "nonce": nonce, "start": time.time(), "log": log,
                           "status": status, "argv_sha256": argv_hash(argv), "argv": argv, "deadline": args.deadline})
        return supervise(args, proc, nonce, log, status, argv, before)
    except BaseException as exc:  # never leave a started job without a record or an owner
        proc.poll()
        stop_group(proc.pid, nonce, own=True)
        print("FAILED_TO_START name=%s reason=internal error after start (%s: %s); job stopped" %
              (args.name, type(exc).__name__, exc))
        return EXIT_FAILED_TO_START


def supervise(args, proc, nonce, log, status, argv, before):
    record = {"pid": proc.pid, "nonce": nonce, "status": status, "argv_sha256": argv_hash(argv)}

    def fail(reason):
        proc.poll()
        stop_group(proc.pid, nonce, own=True)
        try:  # a later `wait` must not read an immediate exit 0 as success of a launch reported as failed
            atomic_write_json(os.path.join(os.path.dirname(status), args.name + ".json"),
                              {"name": args.name, "pid": proc.pid, "nonce": nonce, "log": log, "status": status,
                               "argv_sha256": argv_hash(argv), "failed": reason})
        except OSError:
            pass
        print("FAILED_TO_START name=%s reason=%s log=%s" % (args.name, reason, log))
        return EXIT_FAILED_TO_START

    end = time.time() + args.deadline
    reason = "log did not grow within %ss" % args.deadline
    while time.time() < end:
        proc.poll()  # reap our own child so a dead wrapper is not a zombie that still answers kill -0
        code, _ = read_status(record)
        if code is not None:
            return fail("process exited at once with status %d before proving it runs" % code)
        if proc.returncode is not None:  # we are the parent: this is authoritative, unlike a ps read mid-exec
            return fail("process is not alive and wrote no status")
        try:
            size = os.stat(log).st_size
        except OSError:
            size = None
        if size is None:
            reason = "log file was never created within %ss" % args.deadline
        elif size > (before or 0):
            # Evidence: PID alive, log exists, log grew. Re-check liveness once more so a death right after the
            # first byte is not reported as a start.
            proc.poll()
            code, _ = read_status(record)
            if code is None and proc.returncode is None and not pid_is_job(proc.pid, nonce):
                time.sleep(0.05)  # between fork and exec ps shows the launcher's command line; ask again
                continue
            if code is None and proc.returncode is None:
                print("STARTED name=%s pid=%d log=%s status=%s argv_sha256=%s" %
                      (args.name, proc.pid, log, status, record["argv_sha256"][:16]))
                return EXIT_OK
            return fail("process died right after first output (status %s)" % ("%d" % code if code is not None else "none"))
        else:
            reason = "log exists but did not grow within %ss" % args.deadline
        time.sleep(0.05)
    return fail(reason)


def cmd_wait(args):
    record, why = load_record(job_dir(args.dir), args.name)
    if record is None:
        print("UNPROVEN name=%s reason=%s" % (args.name, why))
        return EXIT_UNPROVEN
    end = None if args.timeout is None else time.time() + args.timeout
    while True:
        code, why = read_status(record)
        if code is not None:
            print("EXITED name=%s EXIT_STATUS=%d" % (args.name, code))
            return EXIT_OK if code == 0 else EXIT_JOB_FAILED
        if why != "missing":
            print("UNPROVEN name=%s reason=status file %s" % (args.name, why))
            return EXIT_UNPROVEN
        if not pid_is_job(record["pid"], record["nonce"]) and not (time.sleep(0.3) or
                                                                    pid_is_job(record["pid"], record["nonce"])):
            # (asked twice: one failed `ps` read must not turn a live job into a lost one)
            # Status is written before the wrapper exits; one last look closes the exit/read race.
            code, why = read_status(record)
            if code is not None:
                print("EXITED name=%s EXIT_STATUS=%d" % (args.name, code))
                return EXIT_OK if code == 0 else EXIT_JOB_FAILED
            print("UNPROVEN name=%s reason=process is gone and left no status (killed, or its PID was reused)" % args.name)
            return EXIT_UNPROVEN
        if end is not None and time.time() >= end:
            print("TIMEOUT name=%s still running (pid %s)" % (args.name, record["pid"]))
            return EXIT_TIMEOUT
        time.sleep(0.1)


def cmd_status(args):
    record, why = load_record(job_dir(args.dir), args.name)
    if record is None:
        print("UNPROVEN name=%s reason=%s" % (args.name, why))
        return EXIT_UNPROVEN
    code, swhy = read_status(record)
    if code is not None:
        print("EXITED name=%s EXIT_STATUS=%d pid=%s log=%s" % (args.name, code, record["pid"], record["log"]))
        return EXIT_OK if code == 0 else EXIT_JOB_FAILED
    elif swhy == "missing" and pid_is_job(record["pid"], record["nonce"]):
        print("RUNNING name=%s pid=%s log=%s" % (args.name, record["pid"], record["log"]))
    elif swhy == "missing":
        print("LOST name=%s pid=%s reason=process gone, no status" % (args.name, record["pid"]))
        return EXIT_UNPROVEN
    else:
        print("UNPROVEN name=%s reason=status file %s" % (args.name, swhy))
        return EXIT_UNPROVEN
    return EXIT_OK


def main(argv=None):
    parser = argparse.ArgumentParser(prog="bg_job.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("launch")
    p.add_argument("--name", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--deadline", type=float, required=True)
    p.add_argument("--dir")
    p.add_argument("argv", nargs=argparse.REMAINDER)
    p = sub.add_parser("wait")
    p.add_argument("--name", required=True)
    p.add_argument("--timeout", type=float)
    p.add_argument("--dir")
    p = sub.add_parser("status")
    p.add_argument("--name", required=True)
    p.add_argument("--dir")
    p = sub.add_parser("_run")
    p.add_argument("--log", required=True)
    p.add_argument("--status", required=True)
    p.add_argument("--nonce", required=True)
    p.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.cmd == "_run":
        args.argv = [a for i, a in enumerate(args.argv) if not (i == 0 and a == "--")]
        return cmd_run(args)
    for opt in ("timeout",):
        value = getattr(args, opt, None)
        if value is not None and (not math.isfinite(value) or value < 0):
            print("UNPROVEN reason=--%s must be a finite number >= 0" % opt)
            return EXIT_USAGE
    try:
        return {"launch": cmd_launch, "wait": cmd_wait, "status": cmd_status}[args.cmd](args)
    except Exception as exc:
        if args.cmd == "launch":
            raise
        print("UNPROVEN name=%s reason=internal error (%s)" % (args.name, type(exc).__name__))
        return EXIT_UNPROVEN


if __name__ == "__main__":
    sys.exit(main())
