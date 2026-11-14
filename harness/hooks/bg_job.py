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
  bg_job.py wait --name N --ssh-job
      Same, but a job whose status is 255 (ssh's own connection failure) is INFRA, exit 5, not a failed job.
  bg_job.py wait-remote --host H --file F --until-file-line TEXT --timeout S [--fail-line TEXT] [--include-existing]
      Waits for TEXT (a fixed substring) in bytes appended to a remote log, polling over ssh with one fixed read-only
      command (retried once on a connection failure). Exit 0 LINE_FOUND; 1 FAIL_LINE_FOUND; 2 UNPROVEN (remote command
      failed, file unreadable, ssh refused: auth, host key, name); 3 TIMEOUT; 5 INFRA (the link kept failing); 64 usage
      (bad arguments, or the file is a path command_guard refuses to read). Baseline: only bytes appended after the first
      look count, so a run launched BEFORE the wait can finish first and be missed. Give the run its own fresh log and use
      --include-existing, or for a log appended across runs take its size before the launch and pass --from-offset N.
      Limits: wait on an append-only log; a path command_guard does not know is not judged; ssh config ProxyCommand, LocalCommand
      and RemoteCommand apply as for plain ssh; the remote needs a POSIX login shell.
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
EXIT_INFRA = 5


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


def _exited(args, code):
    """Print and return the outcome of a job that exited with `code`. With --ssh-job a status of 255 (ssh's own connection
    failure) is infrastructure, not a failed task (goodqa#15565 item 7)."""
    if code == 255 and getattr(args, "ssh_job", False):
        print("INFRA name=%s EXIT_STATUS=255 (an ssh connection failure, not a job failure)" % args.name)
        return EXIT_INFRA
    print("EXITED name=%s EXIT_STATUS=%d" % (args.name, code))
    return EXIT_OK if code == 0 else EXIT_JOB_FAILED


def cmd_wait(args):
    record, why = load_record(job_dir(args.dir), args.name)
    if record is None:
        print("UNPROVEN name=%s reason=%s" % (args.name, why))
        return EXIT_UNPROVEN
    end = None if args.timeout is None else time.time() + args.timeout
    while True:
        code, why = read_status(record)
        if code is not None:
            return _exited(args, code)
        if why != "missing":
            print("UNPROVEN name=%s reason=status file %s" % (args.name, why))
            return EXIT_UNPROVEN
        if not pid_is_job(record["pid"], record["nonce"]) and not (time.sleep(0.3) or
                                                                    pid_is_job(record["pid"], record["nonce"])):
            # (asked twice: one failed `ps` read must not turn a live job into a lost one)
            # Status is written before the wrapper exits; one last look closes the exit/read race.
            code, why = read_status(record)
            if code is not None:
                return _exited(args, code)
            print("UNPROVEN name=%s reason=process is gone and left no status (killed, or its PID was reused)" % args.name)
            return EXIT_UNPROVEN
        if end is not None and time.time() >= end:
            print("TIMEOUT name=%s still running (pid %s)" % (args.name, record["pid"]))
            return EXIT_TIMEOUT
        time.sleep(0.1)


MAX_FILE_WAIT_S = 24 * 3600
EXIT_PRODUCER_GONE = 4


def _producer_alive(spec, directory):
    """(alive, label). spec is `job:<name>` (a bg_job record) or `pid:<N>`. A pid answers kill -0 only, so a reused pid
    reads as alive: prefer job:, which proves the job by its nonce."""
    kind, _, value = spec.partition(":")
    if kind == "job" and NAME_RE.match(value):
        record, why = load_record(directory, value)
        if record is None:
            return False, "job %s (%s)" % (value, why)
        code, swhy = read_status(record)
        return (code is None and swhy == "missing" and pid_is_job(record["pid"], record["nonce"])), "job %s" % value
    if kind == "pid" and value.isdigit() and 1 < int(value) < 2 ** 31:
        try:
            os.kill(int(value), 0)
        except ProcessLookupError:
            return False, "pid %s" % value
        except PermissionError:
            pass
        return True, "pid %s" % value
    return None, spec


def _wait_alert(name, reason, detail):
    """One high ring alert for a waiter that gave up (best effort: the exit code and the line printed are the proof)."""
    try:
        import ops_watch
        ops_watch.emit({"host": ops_watch.default_host(), "source": "bg-wait", "event": "raise", "severity": "high",
                        "check": "bg-wait", "key": "bgwait:%s:%s" % (name, reason),
                        "message": ("background waiter %s gave up: %s" % (name, detail))[:300], "detail": {"reason": reason}})
    except Exception:  # noqa: BLE001 - an alert failure never changes the waiter's exit status
        pass


def cmd_wait_file(args):
    """Wait for a file, but only while something that produces it is alive, and never for ever (GoodQA #15565: a waiter
    sat 12 h on a file nothing produced). Exit 0 FILE_READY; 3 TIMEOUT; 4 PRODUCER_GONE; both raise a high alert."""
    directory = job_dir(args.dir)
    if args.timeout is None or not 0 < args.timeout <= MAX_FILE_WAIT_S:
        print("UNPROVEN reason=--timeout is required, 1 to %d seconds" % MAX_FILE_WAIT_S)
        return EXIT_USAGE
    if not math.isfinite(args.poll) or not 0.05 <= args.poll <= 60:
        print("UNPROVEN reason=--poll must be between 0.05 and 60 seconds")
        return EXIT_USAGE
    alive, label = _producer_alive(args.producer, directory)
    if alive is None:
        print("UNPROVEN reason=--producer must be job:<bg_job name> or pid:<number>, naming what writes %s" % args.file)
        return EXIT_USAGE
    name = os.path.basename(args.file)[:40] or "file"
    end = time.time() + args.timeout
    gone_looks = 0
    while True:
        try:
            ready = os.path.isfile(args.file) and os.path.getsize(args.file) >= args.min_bytes  # a directory is not output
        except OSError:
            ready = False
        if ready:
            print("FILE_READY file=%s" % args.file)
            return EXIT_OK
        alive, label = _producer_alive(args.producer, directory)
        gone_looks = 0 if alive else gone_looks + 1
        if gone_looks >= 2:  # two looks: one failed `ps` read must not end a live producer's wait
            try:
                if os.path.isfile(args.file) and os.path.getsize(args.file) >= args.min_bytes:
                    continue  # it landed between the checks
            except OSError:
                pass
            print("PRODUCER_GONE file=%s producer=%s: it is not running and the file does not exist" % (args.file, label))
            _wait_alert(name, "producer-gone", "%s is gone and %s never appeared" % (label, args.file))
            return EXIT_PRODUCER_GONE
        if time.time() >= end:
            print("TIMEOUT file=%s producer=%s still running after %ss" % (args.file, label, args.timeout))
            _wait_alert(name, "timeout", "%s still not written after %ss (producer %s)" % (args.file, args.timeout, label))
            return EXIT_TIMEOUT
        time.sleep(max(0.05, min(args.poll, end - time.time())))  # the timeout stays a hard bound


# ---- wait-remote (goodqa#15565 items 7 and 8) ----
# Wait for a line to be APPENDED to a log on a remote host. The remote command is one fixed read-only template; the only
# caller text in it is the shell-quoted file name and an integer offset. The ssh binary and its options are fixed.
SSH = "/usr/bin/ssh"
SSH_OPTIONS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2")
SSH_CALL_BOUND = 30  # seconds per ssh call: a hung connection counts as an infrastructure failure
READ_CAP = 65536
REMOTE_TEMPLATE = ("[ -e {f} ] || exit 10; [ -f {f} ] && [ -r {f} ] || exit 11; wc -c < {f}; "
                   "tail -c +{off} -- {f} | head -c %d" % READ_CAP)
EXIT_ABSENT, EXIT_UNREADABLE = 10, 11
HOST_RE = re.compile(r"^([A-Za-z0-9._-]{1,32}@)?[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
SSH_REFUSED = re.compile(r"Permission denied|Host key verification failed|Could not resolve hostname")
MAX_POLLS_LIMIT = 20


def _bad_text(value, limit, what):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or re.search(r"[\0\r\n]", value):
        return "%s must be 1 to %d characters without NUL or a line break" % (what, limit)
    return None


def remote_arguments_problem(args):
    """None, or why the arguments are refused before any ssh call (exit 64)."""
    if not HOST_RE.match(args.host or ""):
        return "--host must be [user@]host (letters, digits, . - _), not starting with - or ."
    problem = _bad_text(args.file, 512, "--file") or _bad_text(args.until_file_line, 200, "--until-file-line")
    if problem is None and args.fail_line is not None:
        problem = _bad_text(args.fail_line, 200, "--fail-line")
    if problem:
        return problem
    if args.file.startswith("~"):
        return "--file must not start with ~ (use an absolute path or a path relative to the remote home)"
    if args.timeout is None or not math.isfinite(args.timeout) or not 0 < args.timeout <= MAX_FILE_WAIT_S:
        return "--timeout is required, 1 to %d seconds" % MAX_FILE_WAIT_S
    if not math.isfinite(args.poll) or not 0.05 <= args.poll <= 60:
        return "--poll must be between 0.05 and 60 seconds"
    if not 1 <= args.max_infra_polls <= MAX_POLLS_LIMIT:
        return "--max-infra-polls must be between 1 and %d" % MAX_POLLS_LIMIT
    if args.from_offset is not None and (args.include_existing or not 0 <= args.from_offset < 2 ** 50):
        return "--from-offset must be a byte count >= 0 and cannot be combined with --include-existing"
    return None


def file_judged_by_guard(path):
    """(allowed, why). The wait answers found or not found about any remote file, which is a substring oracle: the
    credential and protected-location rules that refuse `ssh host cat FILE` apply to FILE too. No guard, no wait."""
    try:
        import shlex
        import command_guard
        # a relative path is relative to the remote home: judge it as ~/PATH too (the Mac's home differs from the host's)
        forms = [shlex.quote(path)] if path.startswith("/") else [shlex.quote(path), '"$HOME"/' + shlex.quote(path)]
        # raw_credential (credential locations), not raw_sensitive: run kits and job logs live under ~/.agent-harness and
        # ~/.claude, and reading them is what this command is for; decide() below judges the read itself
        for text in [path] + ([] if path.startswith("/") else ["~/" + path]):
            if command_guard.raw_credential(text):
                return False, "the path names a credential location"
        for form in forms:
            verdict, message = command_guard.decide("cat -- " + form)
            if verdict == "block":
                return False, str(message)[:200]
    except Exception as exc:  # noqa: BLE001 - fail closed
        return False, "command_guard could not judge the path (%s)" % type(exc).__name__
    return True, ""


def _bounded_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return re.sub(r"[^\x20-\x7e]", "?", line.strip())[:160]
    return ""


def _ssh_once(host, command):
    """(status, stdout bytes, stderr text). A hung call returns status 255 with a timeout note."""
    argv = [SSH, *SSH_OPTIONS, "--", host, command]
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SSH_AUTH_SOCK", "LANG") if k in os.environ}
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                              timeout=SSH_CALL_BOUND)
    except subprocess.TimeoutExpired:
        return 255, b"", "ssh call timed out after %d s" % SSH_CALL_BOUND
    except OSError as exc:
        return 255, b"", "ssh could not start (%s)" % type(exc).__name__
    return done.returncode, done.stdout[:READ_CAP + 64], done.stderr[:2000].decode("utf-8", "replace")


def _poll(host, quoted, offset):
    """One poll, with the single retry on a connection failure: (kind, size, data, note); kind is ok, absent, unreadable,
    refused (not infrastructure), infra or failed."""
    command = REMOTE_TEMPLATE.format(f=quoted, off=offset + 1)
    for attempt in (0, 1):
        status, out, err = _ssh_once(host, command)
        if status == 255:
            if SSH_REFUSED.search(err):
                return "refused", 0, b"", _bounded_line(err)
            if attempt == 0:
                continue
            return "infra", 0, b"", _bounded_line(err)
        break
    if status == EXIT_ABSENT:
        return "absent", 0, b"", ""
    if status == EXIT_UNREADABLE:
        return "unreadable", 0, b"", ""
    if status != 0:
        return "failed", 0, b"", "exit %d" % status
    head, _, data = out.partition(b"\n")
    if not re.fullmatch(rb"\s*[0-9]{1,18}\s*", head):  # a banner, empty output or a garbled size is never a reset
        return "failed", 0, b"", "no size line"
    size = int(head)
    return "ok", size, data[:READ_CAP], ""


def cmd_wait_remote(args):
    import shlex
    problem = remote_arguments_problem(args)
    if problem is None:
        allowed, why = file_judged_by_guard(args.file)
        problem = None if allowed else "--file refused by command_guard: %s" % why
    if problem:
        print("UNPROVEN reason=%s" % problem)
        return EXIT_USAGE
    quoted = shlex.quote(args.file)
    until, fail = args.until_file_line.encode(), (args.fail_line.encode() if args.fail_line else None)
    keep = max(len(until), len(fail or b"")) - 1
    name = os.path.basename(args.file)[:40] or "file"
    end = time.time() + args.timeout
    # offset = bytes of the file already examined. It starts at 0 and moves only by the bytes RECEIVED (never by the reported
    # size, which the read cap can outrun), except for the first look at an existing file: that sets it to the size, so only
    # appended bytes count, unless --include-existing or the caller's own baseline --from-offset (taken before the launch).
    offset, carry, first, infra_polls = 0, b"", True, 0
    if args.from_offset is not None:
        offset, first = args.from_offset, False
    while True:
        kind, size, data, note = _poll(args.host, quoted, offset)
        if kind == "infra":
            infra_polls += 1
            if infra_polls >= args.max_infra_polls:
                print("INFRA host=%s polls=%d %s" % (args.host, infra_polls, note))
                _wait_alert(name, "infra", "ssh to %s failed %d polls in a row (%s)" % (args.host, infra_polls, note))
                return EXIT_INFRA
        elif kind == "refused":
            print("UNPROVEN host=%s reason=ssh refused (%s)" % (args.host, note))
            return EXIT_UNPROVEN
        elif kind in ("unreadable", "failed"):
            print("UNPROVEN host=%s file=%s reason=remote command failed (%s)" % (
                args.host, args.file, "not a readable regular file" if kind == "unreadable" else note))
            return EXIT_UNPROVEN
        else:
            infra_polls = 0
            if kind == "ok":
                if first and not args.include_existing:
                    offset, data = size, b""  # only what is appended after this first look counts (D2)
                elif size < offset:  # truncated or rotated: judge the new content from its start
                    offset, carry, data = 0, b"", b""
                first = False
                buf = carry + data
                offset += len(data)
                carry = buf[-keep:] if keep > 0 else b""
                if fail is not None and fail in buf:
                    print("FAIL_LINE_FOUND host=%s file=%s" % (args.host, args.file))
                    return EXIT_JOB_FAILED
                if until in buf:
                    print("LINE_FOUND host=%s file=%s" % (args.host, args.file))
                    return EXIT_OK
                if len(data) >= READ_CAP and time.time() < end:
                    continue  # more is waiting: read on without sleeping, but never past the deadline
            else:  # absent: not there yet; a file that appears later holds only new bytes
                first = False
        if time.time() >= end:
            print("TIMEOUT host=%s file=%s line not seen after %ss" % (args.host, args.file, args.timeout))
            _wait_alert(name, "timeout", "%s on %s did not show the line after %ss" % (args.file, args.host, args.timeout))
            return EXIT_TIMEOUT
        time.sleep(max(0.05, min(args.poll, end - time.time())))


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
    p.add_argument("--ssh-job", dest="ssh_job", action="store_true",
                   help="the job is an ssh command: report its exit status 255 as INFRA (exit 5), not as a failed job")
    p = sub.add_parser("wait-remote")
    p.add_argument("--host", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--until-file-line", dest="until_file_line", required=True,
                   help="a fixed text (not a pattern) to wait for in bytes appended to the remote file")
    p.add_argument("--fail-line", dest="fail_line", help="a fixed text that ends the wait early as a failure (exit 1)")
    p.add_argument("--include-existing", dest="include_existing", action="store_true",
                   help="also match what the file already holds at the first look (default: only appended bytes)")
    p.add_argument("--from-offset", dest="from_offset", type=int,
                   help="count only bytes after this offset (the file size taken BEFORE the run was launched); for a log "
                        "appended across runs. A run with its own fresh log needs no baseline: use --include-existing")
    p.add_argument("--timeout", type=float, help="required: seconds, at most 86400")
    p.add_argument("--poll", type=float, default=1.0)
    p.add_argument("--max-infra-polls", dest="max_infra_polls", type=int, default=3)
    p = sub.add_parser("wait-file")
    p.add_argument("--file", required=True)
    p.add_argument("--producer", required=True, help="what writes the file: job:<bg_job name> or pid:<number>")
    p.add_argument("--timeout", type=float, help="required: seconds, at most 86400")
    p.add_argument("--min-bytes", dest="min_bytes", type=int, default=1)
    p.add_argument("--poll", type=float, default=1.0)
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
        return {"launch": cmd_launch, "wait": cmd_wait, "wait-file": cmd_wait_file, "wait-remote": cmd_wait_remote,
                "status": cmd_status}[args.cmd](args)
    except Exception as exc:
        if args.cmd == "launch":
            raise
        print("UNPROVEN name=%s reason=internal error (%s)" % (getattr(args, "name", args.cmd), type(exc).__name__))
        return EXIT_UNPROVEN


if __name__ == "__main__":
    sys.exit(main())
