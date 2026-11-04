#!/usr/bin/env python3
"""Run a command in its own process group under a memory, process-count and time cap.

    run_capped.py --max-rss-gb 8 [--max-procs 40] [--timeout-s 300] -- <command...>

Size the cap from the job's declared resource budget with generous headroom
(for example peak x 1.5); it is a safety net, not a quota. A breach of
--max-rss-gb, --max-procs or --timeout-s does NOT kill by default: the tree is
paused (SIGSTOP, state kept, nothing lost), an alert is printed and written to
<wrapper-pid>.alert next to the sidecar, and the wrapper waits:
  kill -USR1 <wrapper-pid>   resume (the breached cap is raised 1.5x)
  kill -TERM <wrapper-pid>   stop the job and every child
--on-breach kill restores kill-on-breach (exit 137, or 124 on timeout) for
disposable jobs. The group is ALWAYS cleaned up (no surviving children) when
  - this wrapper gets SIGTERM/SIGINT/SIGHUP/SIGQUIT            (exit 128+n)
  - this wrapper is SIGKILLed: a detached guardian reaps the tree
  - the command exits but leaves descendants behind

While running, a sidecar JSON is written to
  ~/.agent-harness/state/run_capped/<wrapper-pid>.json
({wrapper_pid, pgid, child_pid, max_rss_gb, max_procs, timeout_s, started_at,
host, argv0}) so netwatch can see the declared cap. It is removed on exit.

Time spent stopped (SIGSTOP by netwatch, or paused by this wrapper) does not count
toward --timeout-s, so a paused-then-resumed job is not killed for the delay. The
Bash tool timeout and an external `timeout N` cannot be made pause-aware: a long job
should go through run_capped (preferably on dev2) rather than rely on those.

Stdlib only, Python 3.9 compatible. Linux and macOS (uses `ps -axo`).
"""
from __future__ import annotations

import argparse
import math
import json
import os
import signal
import subprocess
import sys
import time

def finite_non_negative(text):
    """--timeout-s: 0 means no limit; NaN, inf and negatives are refused."""
    value = positive_finite(text) if float(text) != 0 else 0.0
    return value


def positive_finite(text):
    """argparse type: a finite number > 0. NaN/inf would silently disable every comparison against the bound."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number")
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"{text!r} must be a finite number greater than 0")
    return value


GRACE_S = 2.0
STATE_DIR = os.path.join(os.path.expanduser("~"), ".agent-harness", "state", "run_capped")


def snapshot():
    """[(pid, ppid, pgid, rss_kb, stat)] for every process."""
    ps = subprocess.Popen(["ps", "-axo", "pid=,ppid=,pgid=,rss=,stat="], stdout=subprocess.PIPE, text=True)
    out = ps.communicate(timeout=10)[0]
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 5 and all(p.isdigit() for p in parts[:4]):
            row = tuple(int(p) for p in parts[:4]) + (parts[4],)
            if row[0] != ps.pid and not row[4].startswith("Z"):  # not our own ps, not zombies
                rows.append(row)
    return rows


EXTRA_ROOTS = set()  # the runner itself once it is a subreaper: orphans reparent to it
EXCLUDE = set()      # runner-owned helpers (guardian) that must never be counted or signalled


def become_subreaper():
    """Linux: orphaned/daemonized descendants reparent to us, so double-fork+setsid cannot hide from accounting."""
    try:
        import ctypes
        if sys.platform.startswith("linux") and ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0:  # PR_SET_CHILD_SUBREAPER
            EXTRA_ROOTS.add(os.getpid())
            EXCLUDE.add(os.getpid())
            return True
    except (OSError, AttributeError, ImportError):
        pass
    return False


def members(root_pid, pgid, rows=None):
    """Processes in the group plus every descendant of root_pid (and of the subreaper runner)."""
    rows = rows if rows is not None else snapshot()
    children = {}
    for pid, ppid, _pg, _rss, _st in rows:
        children.setdefault(ppid, []).append(pid)
    tree, stack = set(), [root_pid] + list(EXTRA_ROOTS)
    while stack:
        pid = stack.pop()
        if pid not in tree:
            tree.add(pid)
            stack.extend(children.get(pid, []))
    return [r for r in rows if (r[0] in tree or r[2] == pgid) and r[0] not in EXCLUDE]


def reap_orphans(root_pid):
    """As a subreaper we inherit daemonized orphans; reap the dead ones (never the command itself)."""
    if not EXTRA_ROOTS:
        return
    try:
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,stat="], capture_output=True, text=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        return
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == str(os.getpid()) and parts[2].startswith("Z") and int(parts[0]) != root_pid:
            try:
                os.waitpid(int(parts[0]), os.WNOHANG)
            except OSError:
                pass


def kill_tree(root_pid, pgid, own_pids=()):
    """SIGTERM, wait the grace period, SIGKILL; repeat until nothing is left."""
    for sig, wait in ((signal.SIGTERM, GRACE_S), (signal.SIGKILL, 1.0), (signal.SIGKILL, 1.0)):
        live = [r for r in members(root_pid, pgid) if r[0] not in own_pids]
        if not live:
            return True
        try:
            os.killpg(pgid, sig)
        except OSError:
            pass
        for pid, *_ in live:
            try:
                os.kill(pid, sig)
                if sig == signal.SIGTERM:
                    os.kill(pid, signal.SIGCONT)  # a paused process must wake up to handle TERM
            except OSError:
                pass
        deadline = time.time() + wait
        while time.time() < deadline:
            reap_orphans(root_pid)
            if not [r for r in members(root_pid, pgid) if r[0] not in own_pids]:
                return True
            time.sleep(0.05)
    return not [r for r in members(root_pid, pgid) if r[0] not in own_pids]


def pause_tree(root_pid, pgid, own_pids=()):
    """SIGSTOP every member (twice, to catch forks racing the first pass)."""
    for _ in range(2):
        for pid, *_ in members(root_pid, pgid):
            if pid not in own_pids:
                try:
                    os.kill(pid, signal.SIGSTOP)
                except OSError:
                    pass


def resume_tree(root_pid, pgid, own_pids=()):
    for pid, *_ in members(root_pid, pgid):
        if pid not in own_pids:
            try:
                os.kill(pid, signal.SIGCONT)
            except OSError:
                pass


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def guardian(wrapper_pid, child_pid, pgid):
    """Detached watcher: if the wrapper vanishes (SIGKILL), reap the command's tree."""
    try:
        os.setsid()
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        me = {os.getpid()}
        while True:
            time.sleep(0.5)
            if not alive(wrapper_pid):
                kill_tree(child_pid, pgid, me)
                for suffix in (".json", ".alert"):  # the SIGKILLed wrapper cannot clean up its own sidecar
                    try:
                        os.unlink(os.path.join(STATE_DIR, f"{wrapper_pid}{suffix}"))
                    except OSError:
                        pass
                break
            if not members(child_pid, pgid):
                break
    finally:
        os._exit(0)


def write_sidecar(args, child_pid, pgid, command, status="running", note=""):
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        path = os.path.join(STATE_DIR, f"{os.getpid()}.json")
        record = {"wrapper_pid": os.getpid(), "pgid": pgid, "child_pid": child_pid,
                  "max_rss_gb": args.max_rss_gb, "max_procs": args.max_procs, "timeout_s": args.timeout_s,
                  "on_breach": args.on_breach, "status": status, "note": note,
                  "started_at": time.time(), "host": os.uname().nodename, "argv0": os.path.basename(command[0])}
        tmp = path + ".tmp"
        with open(tmp, "w") as handle:
            json.dump(record, handle)
        os.replace(tmp, path)
        return path
    except OSError:
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-rss-gb", type=positive_finite, required=True)
    parser.add_argument("--max-procs", type=int, default=0, help="0 = no limit")
    parser.add_argument("--timeout-s", type=finite_non_negative, default=0, help="0 = no limit")
    parser.add_argument("--poll-s", type=positive_finite, default=0.2)
    parser.add_argument("--on-breach", choices=("pause", "kill"), default="pause")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.max_rss_gb <= 0:
        parser.error("need --max-rss-gb > 0 and a command after --")

    become_subreaper()
    try:
        child = subprocess.Popen(command, start_new_session=True)
    except OSError as error:
        sys.stderr.write(f"run_capped: cannot start {command[0]}: {error}\n")
        return 127
    pgid = child.pid  # start_new_session makes the child its own group leader
    stop = {"sig": None, "resume": False}

    def on_signal(signum, _frame):
        stop["sig"] = signum

    def on_resume(_signum, _frame):
        stop["resume"] = True

    for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"):
        signal.signal(getattr(signal, name), on_signal)
    signal.signal(signal.SIGUSR1, on_resume)
    guardian_pid = os.fork()
    if guardian_pid == 0:
        guardian(os.getppid(), child.pid, pgid)
    EXCLUDE.add(guardian_pid)
    sidecar = write_sidecar(args, child.pid, pgid, command)
    cap_kb = args.max_rss_gb * 1024 * 1024
    started = time.time()
    stopped_total, last_tick = 0.0, time.time()  # wall time the job spent stopped; never counts toward --timeout-s
    reason, code = None, None
    try:
        while True:
            if stop["sig"] is not None:
                reason, code = f"received signal {stop['sig']}", 128 + stop["sig"]
                break
            rc = child.poll()
            try:
                live = members(child.pid, pgid)
            except (subprocess.SubprocessError, OSError):
                live = []
            now = time.time()
            if live and all(r[4].startswith("T") for r in live):
                stopped_total += now - last_tick  # paused by netwatch (SIGSTOP) or by us
            last_tick = now
            rss_kb = sum(r[3] for r in live)
            breach = None
            if rss_kb > cap_kb:
                breach = (f"RSS {rss_kb / 1048576:.2f} GB exceeded the {args.max_rss_gb:g} GB cap", 137, "rss")
            elif args.max_procs and len(live) > args.max_procs:
                breach = (f"{len(live)} processes exceeded the {args.max_procs} process cap", 137, "procs")
            elif args.timeout_s and time.time() - started - stopped_total > args.timeout_s:
                breach = (f"timeout after {args.timeout_s:g} s", 124, "time")
            if breach and args.on_breach == "kill":
                reason, code = breach[0], breach[1]
                break
            if breach:
                pause_tree(child.pid, pgid)
                note = f"PAUSED: {breach[0]}. kill -USR1 {os.getpid()} to resume, kill -TERM {os.getpid()} to stop."
                sys.stderr.write(f"run_capped: {note}\n")
                write_sidecar(args, child.pid, pgid, command, "paused", note)
                try:
                    with open(os.path.join(STATE_DIR, f"{os.getpid()}.alert"), "w") as handle:
                        handle.write(note + "\n")
                except OSError:
                    pass
                paused_at = time.time()
                while stop["sig"] is None and not stop["resume"]:
                    time.sleep(0.1)
                stopped_total += time.time() - paused_at
                last_tick = time.time()
                if stop["sig"] is not None:
                    continue
                stop["resume"] = False
                if breach[2] == "rss":
                    cap_kb *= 1.5
                elif breach[2] == "procs":
                    args.max_procs = int(args.max_procs * 1.5) + 1
                else:
                    args.timeout_s *= 1.5
                resume_tree(child.pid, pgid)
                write_sidecar(args, child.pid, pgid, command, "running", "resumed")
                continue
            if rc is not None and not [r for r in live if r[0] != child.pid]:
                return rc if rc >= 0 else 128 - rc
            if rc is not None:  # command exited but left descendants running: reap them
                kill_tree(child.pid, pgid)
                return rc if rc >= 0 else 128 - rc
            time.sleep(args.poll_s)
        sys.stderr.write(f"run_capped: killing process group {pgid}: {reason}\n")
        kill_tree(child.pid, pgid)
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        return code
    finally:
        try:
            os.kill(guardian_pid, signal.SIGKILL)
            os.waitpid(guardian_pid, 0)
        except OSError:
            pass
        for suffix in (".json", ".alert"):
            try:
                os.unlink(os.path.join(STATE_DIR, f"{os.getpid()}{suffix}"))
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
