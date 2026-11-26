#!/usr/bin/env python3
"""Durable, explicitly enrolled native-agent tasks for owned user services."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 65536


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private(path, directory=False):
    meta = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise ValueError("task files and directories must be private and owned")
    return meta


def read(path):
    private(path)
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("task input exceeds limit")
    return raw


def atomic(path, value):
    fd, name = tempfile.mkstemp(prefix=".recovery-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def argv(value):
    if (not isinstance(value, list) or not value or len(value) > 64 or
            any(not isinstance(x, str) or not x or "\x00" in x or len(x) > 4096 for x in value) or
            not Path(value[0]).is_absolute()):
        raise ValueError("commands require bounded argv with absolute executable")
    return value


def validate(m, *, require_cwd=True):
    required = {"schema", "task_id", "cwd", "agent_argv", "prompt_file", "prompt_sha256",
                "verify_argv", "max_attempts", "attempt_timeout", "task_timeout"}
    if set(m) != required or m["schema"] != "native-recovery-v1":
        raise ValueError("invalid manifest schema")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", m["task_id"]):
        raise ValueError("invalid task id")
    if not Path(m["cwd"]).is_absolute() or (require_cwd and not Path(m["cwd"]).is_dir()):
        raise ValueError("cwd must be an existing absolute directory")
    argv(m["agent_argv"])
    argv(m["verify_argv"])
    if Path(m["agent_argv"][0]).name not in ("codex", "claude"):
        raise ValueError("agent must be a native codex or claude executable")
    for key, upper in (("max_attempts", 4), ("attempt_timeout", 21600), ("task_timeout", 86400)):
        if type(m[key]) is not int or not 1 <= m[key] <= upper:
            raise ValueError("invalid task limit")
    if not Path(m["prompt_file"]).is_absolute() or digest(read(Path(m["prompt_file"]))) != m["prompt_sha256"]:
        raise ValueError("prompt integrity mismatch")
    return m


def completion_time(state):
    value = state.get("verified_at")
    return value if state.get("status") == "complete" and type(value) in (int, float) and 0 < value <= time.time() else None


def load(root):
    private(root, True)
    raw = read(root / "manifest.json")
    state = json.loads(read(root / "state.json"))
    if state["manifest_sha256"] != digest(raw):
        raise ValueError("enrolled manifest changed")
    verified = completion_time(state)
    if state.get("status") == "complete" and verified is None:
        raise ValueError("missing verified completion time")
    manifest = validate(json.loads(raw), require_cwd=verified is None)
    return manifest, state


def lock(root):
    fd = os.open(root / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    private(root / "lock")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def enroll(root, source):
    manifest = validate(json.loads(read(source)))
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    private(root, True)
    fd = lock(root)
    try:
        raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        if (root / "manifest.json").exists():
            if read(root / "manifest.json") != raw:
                raise ValueError("task already enrolled with different declaration")
            load(root)
            return
        if (root / "state.json").exists():
            raise ValueError("orphan state requires reconciliation")
        atomic(root / "manifest.json", manifest)
        state = {"manifest_sha256": digest(raw), "attempts": 0,
                 "deadline": time.time() + manifest["task_timeout"], "status": "enrolled"}
        atomic(root / "state.json", state)
    finally:
        os.close(fd)


class ProcessUncertain(RuntimeError):
    """An owned process group may still contain a live writer."""


def group_live(pgid):
    try:
        result = subprocess.run(["/bin/ps", "-axo", "pgid=,stat="], capture_output=True, timeout=2)
        rows = result.stdout.decode("ascii", "strict").splitlines()
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise ProcessUncertain("process observation unavailable") from error
    if result.returncode:
        raise ProcessUncertain("process observation unavailable")
    for line in rows:
        fields = line.split()
        if len(fields) != 2 or not fields[0].isdigit():
            raise ProcessUncertain("process observation malformed")
        if int(fields[0]) == pgid and not fields[1].startswith("Z"):
            return True
    return False


def quiesce(child):
    """Observe descendants independently from the command leader."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not group_live(child.pid):
            child.wait(timeout=2)
            return
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        end = time.monotonic() + .2
        while time.monotonic() < end:
            child.poll()
            if not group_live(child.pid):
                child.wait(timeout=2)
                return
            time.sleep(.02)
    child.poll()
    if group_live(child.pid):
        raise ProcessUncertain("owned group remains active")


def execute(command, cwd, log, timeout, prompt=None):
    """Only signal the new child session created by this invocation."""
    with log.open("ab", buffering=0) as output:
        child = subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE if prompt else subprocess.DEVNULL,
                                 stdout=output, stderr=output, start_new_session=True, close_fds=True)
        try:
            child.communicate(input=prompt, timeout=max(.01, timeout))
            quiesce(child)
            return child.returncode
        except (subprocess.TimeoutExpired, BaseException) as error:
            quiesce(child)
            if isinstance(error, subprocess.TimeoutExpired):
                return 124
            raise


def attempt(root, number, inherited_fd):
    # Keep the shared lock alive even if the service supervisor dies.
    os.fstat(inherited_fd)
    manifest, state = load(root)
    prompt = read(Path(manifest["prompt_file"]))
    directive = (
        "\nTask recovery instruction. Reconcile the existing checkout, task journal, live services, "
        "and external receipts before taking action. Prior work may have partially completed. "
        "Preserve user pauses and uncertain writes. Continue only this enrolled task. "
        "Use the completion verifier as the requested outcome. Attempt %d of %d.\n"
        % (number, manifest["max_attempts"])
    ).encode()
    remaining = min(manifest["attempt_timeout"], state["deadline"] - time.time())
    code, quiescent = 125, True
    try:
        if remaining > 0 and not (root / "paused.json").exists():
            code = execute(manifest["agent_argv"], manifest["cwd"], root / ("attempt-%d.log" % number),
                           remaining, prompt + directive)
    except ProcessUncertain:
        quiescent = False
    finally:
        atomic(root / ("attempt-%d.json" % number), {"attempt": number, "exit": code,
                                                    "quiescent": quiescent,
                                                    "manifest_sha256": state["manifest_sha256"],
                                                    "finished_at": time.time()})
    return 0


def run(root):
    fd = lock(root)
    try:
        manifest, state = load(root)
        if (root / "paused.json").exists() or state["status"] == "complete":
            return 0
        # A missing receipt may hide a surviving native writer. Preserve ambiguity.
        if state["status"] == "running" and state["attempts"] > 0:
            previous = root / ("attempt-%d.json" % state["attempts"])
            if not previous.exists() or json.loads(read(previous)).get("quiescent") is not True:
                state["status"] = "recovery_uncertain"
                atomic(root / "state.json", state)
                return 0
        if state["status"] == "recovery_uncertain":
            return 0
        # Completion verification is explicitly enrolled and must be read-only.
        while True:
            remaining = state["deadline"] - time.time()
            if remaining <= 0:
                state["status"] = "deadline_exhausted"
                atomic(root / "state.json", state)
                return 0
            try:
                verified = execute(manifest["verify_argv"], manifest["cwd"], root / "verification.log",
                                   min(60, remaining))
            except ProcessUncertain:
                state["status"] = "recovery_uncertain"
                atomic(root / "state.json", state)
                return 0
            if verified == 0:
                state["status"], state["verified_at"] = "complete", time.time()
                atomic(root / "state.json", state)
                return 0
            if (root / "paused.json").exists():
                return 0
            if state["attempts"] >= manifest["max_attempts"]:
                state["status"] = "attempts_exhausted"
                atomic(root / "state.json", state)
                return 0
            state["attempts"] += 1
            state["status"] = "running"
            atomic(root / "state.json", state)
            number = state["attempts"]
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "_attempt", "--task-dir", str(root),
                 "--number", str(number), "--lock-fd", str(fd)],
                pass_fds=(fd,), start_new_session=True)
            child.wait()
            path = root / ("attempt-%d.json" % number)
            if path.exists():
                receipt = json.loads(read(path))
                if receipt["attempt"] != number or receipt["manifest_sha256"] != state["manifest_sha256"]:
                    raise ValueError("attempt receipt does not match task")
                if receipt.get("quiescent") is not True:
                    state["status"] = "recovery_uncertain"
                    atomic(root / "state.json", state)
                    return 0
            else:
                state["status"] = "recovery_uncertain"
                atomic(root / "state.json", state)
                return 0
            # Never equate native process exit with completion. Reconcile every attempt.
    finally:
        os.close(fd)


def service(root, kind):
    manifest, _ = load(root)
    command = [sys.executable, str(Path(__file__).resolve()), "run", "--task-dir", str(root)]
    if kind == "launchd":
        import plistlib
        result = {"Label": "ai.agent-harness.task." + manifest["task_id"], "ProgramArguments": command,
                  "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 10,
                  "WorkingDirectory": manifest["cwd"], "Umask": 63,
                  "StandardOutPath": str(root / "service.log"), "StandardErrorPath": str(root / "service.log")}
        sys.stdout.buffer.write(plistlib.dumps(result))
    else:
        if any(any(c in arg for c in '\n\r%"\\') for arg in command):
            raise ValueError("service path cannot be represented safely")
        print("[Unit]\nDescription=Enrolled native agent task %s\n\n[Service]" % manifest["task_id"])
        print("Type=simple\nUMask=0077\nRestart=on-failure\nRestartSec=10")
        print("ExecStart=" + " ".join('"%s"' % arg for arg in command))
        print("\n[Install]\nWantedBy=default.target")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("enroll", "run", "pause", "status", "service", "_attempt"))
    parser.add_argument("--task-dir", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--kind", choices=("launchd", "systemd"))
    parser.add_argument("--number", type=int)
    parser.add_argument("--lock-fd", type=int)
    args = parser.parse_args()
    root = args.task_dir
    if not root.is_absolute():
        parser.error("task directory must be absolute")
    try:
        if args.command == "enroll":
            if args.manifest is None:
                parser.error("--manifest required")
            enroll(root, args.manifest)
        elif args.command == "run":
            return run(root)
        elif args.command == "_attempt":
            return attempt(root, args.number, args.lock_fd)
        elif args.command == "pause":
            load(root)
            atomic(root / "paused.json", {"paused_at": time.time()})
        elif args.command == "status":
            print(json.dumps(load(root)[1], sort_keys=True))
        else:
            if args.kind is None:
                parser.error("--kind required")
            service(root, args.kind)
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("Task recovery refused invalid, unavailable, or concurrently owned state.", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
