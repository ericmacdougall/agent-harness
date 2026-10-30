"""Run a POSIX command with a deadline and clean up its process group on failure."""

import os
import selectors
import signal
import subprocess
import time

# Git removes its lock files from its SIGTERM handler; SIGKILL skips that cleanup.
TERMINATION_GRACE_SECONDS = 2
DISCARD_CHUNK_BYTES = 65536
DISCARD_CLEANUP_SECONDS = 5


def signal_group(pid, signum):
    try:
        os.killpg(pid, signum)
    except (ProcessLookupError, PermissionError):
        # A group can disappear or become inaccessible between TERM and KILL.
        # The caller still reaps the leader and bounds pipe cleanup below.
        pass


def drain_discarded(pipe, deadline):
    """Discard fixed-size chunks until every inherited writer closes or time runs out."""
    with selectors.DefaultSelector() as poller:
        poller.register(pipe, selectors.EVENT_READ)
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            if not poller.select(remaining):
                return False
            if not os.read(pipe.fileno(), DISCARD_CHUNK_BYTES):
                return True


def cleanup_discarded(process):
    """Drain without retaining output while the process group exits."""
    grace_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    signal_group(process.pid, signal.SIGTERM)
    try:
        drain_discarded(process.stdout, grace_deadline)
    except (OSError, ValueError):
        pass
    while time.monotonic() < grace_deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            pass
        time.sleep(min(0.05, grace_deadline - time.monotonic()))
    signal_group(process.pid, signal.SIGKILL)
    try:
        drain_discarded(process.stdout, time.monotonic() + DISCARD_CLEANUP_SECONDS)
    except (OSError, ValueError):
        pass
    try:
        process.stdout.close()
    finally:
        process.wait(timeout=DISCARD_CLEANUP_SECONDS)


def run(command, *, cwd=None, env=None, timeout=None, input=None, text=True,
        stream=False, discard_output=False):
    # Git and test runners spawn children that subprocess.run(timeout=...) leaves alive.
    # Malformed output from a child must not bypass a caller's rollback path.
    # Keep binary mode exact for callers that inspect Git object bytes.
    if stream and discard_output:
        raise ValueError('stream and discard_output are mutually exclusive')
    if discard_output and input is not None:
        raise ValueError('discard_output does not accept input')
    decoding = {'errors': 'replace'} if text else {}
    # The discard path drains one merged pipe to preserve descendant EOF semantics.
    output = None if stream else subprocess.PIPE
    process = subprocess.Popen(command, cwd=cwd, env=env, text=text,
                               stdin=subprocess.PIPE if input is not None else None,
                               stdout=output,
                               stderr=subprocess.STDOUT if discard_output else output,
                               start_new_session=True, **decoding)
    if discard_output:
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            if not drain_discarded(process.stdout, deadline):
                raise subprocess.TimeoutExpired(command, timeout)
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            process.wait(timeout=remaining)
            process.stdout.close()
            return subprocess.CompletedProcess(command, process.returncode, None, None)
        except BaseException as failure:
            try:
                cleanup_discarded(process)
            except (OSError, subprocess.TimeoutExpired):
                failure.cleanup_incomplete = True
            raise
    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)
    except BaseException:
        deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
        signal_group(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        # With streamed output the leader can exit while descendants are still
        # handling TERM. Give the entire group the promised grace period.
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                pass
            time.sleep(min(0.05, deadline - time.monotonic()))
        # Anything that ignored SIGTERM, or kept running after the leader exited, is killed.
        signal_group(process.pid, signal.SIGKILL)
        # Even a child that deliberately escaped the group must not hold us on a pipe.
        try:
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
                process.wait(timeout=5)
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
