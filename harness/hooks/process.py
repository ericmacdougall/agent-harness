"""Run a POSIX command with a deadline and clean up its process group on failure."""

import os
import signal
import subprocess
import time

# Git removes its lock files from its SIGTERM handler; SIGKILL skips that cleanup.
TERMINATION_GRACE_SECONDS = 2


def signal_group(pid, signum):
    try:
        os.killpg(pid, signum)
    except (ProcessLookupError, PermissionError):
        # A group can disappear or become inaccessible between TERM and KILL.
        # The caller still reaps the leader and bounds pipe cleanup below.
        pass


def run(command, *, cwd=None, env=None, timeout=None, input=None, text=True,
        stream=False, discard_output=False):
    # Git and test runners spawn children that subprocess.run(timeout=...) leaves alive.
    # Malformed output from a child must not bypass a caller's rollback path.
    # Keep binary mode exact for callers that inspect Git object bytes.
    if stream and discard_output:
        raise ValueError('stream and discard_output are mutually exclusive')
    decoding = {'errors': 'replace'} if text else {}
    # Discarded output cannot accumulate in communicate()'s captured buffers.
    output = None if stream else (subprocess.DEVNULL if discard_output else subprocess.PIPE)
    process = subprocess.Popen(command, cwd=cwd, env=env, text=text,
                               stdin=subprocess.PIPE if input is not None else None,
                               stdout=output, stderr=output,
                               start_new_session=True, **decoding)
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
