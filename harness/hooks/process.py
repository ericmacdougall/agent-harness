"""Run a POSIX command with a deadline and clean up its process group on failure."""

import os
import signal
import subprocess


def run(command, *, cwd=None, env=None, timeout=None):
    # Git and test runners spawn children that subprocess.run(timeout=...) leaves alive.
    process = subprocess.Popen(command, cwd=cwd, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # Even a child that deliberately escaped the group must not hold us on a pipe.
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.stdout.close()
            process.stderr.close()
            process.wait(timeout=5)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
