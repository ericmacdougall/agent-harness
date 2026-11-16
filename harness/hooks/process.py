"""Run a POSIX command with a deadline and clean up its process group on failure."""

import os
import selectors
import signal
import subprocess
import threading
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


def drain_discarded(pipe, deadline, sink=None):
    """Discard fixed-size chunks until every inherited writer closes or time runs out.

    An optional sink receives each chunk (for a bounded caller-owned log); the
    pipe is still drained here, so a slow or failing sink cannot block writers.
    """
    with selectors.DefaultSelector() as poller:
        poller.register(pipe, selectors.EVENT_READ)
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            if not poller.select(remaining):
                return False
            chunk = os.read(pipe.fileno(), DISCARD_CHUNK_BYTES)
            if not chunk:
                return True
            if sink is not None:
                sink(chunk)


def cleanup_discarded(process, sink=None):
    """Drain without retaining output while the process group exits."""
    grace_deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    signal_group(process.pid, signal.SIGTERM)
    try:
        drain_discarded(process.stdout, grace_deadline, sink)
    except (OSError, ValueError):
        pass
    while time.monotonic() < grace_deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            pass
        remaining = grace_deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.05, remaining))
    signal_group(process.pid, signal.SIGKILL)
    try:
        drain_discarded(process.stdout, time.monotonic() + DISCARD_CLEANUP_SECONDS, sink)
    except (OSError, ValueError):
        pass
    try:
        process.stdout.close()
    finally:
        process.wait(timeout=DISCARD_CLEANUP_SECONDS)


class OutputLimitExceeded(Exception):
    """The child's combined stdout and stderr passed the caller's output_limit; its group was stopped.

    stdout and stderr hold the bounded prefix captured before the stop (decoded like the normal result)."""

    def __init__(self, command, limit, stdout, stderr):
        super().__init__('output of %r exceeded %d bytes' % (command[0] if command else '', limit))
        self.command, self.limit, self.stdout, self.stderr = command, limit, stdout, stderr


class CleanupIncomplete(OSError):
    """The child's process group could not be proven gone (leader not reaped, a member still alive, or liveness
    could not be checked). Ownership is unknown: callers must not treat this as a known end (for example, must not
    release a provider reservation). `original` is the error that started the cleanup, when there was one.
    `cleanup_incomplete` follows the existing convention that usage_guard records on interrupted runs. Raised by the
    bounded-capture stop; the on_spawn failure path instead marks the callback error cleanup_incomplete."""
    cleanup_incomplete = True

    def __init__(self, message, original=None):
        super().__init__(message)
        self.original = original


def _confirm_gone(process, original=None):
    """After SIGKILL: reap the leader, then require that no member of its group remains, within a bounded deadline.
    A PermissionError on the liveness probe means liveness cannot be established, which also fails."""
    try:
        process.wait(timeout=DISCARD_CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        raise CleanupIncomplete('child %d could not be reaped' % process.pid, original) from original
    if not _wait_group(process, time.monotonic() + DISCARD_CLEANUP_SECONDS):
        raise CleanupIncomplete('process group %d could not be proven gone' % process.pid, original) from original


def _wait_group(process, deadline):
    """Wait until the leader is reaped and no member of its group remains, or until the deadline."""
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    return False


def _stop_bounded(process):
    """Stop the group without retaining more output: TERM, drain-discard, wait out the grace period for the whole
    group (a child may close its pipes and still be running its TERM handler), KILL, drain-discard, then prove the
    whole group is gone (_confirm_gone); otherwise CleanupIncomplete.

    stdin belongs to the feeder thread (it closes it); closing it here could block on the writer's lock."""
    pipes = [pipe for pipe in (process.stdout, process.stderr) if pipe is not None and not pipe.closed]
    signal_group(process.pid, signal.SIGTERM)
    grace = time.monotonic() + TERMINATION_GRACE_SECONDS
    for pipe in pipes:
        try:
            drain_discarded(pipe, grace)
        except (OSError, ValueError):
            pass
    _wait_group(process, grace)
    signal_group(process.pid, signal.SIGKILL)
    for pipe in pipes:
        try:
            drain_discarded(pipe, time.monotonic() + DISCARD_CLEANUP_SECONDS)
        except (OSError, ValueError):
            pass
    for pipe in pipes:
        try:
            pipe.close()
        except OSError:
            pass
    _confirm_gone(process)


def _bounded_capture(command, process, data, timeout, limit, decode):
    """communicate() with a ceiling on retained output: feed stdin from a thread (a large prompt cannot deadlock
    against a full output pipe), read both pipes in fixed chunks, and stop the group once the ceiling is passed.
    The feeder writes non-blocking and checks a stop flag, so a descendant that escaped the group and holds stdin
    open without reading cannot block cleanup."""
    deadline = None if timeout is None else time.monotonic() + timeout
    stop = threading.Event()

    def feed():
        try:
            descriptor = process.stdin.fileno()
            os.set_blocking(descriptor, False)
            view = memoryview(data or b'')
            with selectors.DefaultSelector() as writable:
                writable.register(descriptor, selectors.EVENT_WRITE)
                while view and not stop.is_set():
                    if not writable.select(0.1):
                        continue
                    try:
                        view = view[os.write(descriptor, view[:DISCARD_CHUNK_BYTES]):]
                    except BlockingIOError:
                        continue
        except (OSError, ValueError):
            pass  # the child exited or was stopped; its output decides the outcome
        finally:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass

    def finish_feeder():
        stop.set()
        if feeder is not None:
            feeder.join(DISCARD_CLEANUP_SECONDS)

    feeder = None
    if process.stdin is not None:
        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
    captured = {process.stdout: bytearray(), process.stderr: bytearray()}
    total = 0
    try:
        with selectors.DefaultSelector() as poller:
            for pipe in captured:
                poller.register(pipe, selectors.EVENT_READ)
            while poller.get_map():
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in poller.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), DISCARD_CHUNK_BYTES)
                    if not chunk:
                        poller.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > limit:
                        captured[key.fileobj] += chunk[:max(0, len(chunk) - (total - limit))]
                        raise OutputLimitExceeded(command, limit, decode(captured[process.stdout]),
                                                  decode(captured[process.stderr]))
                    captured[key.fileobj] += chunk
        remaining = None if deadline is None else max(0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(command, timeout) from None
    except BaseException:
        stop.set()
        try:
            _stop_bounded(process)  # CleanupIncomplete replaces the original error: the end is not known
        finally:
            finish_feeder()
        raise
    finish_feeder()
    for pipe in captured:
        pipe.close()
    return subprocess.CompletedProcess(command, process.returncode, decode(captured[process.stdout]),
                                       decode(captured[process.stderr]))


def run(command, *, cwd=None, env=None, timeout=None, input=None, text=True,
        stream=False, discard_output=False, sink=None, on_spawn=None, output_limit=None):
    # Git and test runners spawn children that subprocess.run(timeout=...) leaves alive.
    # Malformed output from a child must not bypass a caller's rollback path.
    # Keep binary mode exact for callers that inspect Git object bytes.
    if stream and discard_output:
        raise ValueError('stream and discard_output are mutually exclusive')
    if discard_output and input is not None:
        raise ValueError('discard_output does not accept input')
    if sink is not None and not discard_output:
        raise ValueError('sink requires discard_output')
    bounded = output_limit is not None
    if bounded and (stream or discard_output or type(output_limit) is not int or output_limit < 0):
        raise ValueError('output_limit needs captured output and a nonnegative integer')
    # Bounded capture reads raw bytes in fixed chunks and decodes them itself, like text mode would.
    decoding = {'errors': 'replace'} if text and not bounded else {}
    # The discard path drains one merged pipe to preserve descendant EOF semantics.
    output = None if stream else subprocess.PIPE
    process = subprocess.Popen(command, cwd=cwd, env=env, text=text and not bounded,
                               stdin=subprocess.PIPE if input is not None else None,
                               stdout=output,
                               stderr=subprocess.STDOUT if discard_output else output,
                               start_new_session=True, **decoding)
    if on_spawn is not None:
        # Lets a supervisor record the child it is responsible for (usage guard liveness).
        # If recording fails the child must not outlive the record: kill its group and re-raise the callback error.
        # When the group cannot be proven gone the error is marked cleanup_incomplete (the convention of the discard
        # path below), so a caller never treats it as a known end. The original type is kept: usage_guard relies on
        # a failed registration propagating as its own GuardError, which writes no final record.
        try:
            on_spawn(process)
        except BaseException as failure:
            try:
                signal_group(process.pid, signal.SIGKILL)
            except OSError:
                pass
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try: stream.close()
                    except OSError: pass
            try:
                _confirm_gone(process, failure)
            except CleanupIncomplete:
                try:
                    failure.cleanup_incomplete = True
                except AttributeError:
                    pass
            raise
    if discard_output:
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            if not drain_discarded(process.stdout, deadline, sink):
                raise subprocess.TimeoutExpired(command, timeout)
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            process.wait(timeout=remaining)
            process.stdout.close()
            return subprocess.CompletedProcess(command, process.returncode, None, None)
        except BaseException as failure:
            try:
                if sink is None:
                    cleanup_discarded(process)
                else:
                    cleanup_discarded(process, sink)
            except (OSError, subprocess.TimeoutExpired):
                failure.cleanup_incomplete = True
            raise
    if bounded:
        if text:
            data = input.encode('utf-8', errors='replace') if input is not None else None
            def decode(raw):
                return bytes(raw).decode('utf-8', errors='replace')
        else:
            data, decode = input, bytes
        return _bounded_capture(command, process, data, timeout, output_limit, decode)
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
