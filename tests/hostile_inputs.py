"""Standard hostile-input fixture for hook tests: every hook that reads a path, stdin or JSON should be run
against these. Safe by construction: nothing here is read by the fixture itself, children run in their own
process group under a hard timeout (killpg) and, on Linux, an address-space cap, so a regression cannot
orphan a process or eat the machine. Heavy runs belong on dev2 (`ulimit -v` + this runner).

    from hostile_inputs import HostileInputs, run_capped
    with HostileInputs() as hostile:
        for label, path in hostile.paths().items(): ...
"""

import os
import resource
import signal
import subprocess
import sys
import tempfile
import time

DEVICES = ("/dev/zero", "/dev/urandom", "/dev/null", "/dev/tty")


class HostileInputs:
    def __init__(self, root=None):
        self._tmp = None if root else tempfile.TemporaryDirectory()
        self.root = os.fspath(root or self._tmp.name)

    def __enter__(self):
        self.build()
        return self

    def __exit__(self, *exc):
        if self._tmp:
            self._tmp.cleanup()

    def build(self):
        join = lambda name: os.path.join(self.root, name)  # noqa: E731
        os.makedirs(join("dir"), exist_ok=True)
        if not os.path.exists(join("fifo")):
            os.mkfifo(join("fifo"))
        with open(join("sparse-5g"), "wb") as handle:  # 5 GiB hole: reading it whole means seconds and gigabytes
            handle.truncate(5 * 1024 ** 3)
        for name, device in (("link-zero", "/dev/zero"), ("link-urandom", "/dev/urandom")):
            if not os.path.lexists(join(name)):
                os.symlink(device, join(name))
        with open(join("deep-json"), "wb") as handle:
            handle.write(b"[" * 5000 + b"]" * 5000 + b"\n")
        with open(join("invalid-utf8"), "wb") as handle:
            handle.write(b'{"type":"assistant","message":{"content":"\xff\xfe\xc3\x28 broken"}}\n\xf0\x28\x8c\x28\n')
        with open(join("nul-bytes"), "wb") as handle:
            handle.write(b'{"a":"x\x00y"}\n\x00\x00\x00\x00\n' + b"\x00" * 4096)
        with open(join("huge-line"), "wb") as handle:  # one 9 MiB line, no newline
            handle.write(b'{"k":"' + b"A" * (9 * 1024 * 1024) + b'"}')
        return self

    def paths(self, include_devices=True) -> dict:
        found = {name: os.path.join(self.root, name) for name in
                 ("dir", "fifo", "sparse-5g", "link-zero", "link-urandom", "deep-json", "invalid-utf8", "nul-bytes", "huge-line")}
        if include_devices:
            found.update({device: device for device in DEVICES if os.path.exists(device)})
        return found

    def never_regular(self) -> list:
        """Paths a hook must refuse to open (not regular files)."""
        return [path for label, path in self.paths().items()
                if label in ("dir", "fifo", "link-zero", "link-urandom") or label.startswith("/dev/")]


def run_capped(args, stdin_text="", env=None, timeout=8.0, mem_limit=1 << 30):
    """Run a hook child in its own process group with a hard timeout (killpg) and, where the OS enforces it,
    an address-space cap. Returns (returncode, stdout, stderr, seconds, peak_rss_bytes). Never leaves an orphan."""
    clock = time

    def limits():
        os.setsid()
        if sys.platform.startswith("linux"):  # RLIMIT_AS is not enforced on macOS
            resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))

    start = clock.perf_counter()
    child = subprocess.Popen([sys.executable, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, preexec_fn=limits)
    try:
        out, err = child.communicate(stdin_text.encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.communicate()
        return None, "", "TIMEOUT", clock.perf_counter() - start, 0
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except OSError:
            pass
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return child.returncode, out.decode(), err.decode(), clock.perf_counter() - start, peak
