#!/usr/bin/env python3
"""Run a hostile/abuse probe under the exact bound it declared. For red-team work.

    run_probe.py --class memory --worst-case "reads /dev/zero: unbounded RSS" \\
        --max-rss-gb 1 --timeout-s 10 [--max-file-mb N] [--max-procs N] [--net] \\
        [--report out.json] -- <command...>

Breaking things with hostile input is the red team's job. The contract is that the
probe first DECLARES its expected worst-case side effect, its class, and the bound it
will enforce, and this runner enforces exactly that bound so the probe can never
become a system-wide incident. A breach is the EXPECTED RESULT of a successful probe:
it is recorded as a finding, the whole process group is killed cleanly, and the run
exits 3. This is the one place a hard bound is right: the finding is the output, not
work to preserve.

Refused (exit 2) when the declaration is missing: --class, --worst-case, a wall-clock
--timeout-s, and the bound that matches the class (memory -> --max-rss-gb, disk ->
--max-file-mb, process -> --max-procs). Classes: memory, disk, cpu, process, network,
external-write, sandbox-escape, hang.

Honest limits: the disk bound counts the probe's sandbox directory only (RLIMIT_FSIZE bounds each file
anywhere); HOME/TMPDIR are environment variables, not filesystem confinement, so a probe can still write
elsewhere (class external-write/sandbox-escape probes should declare that and run on dev2 or a throwaway
dir); bounds are polled, so memory and process counts overshoot by one poll interval. Daemonized
(setsid) escapees are only accounted for on Linux, where the runner is a subreaper; the report says so.
Every probe also gets a default RSS ceiling of 25% of physical memory when it declares none.

Enforced: group+descendant RSS, wall clock, process count, RLIMIT_FSIZE plus the size
of the sandbox directory, RLIMIT_CORE=0. The probe gets a private HOME/TMPDIR (removed
afterwards). Network is denied unless --net (macOS sandbox-exec; elsewhere the report
says "not enforced"). Exit codes: 0 completed inside its bounds (child rc in the
report), 3 bound hit (finding), 2 refused/usage, 130+ signalled.

Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import math
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_capped  # noqa: E402

def positive_finite(text):
    """argparse type: a finite number > 0. NaN/inf would silently disable every comparison against the bound."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number")
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"{text!r} must be a finite number greater than 0")
    return value


CLASSES = ("memory", "disk", "cpu", "process", "network", "external-write", "sandbox-escape", "hang")
REQUIRED_BOUND = {"memory": "max_rss_gb", "disk": "max_file_mb", "process": "max_procs"}
SANDBOX_NO_NET = "(version 1)(allow default)(deny network*)"


def dir_size_mb(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total / 1048576


def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--class", dest="klass", choices=CLASSES)
    parser.add_argument("--worst-case", dest="worst_case")
    parser.add_argument("--max-rss-gb", type=positive_finite, default=0)
    parser.add_argument("--timeout-s", type=positive_finite, default=0)
    parser.add_argument("--max-file-mb", type=positive_finite, default=0)
    parser.add_argument("--max-procs", type=int, default=0)
    parser.add_argument("--net", action="store_true", help="declare that the probe needs the network")
    parser.add_argument("--report")
    parser.add_argument("--poll-s", type=positive_finite, default=0.1)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        phys_gb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2 ** 30
    except (ValueError, OSError, AttributeError):
        phys_gb = 8.0
    args.phys_gb = phys_gb
    args.rss_defaulted = False
    args.command = args.command[1:] if args.command[:1] == ["--"] else args.command
    missing = []
    if not args.klass:
        missing.append("--class")
    if not args.worst_case or len(args.worst_case.strip()) < 8:
        missing.append("--worst-case '<expected worst-case side effect>'")
    if args.timeout_s <= 0:
        missing.append("--timeout-s (every probe needs a wall-clock bound)")
    need = REQUIRED_BOUND.get(args.klass)
    if need and not getattr(args, need):
        missing.append("--" + need.replace("_", "-") + f" (the bound for class {args.klass})")
    if not args.command:
        missing.append("-- <command>")
    if args.max_rss_gb > phys_gb:
        missing.append(f"--max-rss-gb must not exceed physical memory ({phys_gb:.0f} GB)")
    if not missing and not args.max_rss_gb:
        fraction = float(os.environ.get("HARNESS_PROBE_RSS_FRACTION", "0.25"))  # env override exists for tests
        args.max_rss_gb, args.rss_defaulted = round(phys_gb * fraction, 2), True  # every class gets a memory ceiling
    if missing:
        parser.exit(2, "run_probe: REFUSED, declaration incomplete. Declare before running: " + "; ".join(missing) + "\n")
    return args


def main(argv=None):
    args = parse(argv if argv is not None else sys.argv[1:])
    sandbox = tempfile.mkdtemp(prefix="run-probe-")
    env = dict(os.environ, HOME=sandbox, TMPDIR=sandbox, XDG_CACHE_HOME=sandbox, XDG_CONFIG_HOME=sandbox,
               XDG_DATA_HOME=sandbox)
    command, network = list(args.command), "allowed (declared)"
    if not args.net:
        for key in [k for k in env if k.lower().endswith("_proxy")]:
            env.pop(key)
        if sys.platform == "darwin" and shutil.which("sandbox-exec"):
            command, network = ["sandbox-exec", "-p", SANDBOX_NO_NET] + command, "denied (sandbox-exec)"
        else:
            network = "not enforced (no sandbox-exec on this host)"

    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if args.max_file_mb:
            cap = int(args.max_file_mb * 1048576)
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))

    subreaper = run_capped.become_subreaper()
    started = time.time()
    finding, rc = None, None
    try:
        child = subprocess.Popen(command, start_new_session=True, env=env, preexec_fn=limits)
    except OSError as error:
        sys.stderr.write(f"run_probe: cannot start: {error}\n")
        shutil.rmtree(sandbox, ignore_errors=True)
        return 127
    pgid, stop = child.pid, {"sig": None}
    for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"):
        signal.signal(getattr(signal, name), lambda s, _f: stop.__setitem__("sig", s))
    guardian = os.fork()
    if guardian == 0:
        run_capped.guardian(os.getppid(), child.pid, pgid)
    run_capped.EXCLUDE.add(guardian)
    peak_rss = peak_procs = 0.0
    try:
        while True:
            if stop["sig"] is not None:
                finding = ("signalled", f"probe runner received signal {stop['sig']}")
                break
            rc = child.poll()
            try:
                live = run_capped.members(child.pid, pgid)
            except (subprocess.SubprocessError, OSError):
                live = []
            rss_gb = sum(r[3] for r in live) / 1048576
            peak_rss, peak_procs = max(peak_rss, rss_gb), max(peak_procs, len(live))
            elapsed = time.time() - started
            if args.max_rss_gb and rss_gb > args.max_rss_gb:
                finding = ("memory", f"memory bound hit: {rss_gb:.2f} GB > {args.max_rss_gb:g} GB")
            elif args.max_procs and len(live) > args.max_procs:
                finding = ("process", f"process-count bound hit: {len(live)} > {args.max_procs}")
            elif args.max_file_mb and dir_size_mb(sandbox) >= args.max_file_mb - 0.01:
                finding = ("disk", f"file-size bound hit: sandbox grew past {args.max_file_mb:g} MB")
            elif elapsed > args.timeout_s:
                finding = ("time", f"time bound hit: still running after {args.timeout_s:g} s (hang or spin)")
            elif rc is not None and rc == -signal.SIGXFSZ:
                finding = ("disk", f"file-size bound hit: RLIMIT_FSIZE {args.max_file_mb:g} MB")
            if finding:
                break
            if rc is not None:
                if len(live) > 1 or any(r[0] != child.pid for r in live):
                    run_capped.kill_tree(child.pid, pgid)
                break
            time.sleep(args.poll_s)
        if finding:
            run_capped.kill_tree(child.pid, pgid)
            try:
                rc = child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                rc = None
    finally:
        try:
            os.kill(guardian, signal.SIGKILL)
            os.waitpid(guardian, 0)
        except OSError:
            pass
        left = run_capped.members(child.pid, pgid)
        shutil.rmtree(sandbox, ignore_errors=True)
    report = {
        "declared": {"class": args.klass, "worst_case": args.worst_case, "max_rss_gb": args.max_rss_gb,
                     "timeout_s": args.timeout_s, "max_file_mb": args.max_file_mb, "max_procs": args.max_procs,
                     "net": args.net},
        "command": os.path.basename(args.command[0]), "network": network,
        "outcome": ("bound-hit:" + finding[0]) if finding else "completed",
        "finding": finding[1] if finding else None, "child_rc": rc,
        "observed": {"peak_rss_gb": round(peak_rss, 3), "peak_procs": int(peak_procs),
                     "seconds": round(time.time() - started, 2)},
        "survivors": len(left),
        "escape_detection": "subreaper (daemonized descendants are counted and killed)" if subreaper else
                            "unavailable on this host: a double-forked setsid daemon may escape accounting",
        "rss_bound_defaulted": args.rss_defaulted,
    }
    text = json.dumps(report, indent=1)
    if args.report:
        with open(args.report, "w") as handle:
            handle.write(text + "\n")
    print(("FINDING: " + finding[1]) if finding else "PROBE COMPLETED within its declared bounds")
    print(text)
    if finding and finding[0] == "signalled":
        return 130
    return 3 if finding else 0


if __name__ == "__main__":
    sys.exit(main())
