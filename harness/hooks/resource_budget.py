#!/usr/bin/env python3
"""Resource-budget gate: every plan and spec declares what it will consume and where.

    resource_budget.py check --host mac|dev2 --packet plan.md [--capacity-json cap.json]
    resource_budget.py capacity --host mac|dev2

A plan packet or spec needs a `## Resource budget` section:

    ## Resource budget
    Host: dev2
    Fan-out: agents=2 jobs=1 processes=8 browser_pages=0 test_workers=4
    Peak memory: 6 GB (method: measured RSS of the previous run x1.5)
    CPU: 8 cores (method: nproc used by the test runner)
    Disk: 2 GB (method: size of the fixtures plus build output)
    Network: 100 MB (method: lockfile download size)
    Wall time: 25 min
    (a `Host: vm:<name>` budget also needs `Capacity: <memory, cores, disk>`; it is not read live)
    Cap and kill: run_capped.py --max-rss-gb 9 pauses on breach; netwatch kills only as last resort
    Checkpoint: durable output under ~/.agent-harness/work/<session>/<task>/, steps idempotent, resume by re-running

`check` rejects (exit 2) a packet that omits the section or a field, whose numbers exceed the
target host's live headroom, or that omits checkpointing for a job over 10 minutes or 4 GB.
The same budget can pass for dev2 and fail for the Mac. Big jobs are welcome on dev2; the gate
only asks that the numbers exist and fit. Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

CHECKPOINT_WALL_MIN = 10
CHECKPOINT_MEM_GB = 4
FANOUT_KEYS = ("agents", "jobs", "processes", "browser_pages", "test_workers")
# Per-host ceilings on top of live headroom: the Mac is the fragile host.
HOST_LIMITS = {
    "mac": {"processes": 8, "browser_pages": 4, "test_workers": 4, "agents": 8, "jobs": 2, "mem_fraction": 0.4},
    "dev2": {"processes": 64, "browser_pages": 16, "test_workers": 32, "agents": 8, "jobs": 16, "mem_fraction": 0.7},
}
SECTION = re.compile(r"(?ms)^##[ \t]+Resource budget[ \t]*\n(.*?)(?=^##[ \t]|\Z)")
FIELD = re.compile(r"(?m)^[ \t]*(?:[-*][ \t]+)?([A-Za-z][A-Za-z -]+?)[ \t]*:[ \t]*(.+?)[ \t]*$")
PLACEHOLDER = re.compile(r"<[^<>\n]{2,60}>")


def extract(text: str):
    match = SECTION.search(text)
    if not match:
        return None
    fields = {}
    for key, value in FIELD.findall(match.group(1)):
        fields.setdefault(key.strip().lower(), value.strip())
    return fields


def gb(value: str):
    match = re.search(r"(\d+(?:\.\d+)?)\s*(TB|GB|GiB|G|MB|MiB|M)\b", value, re.I)
    if not match:
        return None
    number, unit = float(match.group(1)), match.group(2).lower()
    return number * {"tb": 1024, "gb": 1, "gib": 1, "g": 1, "mb": 1 / 1024, "mib": 1 / 1024, "m": 1 / 1024}[unit]


def minutes(value: str):
    match = re.search(r"(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b", value, re.I)
    if not match:
        return None
    number, unit = float(match.group(1)), match.group(2).lower()
    return number * (1 / 60 if unit.startswith("s") else 60 if unit.startswith("h") else 1)


def fanout(value: str):
    pairs = dict((k.lower(), int(v)) for k, v in re.findall(r"([A-Za-z_]+)\s*=\s*(\d+)", value))
    return pairs


def lint_budget(text: str):
    """Structural problems only (no live capacity). Returns (problems, parsed-or-None)."""
    fields = extract(text)
    if fields is None:
        return ["the packet has no `## Resource budget` section (expected fan-out, peak memory/CPU/disk/network with "
                "estimate methods, wall time, host, cap and kill mechanism, checkpointing)"], None
    problems = []
    parsed = {"host": fields.get("host", "").split()[0].lower() if fields.get("host") else ""}
    if parsed["host"] not in HOST_LIMITS and not parsed["host"].startswith("vm"):
        problems.append("Resource budget: `Host:` must be mac, dev2 or vm:<name>")
    if parsed["host"].startswith("vm") and not fields.get("capacity"):
        problems.append("Resource budget: a vm host needs `Capacity:` stating its memory, cores and disk (it cannot be read live)")
    pairs = fanout(fields.get("fan-out", ""))
    missing = [k for k in FANOUT_KEYS if k not in pairs]
    if missing:
        problems.append("Resource budget: `Fan-out:` must give " + " ".join(f"{k}=N" for k in missing))
    parsed["fanout"] = pairs
    for name in ("peak memory", "cpu", "disk", "network"):
        value = fields.get(name, "")
        if not value or PLACEHOLDER.search(value):
            problems.append(f"Resource budget: `{name.title()}:` is missing")
        elif "method" not in value.lower():
            problems.append(f"Resource budget: `{name.title()}:` needs `(method: how you estimated it)`")
    parsed["mem_gb"] = gb(fields.get("peak memory", "")) or 0.0
    if fields.get("peak memory") and gb(fields["peak memory"]) is None:
        problems.append("Resource budget: `Peak memory:` needs a number with a unit, e.g. 6 GB")
    cores = re.search(r"(\d+(?:\.\d+)?)", fields.get("cpu", ""))
    parsed["cores"] = float(cores.group(1)) if cores else 0.0
    parsed["disk_gb"] = gb(fields.get("disk", "")) or 0.0
    parsed["wall_min"] = minutes(fields.get("wall time", ""))
    if parsed["wall_min"] is None:
        problems.append("Resource budget: `Wall time:` needs a number with a unit, e.g. 25 min")
    cap = fields.get("cap and kill", fields.get("cap", ""))
    if not cap or PLACEHOLDER.search(cap):
        problems.append("Resource budget: `Cap and kill:` must name the cap and kill mechanism for each heavy step")
    long_or_big = (parsed["wall_min"] or 0) > CHECKPOINT_WALL_MIN or parsed["mem_gb"] > CHECKPOINT_MEM_GB
    checkpoint = fields.get("checkpoint", "")
    if long_or_big:
        low = checkpoint.lower()
        if not checkpoint or low.startswith(("none", "n/a", "no ")):
            problems.append(f"Resource budget: a job over {CHECKPOINT_WALL_MIN} min or {CHECKPOINT_MEM_GB} GB must declare "
                            "`Checkpoint:` (durable output under the work dir, idempotent steps, how it resumes)")
        else:
            for needle, why in (("idempotent", "idempotent steps"), ("resume", "how it resumes")):
                if needle not in low:
                    problems.append(f"Resource budget: `Checkpoint:` must state {why}")
            if re.search(r"(?<![\w.])/(?:private/)?tmp\b", checkpoint) or "scratchpad" in low:
                problems.append("Resource budget: `Checkpoint:` output must live in the durable work dir, not /tmp or the scratchpad")
    return problems, parsed


def _run(argv, timeout=15):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout).stdout


def capacity(host: str):
    """Live headroom inputs for a host: {mem_available_gb, cores, load1, disk_free_gb, pressure_free_pct}."""
    if host == "mac":
        page = int(re.search(r"page size of (\d+)", _run(["vm_stat"])).group(1))
        vm = {k: int(v) for k, v in re.findall(r"Pages ([a-z ]+):\s+(\d+)\.", _run(["vm_stat"]))}
        avail = (vm.get("free", 0) + vm.get("inactive", 0) + vm.get("speculative", 0) + vm.get("purgeable", 0)) * page / 2 ** 30
        pressure = re.search(r"free percentage:\s*(\d+)%", _run(["memory_pressure", "-Q"]) if _which("memory_pressure") else "")
        disk = _run(["df", "-k", "/"]).splitlines()[-1].split()
        return {"host": host, "mem_available_gb": round(avail, 2), "cores": int(_run(["sysctl", "-n", "hw.ncpu"])),
                "load1": float(_run(["sysctl", "-n", "vm.loadavg"]).strip("{} \n").split()[0]),
                "disk_free_gb": round(int(disk[3]) / 2 ** 20, 1),
                "pressure_free_pct": int(pressure.group(1)) if pressure else None}
    script = ("free -m | awk '/Mem:/{print $7}'; nproc; cut -d' ' -f1 /proc/loadavg; df -k $HOME | awk 'END{print $4}'")
    out = _run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "dev2", script], 30).split()
    return {"host": host, "mem_available_gb": round(int(out[0]) / 1024, 2), "cores": int(out[1]), "load1": float(out[2]),
            "disk_free_gb": round(int(out[3]) / 2 ** 20, 1), "pressure_free_pct": None}


def _which(name):
    import shutil
    return shutil.which(name)


def headroom(cap: dict):
    limits = HOST_LIMITS.get(cap["host"], HOST_LIMITS["dev2"])
    pressure = cap.get("pressure_free_pct")
    mem = cap["mem_available_gb"] * limits["mem_fraction"]
    if pressure is not None and pressure < 20:
        mem = 0.0  # the Mac is already under memory pressure: nothing heavy fits
    return {"mem_gb": mem, "cores": max(0.0, cap["cores"] - cap["load1"]), "disk_gb": cap["disk_free_gb"] * 0.5,
            "limits": limits}


def check_numbers(parsed: dict, cap: dict):
    room = headroom(cap)
    problems = []
    host = cap["host"]
    if parsed["mem_gb"] > room["mem_gb"]:
        problems.append(f"peak memory {parsed['mem_gb']:g} GB exceeds {host} headroom {room['mem_gb']:.1f} GB "
                        f"({cap['mem_available_gb']:g} GB available x {room['limits']['mem_fraction']})")
    if parsed["cores"] > room["cores"]:
        problems.append(f"CPU {parsed['cores']:g} cores exceeds {host} spare cores {room['cores']:.1f} "
                        f"({cap['cores']} cores, load {cap['load1']:g})")
    if parsed["disk_gb"] > room["disk_gb"]:
        problems.append(f"disk {parsed['disk_gb']:g} GB exceeds {host} headroom {room['disk_gb']:.0f} GB")
    for key, ceiling in (("processes", "processes"), ("browser_pages", "browser_pages"), ("test_workers", "test_workers"),
                         ("agents", "agents"), ("jobs", "jobs")):
        if parsed["fanout"].get(key, 0) > room["limits"][ceiling]:
            problems.append(f"fan-out {key}={parsed['fanout'][key]} exceeds the {host} ceiling {room['limits'][ceiling]}")
    return problems


def check(text: str, host=None, cap=None):
    """All problems for a packet against `host` (default: its declared Host). cap may be injected."""
    problems, parsed = lint_budget(text)
    if parsed is None:
        return problems
    host = host or parsed["host"]
    if host in HOST_LIMITS:
        try:
            cap = cap or capacity(host)
        except (OSError, subprocess.SubprocessError, ValueError, IndexError, AttributeError) as error:
            return problems + [f"could not read {host} capacity ({type(error).__name__}); gate cannot compare numbers"]
        cap = dict(cap, host=host)
        problems += ["Resource budget: " + p for p in check_numbers(parsed, cap)]
    return problems


def plan_gate(packet: str, mode: str = "enforce", cap=None):
    """(exit_code, text) for peer_review.py plan and spec_flow lint."""
    if mode == "off":
        return 0, ""
    problems = check(packet, cap=cap)
    if not problems:
        return 0, ""
    text = "resource-budget gate:\n  - " + "\n  - ".join(problems)
    return (2, text) if mode == "enforce" else (0, text + "\n(warn mode: continuing)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("check")
    one.add_argument("--host", choices=("mac", "dev2"))
    one.add_argument("--packet", required=True)
    one.add_argument("--capacity-json", help="use this capacity instead of reading the live host (tests)")
    cap_cmd = sub.add_parser("capacity")
    cap_cmd.add_argument("--host", choices=("mac", "dev2"), required=True)
    args = parser.parse_args(argv)
    if args.command == "capacity":
        print(json.dumps(dict(capacity(args.host), headroom={k: v for k, v in headroom(capacity(args.host)).items()
                                                            if k != "limits"}), indent=1))
        return 0
    with open(args.packet) as handle:
        text = handle.read()
    cap = json.load(open(args.capacity_json)) if args.capacity_json else None
    problems = check(text, host=args.host, cap=cap)
    if problems:
        print("REJECTED:\n  - " + "\n  - ".join(problems))
        return 2
    print("OK: resource budget present and within headroom")
    return 0


if __name__ == "__main__":
    sys.exit(main())
