#!/usr/bin/env python3
"""Resource-budget gate: every plan and spec declares what it will consume and where.

    resource_budget.py check --host mac|<host> --packet plan.md [--capacity-json cap.json]
    resource_budget.py capacity --host mac|<host>

<host> is a host named in ~/.agent-harness/local.json `hosts` (ah_local); its `limits` override the remote defaults.

A plan packet or spec needs a `## Resource budget` section:

    ## Resource budget
    Host: <a configured worker host, or mac>
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
The same budget can pass for a worker host and fail for the Mac. Big jobs are welcome on a worker host; the gate
only asks that the numbers exist and fit. Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # safe_input lives beside this file

CHECKPOINT_WALL_MIN = 10
CHECKPOINT_MEM_GB = 4
FANOUT_KEYS = ("agents", "jobs", "processes", "browser_pages", "test_workers")
# Per-host ceilings on top of live headroom: the Mac is the fragile host.
HOST_LIMITS = {
    # "agents" is not set here: headroom() fills it from owner_cap(), the one owner cap
    "mac": {"processes": 8, "browser_pages": 4, "test_workers": 4, "jobs": 2, "mem_fraction": 0.4},
}
# A configured worker host without its own `limits` in local.json gets these.
REMOTE_DEFAULT_LIMITS = {"processes": 64, "browser_pages": 16, "test_workers": 32, "jobs": 16, "mem_fraction": 0.7}


def host_limits() -> dict:
    """HOST_LIMITS plus every non-Windows host of ~/.agent-harness/local.json, with its `limits` laid over the
    remote defaults (numbers only)."""
    out = {k: dict(v) for k, v in HOST_LIMITS.items()}
    try:
        import ah_local  # noqa: PLC0415
        for name, info in ah_local.hosts().items():
            if name in out or str(info.get("os", "")).lower() == "windows" or not re.fullmatch(r"[a-z0-9._-]{1,60}", name):
                continue
            limits = dict(REMOTE_DEFAULT_LIMITS)
            given = info.get("limits") if isinstance(info.get("limits"), dict) else {}
            limits.update({k: v for k, v in given.items() if k in limits and isinstance(v, (int, float))
                           and not isinstance(v, bool)})
            out[name] = limits
    except Exception:  # noqa: BLE001 - a broken local file leaves the Mac only
        pass
    return out
SECTION = re.compile(r"(?ms)^##[ \t]+Resource budget[ \t]*\n(.*?)(?=^##[ \t]|\Z)")
FIELD = re.compile(r"(?m)^[ \t]*(?:[-*][ \t]+)?([A-Za-z][A-Za-z -]+?)[ \t]*:[ \t]*(.+?)[ \t]*$")
PLACEHOLDER = re.compile(r"<[^<>\n]{2,60}>")


FENCE = re.compile(r"(?ms)^[ \t]*(```|~~~).*?^[ \t]*\1[ \t]*$")
NUMBER = r"(\d+(?:\.\d+)?)"


def extract(text: str):
    """Fields of the first `## Resource budget` section outside code fences; (fields, duplicate-keys) or None."""
    match = SECTION.search(FENCE.sub("", text))
    if not match:
        return None
    fields, dupes = {}, []
    for key, value in FIELD.findall(match.group(1)):
        key = key.strip().lower()
        if key in fields:
            dupes.append(key)
        fields.setdefault(key, value.strip())
    fields["__dupes__"] = dupes
    return fields


# ---------------------------------------------------------------- limits: one place for the harness's numbers
#
# Defaults ship in the repo (resource_limits.json beside this file, else the code default below). A local override
# lives in ~/.agent-harness/limits.local.json ({"values": {key: {"value", "set_by", "reason", "at"}}}), written by
# `ah limits set`. Loosening is always honoured. Tightening is honoured only when set_by is "user" or
# "supervisor:<session>"; anything else an agent wrote is ignored with one log line (an agent-set threshold once
# blocked test starts until the owner lowered it). heavy_job_guard.json numbers beside the hooks are read the same way
# as an unsigned local value (honoured only when looser).

LIMITS = {  # key: (code default, type, which direction is looser)
    "max_live_owners": (16, int, "higher"),   # the one owner cap (agent_gate, tier_gate, mission_coverage, plans)
    "enforce": (False, bool, "lower"),        # true: the owner cap denies; false (default): a short advisory
    "max_heavy_mac": (2, int, "higher"),      # heavy jobs at once on the Mac (heavy_job_guard)
    "copy_gib": (1.0, float, "higher"),       # copies at or above this many GiB go to the worker host (heavy_job_guard)
    "hatch_per_hour": (1, int, "higher"),     # HARNESS_LOCAL_OK uses per owner per hour (heavy_job_guard)
    "min_free_gb": (25.0, float, "lower"),    # disk floor (for copy_hygiene to adopt; see docs/approvals.md)
}
LIMITS_LOCAL = "limits.local.json"
TRUSTED_SETTERS = re.compile(r"^(user|supervisor:[0-9A-Za-z-]{8,64})$")
_HERE = os.path.dirname(os.path.abspath(__file__))


def _state_home():
    return os.path.join(os.environ.get("AH_HOME") or os.path.expanduser("~"), ".agent-harness")


def _read_json(path, limit=64 * 1024):
    try:
        import safe_input
        data = safe_input.safe_json_loads(safe_input.read_bounded(path, limit), max_depth=20, max_bytes=limit)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - missing, oversize, FIFO or bad JSON: no values
        return {}


def _coerce(key, value):
    kind = LIMITS[key][1]
    if kind is bool:
        if isinstance(value, bool):
            return value
        if str(value).lower() in ("true", "false"):
            return str(value).lower() == "true"
        raise ValueError(f"{key} is true or false")
    if isinstance(value, bool):
        raise ValueError(f"{key} is a number")
    number = kind(value)
    if number < 0 or (kind is int and number == 0 and key != "enforce"):
        raise ValueError(f"{key} must be positive")
    return number


def _looser(key, value, than) -> bool:
    return value > than if LIMITS[key][2] == "higher" else value < than


def shipped_limit(key):
    """The repo default: resource_limits.json beside the hooks, else the code default. max_live_owners falls back to
    model_tiers.json caps.session_owner_agents for one release (old installs carry no max_live_owners)."""
    data = _read_json(os.path.join(_HERE, "resource_limits.json"))
    if key in data:
        try:
            return _coerce(key, data[key])
        except (TypeError, ValueError):
            pass
    if key == "max_live_owners":  # legacy key, read for one release only
        caps = _read_json(os.path.join(_HERE, "model_tiers.json")).get("caps")
        legacy = caps.get("session_owner_agents") if isinstance(caps, dict) else None
        if isinstance(legacy, int) and not isinstance(legacy, bool) and legacy > 0:
            return legacy
    return LIMITS[key][0]


def _local_entries():
    data = _read_json(os.path.join(_state_home(), LIMITS_LOCAL))
    values = data.get("values")
    return values if isinstance(values, dict) else {}


def _log_ignored(line: str) -> None:
    """One log line per distinct ignored value (the same line is not repeated back to back)."""
    try:
        directory = os.path.join(_state_home(), "logs")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        path = os.path.join(directory, "limits.log")
        try:
            with open(path, "rb") as handle:
                handle.seek(max(0, os.path.getsize(path) - 1024))
                if handle.read().decode("utf-8", "replace").rstrip("\n").endswith(line):
                    return
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + line + "\n")
    except OSError:
        pass


def limit_detail(key):
    """{key, default, value, source, ignored: [why...]} for one limit."""
    default = shipped_limit(key)
    value, source, ignored = default, "repo default", []
    candidates = []
    if key in ("copy_gib", "hatch_per_hour"):
        legacy = _read_json(os.path.join(_HERE, "heavy_job_guard.json")).get(key)
        if legacy is not None:
            candidates.append((legacy, "", "heavy_job_guard.json"))
    entry = _local_entries().get(key)
    if isinstance(entry, dict) and "value" in entry:
        candidates.append((entry["value"], str(entry.get("set_by") or ""), LIMITS_LOCAL + " (set by %s)"
                           % (entry.get("set_by") or "unknown")))
    for raw, setter, where in candidates:
        try:
            wanted = _coerce(key, raw)
        except (TypeError, ValueError):
            ignored.append(f"{where}: unreadable value {raw!r}")
            continue
        if wanted == value or _looser(key, wanted, value) or TRUSTED_SETTERS.match(setter):
            value, source = wanted, where
        else:
            why = f"{where}: {key}={wanted} tightens {value} and was not set by the owner or a supervisor; ignored"
            ignored.append(why)
            _log_ignored(why)
    return {"key": key, "default": default, "value": value, "source": source, "ignored": ignored}


def limit(key):
    """The effective value of one limit (never raises)."""
    try:
        return limit_detail(key)["value"]
    except Exception:  # noqa: BLE001
        return LIMITS[key][0]


def owner_cap() -> dict:
    """THE owner cap: {"max": live owners per session, "enforce": deny at the cap instead of advising}.
    Helpers, reviewers and testers are not owners and are never counted against it."""
    return {"max": int(limit("max_live_owners")), "enforce": bool(limit("enforce"))}


def set_limit(key, value, set_by, reason):
    """Write one local value. Refuses (ValueError) an agent's tightening: only the owner or a supervisor tightens."""
    if key not in LIMITS:
        raise ValueError("unknown limit; one of " + ", ".join(LIMITS))
    if not str(reason or "").strip():
        raise ValueError("--reason is required (it is shown in `ah limits show`)")
    wanted = _coerce(key, value)
    current = limit(key)
    if not TRUSTED_SETTERS.match(set_by) and wanted != current and not _looser(key, wanted, current):
        raise PermissionError(f"{key}={wanted} tightens the current {current}; only the owner or a supervisor tightens "
                              "a limit. Path: the owner runs `ah limits set ...` in a terminal, or pass --as-user "
                              "--user-msg <id> citing the owner's message")
    path = os.path.join(_state_home(), LIMITS_LOCAL)
    data = _read_json(path)
    values = data.get("values") if isinstance(data.get("values"), dict) else {}
    values[key] = {"value": wanted, "set_by": set_by, "reason": str(reason)[:500],
                   "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    temporary = path + ".%d" % os.getpid()
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({"values": values}, handle, indent=1, sort_keys=True)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return limit_detail(key)


def limits_cli(argv=None, env=None) -> int:
    """`ah limits show [--json]` and `ah limits set KEY VALUE --reason R [--as-user --user-msg ID]`."""
    parser = argparse.ArgumentParser(prog="ah limits")
    sub = parser.add_subparsers(dest="action", required=True)
    show = sub.add_parser("show")
    show.add_argument("--json", action="store_true")
    put = sub.add_parser("set")
    put.add_argument("key", choices=sorted(LIMITS))
    put.add_argument("value")
    put.add_argument("--reason", required=True)
    put.add_argument("--as-user", action="store_true")
    put.add_argument("--user-msg")
    args = parser.parse_args(argv)
    if args.action == "show":
        rows = [limit_detail(key) for key in LIMITS]
        if args.json:
            print(json.dumps(rows, indent=1))
        else:
            for row in rows:
                print(f"{row['key']:<16} {str(row['value']):<8} (default {row['default']}; from {row['source']})")
                for why in row["ignored"]:
                    print(" " * 17 + "ignored: " + why)
        return 0
    import ah_approvals
    try:
        try:
            who, _ = ah_approvals.caller(args.as_user, args.user_msg, env=env)
        except ah_approvals.Refused:
            who = "agent:" + (ah_approvals.calling_session(env) or "unknown")  # may loosen, never tighten
        row = set_limit(args.key, args.value, who, args.reason)
    except (ValueError, PermissionError) as error:
        print(json.dumps({"ok": False, "code": "refused" if isinstance(error, PermissionError) else "bad_request",
                          "message": str(error)}))
        return 3 if isinstance(error, PermissionError) else 2
    print(json.dumps({"ok": True, "limit": row}, indent=1))
    return 0


def head(value: str) -> str:
    """The declared figure: everything before the `(method: ...)` note, so the note cannot supply the number."""
    return value.split("(")[0]


def clean_number(text: str):
    """True when `text` holds no thousands separators, underscores or exponents that would misparse."""
    return not re.search(r"\d[,_]\d|\d[eE][+-]?\d", text)


def gb(value: str):
    value = head(value)
    if not clean_number(value):
        return None
    if len(re.findall(NUMBER, value)) != 1:
        return None  # exactly one figure before the method note: "3 GB 900 GB" is ambiguous
    match = re.search(NUMBER + r"\s*(TB|GB|GiB|G|MB|MiB|M)\b", value, re.I)
    if not match:
        return None
    number, unit = float(match.group(1)), match.group(2).lower()
    return number * {"tb": 1024, "gb": 1, "gib": 1, "g": 1, "mb": 1 / 1024, "mib": 1 / 1024, "m": 1 / 1024}[unit]


def minutes(value: str):
    value = head(value)
    if not clean_number(value):
        return None
    if len(re.findall(NUMBER, value)) != 1:
        return None
    match = re.search(NUMBER + r"\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b", value, re.I)
    if not match:
        return None
    number, unit = float(match.group(1)), match.group(2).lower()
    return number * (1 / 60 if unit.startswith("s") else 60 if unit.startswith("h") else 1)


def fanout(value: str):
    pairs, dupes, bad = {}, [], False
    for key, number, tail in re.findall(r"([A-Za-z_]+)\s*=\s*(\d+)([^\s]*)", value):
        if tail:
            bad = True  # 1_000, 1e3, 5x ...
        key = key.lower()
        if key in pairs:
            dupes.append(key)
        pairs[key] = int(number)
    return pairs, dupes, bad


VM_HOST = re.compile(r"^vm:[A-Za-z0-9._-]+$")


def lint_budget(text: str):
    """Structural problems only (no live capacity). Returns (problems, parsed-or-None)."""
    fields = extract(text)
    if fields is None:
        return ["the packet has no `## Resource budget` section (expected fan-out, peak memory/CPU/disk/network with "
                "estimate methods, wall time, host, cap and kill mechanism, checkpointing)"], None
    problems = []
    for key in fields["__dupes__"]:
        problems.append(f"Resource budget: `{key}` is declared more than once")
    host = fields.get("host", "").split()[0].lower() if fields.get("host") else ""
    parsed = {"host": host}
    if host not in host_limits() and not VM_HOST.match(host):
        problems.append("Resource budget: `Host:` must be mac, a host named in ~/.agent-harness/local.json, or vm:<name>")
    parsed["capacity"] = None
    if VM_HOST.match(host):
        cap_text = fields.get("capacity", "")
        mem_match = re.search(NUMBER + r"\s*(TB|GB|GiB|G)\b\s*(?:of\s+)?(?:memory|ram)", cap_text, re.I)
        cap_mem = (float(mem_match.group(1)) * (1024 if mem_match.group(2).lower() == "tb" else 1)) if mem_match else None
        cap_cores = re.search(NUMBER + r"\s*cores?\b", cap_text, re.I)
        if cap_mem is None or not cap_cores:
            problems.append("Resource budget: a vm host needs `Capacity:` with memory and cores, e.g. 16 GB memory, 8 cores, 100 GB disk")
        else:
            disk = re.search(NUMBER + r"\s*(GB|TB)\s*disk", cap_text, re.I)
            parsed["capacity"] = {"host": host, "mem_available_gb": cap_mem, "cores": float(cap_cores.group(1)), "load1": 0.0,
                                  "disk_free_gb": (float(disk.group(1)) * (1024 if disk.group(2).upper() == "TB" else 1)) if disk else 1e9,
                                  "pressure_free_pct": None}
    pairs, dupes, bad = fanout(fields.get("fan-out", ""))
    missing = [k for k in FANOUT_KEYS if k not in pairs]
    if missing or bad or dupes:
        problems.append("Resource budget: `Fan-out:` must give each of " + " ".join(f"{k}=N" for k in FANOUT_KEYS)
                        + " once, as plain integers")
    parsed["fanout"] = pairs
    for name in ("peak memory", "cpu", "disk", "network"):
        value = fields.get(name, "")
        if not value or PLACEHOLDER.search(value):
            problems.append(f"Resource budget: `{name.title()}:` is missing")
        elif "method" not in value.lower():
            problems.append(f"Resource budget: `{name.title()}:` needs `(method: how you estimated it)`")
    parsed["mem_gb"] = gb(fields.get("peak memory", "")) or 0.0
    if fields.get("peak memory") and not parsed["mem_gb"] > 0:
        problems.append("Resource budget: `Peak memory:` needs one plain positive number with a unit before the method, e.g. 6 GB")
    cpu_head = head(fields.get("cpu", ""))
    cores = re.search(NUMBER, cpu_head) if clean_number(cpu_head) and len(re.findall(NUMBER, cpu_head)) == 1 else None
    parsed["cores"] = float(cores.group(1)) if cores else 0.0
    if fields.get("cpu") and not parsed["cores"] > 0:
        problems.append("Resource budget: `CPU:` needs one plain positive number of cores before the method")
    disk = fields.get("disk", "")
    parsed["disk_gb"] = gb(disk) or 0.0
    if disk and gb(disk) is None:
        problems.append("Resource budget: `Disk:` needs one plain number with a unit before the method")
    parsed["wall_min"] = minutes(fields.get("wall time", ""))
    if not parsed["wall_min"] or parsed["wall_min"] <= 0:
        problems.append("Resource budget: `Wall time:` needs one plain positive number with a unit, e.g. 25 min")
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
    if host not in host_limits():
        raise ValueError("unknown host")
    out = _run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", host, script], 30).split()
    return {"host": host, "mem_available_gb": round(int(out[0]) / 1024, 2), "cores": int(out[1]), "load1": float(out[2]),
            "disk_free_gb": round(int(out[3]) / 2 ** 20, 1), "pressure_free_pct": None}


def _which(name):
    import shutil
    return shutil.which(name)


def headroom(cap: dict):
    limits = dict(host_limits().get(cap["host"], REMOTE_DEFAULT_LIMITS))
    limits["agents"] = owner_cap()["max"]  # a plan's agent fan-out is held to the one owner cap, not a number of its own
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
    if host in host_limits():
        try:
            cap = cap or capacity(host)
        except (OSError, subprocess.SubprocessError, ValueError, IndexError, AttributeError) as error:
            # Fail open: an unreachable host must not stop planning. Reported as a warning, not a rejection.
            return problems + [f"WARN: could not read {host} capacity ({type(error).__name__}); numbers not compared"]
        cap = dict(cap, host=host)
    elif parsed.get("capacity"):
        cap = parsed["capacity"]
    else:
        return problems
    return problems + ["Resource budget: " + p for p in check_numbers(parsed, cap)]


def plan_gate(packet: str, mode: str = "enforce", cap=None):
    """(exit_code, text) for peer_review.py plan and spec_flow lint."""
    if mode == "off":
        return 0, ""
    found = check(packet, cap=cap)
    problems = [p for p in found if not p.startswith("WARN:")]
    warnings = [p for p in found if p.startswith("WARN:")]
    if not problems and not warnings:
        return 0, ""
    text = "resource-budget gate:\n  - " + "\n  - ".join(problems + warnings)
    if problems and mode == "enforce":
        return 2, text
    return 0, text + ("\n(warn mode: continuing)" if problems else "")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("check")
    one.add_argument("--host", help="mac or a host named in ~/.agent-harness/local.json")
    one.add_argument("--packet", required=True)
    one.add_argument("--capacity-json", help="use this capacity instead of reading the live host (tests)")
    cap_cmd = sub.add_parser("capacity")
    cap_cmd.add_argument("--host", required=True, help="mac or a host named in ~/.agent-harness/local.json")
    args = parser.parse_args(argv)
    if args.command == "capacity":
        print(json.dumps(dict(capacity(args.host), headroom={k: v for k, v in headroom(capacity(args.host)).items()
                                                            if k != "limits"}), indent=1))
        return 0
    import safe_input
    try:
        text = safe_input.read_bounded(args.packet, 1024 * 1024).decode("utf-8", "replace")
        cap = (safe_input.safe_json_loads(safe_input.read_bounded(args.capacity_json, 64 * 1024), max_depth=10, max_bytes=64 * 1024)
               if args.capacity_json else None)
    except (safe_input.InputRejected, ValueError) as error:
        print(f"REJECTED: cannot read the input safely ({getattr(error, 'code', 'bad-json')})")
        return 2
    found = check(text, host=args.host, cap=cap)
    problems = [p for p in found if not p.startswith("WARN:")]
    for note in found:
        if note.startswith("WARN:"):
            print(note)
    if problems:
        print("REJECTED:\n  - " + "\n  - ".join(problems))
        return 2
    print("OK: resource budget present and within headroom")
    return 0


if __name__ == "__main__":
    sys.exit(main())
