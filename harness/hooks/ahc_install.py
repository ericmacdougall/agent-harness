#!/usr/bin/env python3
"""ahc install, uninstall and unit status on the build host (GoodQA goodqa#16034 D1, AC-11, AC-29).

Two systemd user units run the daemon: `ahc-core` (ingest, escalation, effects; the only ledger migrator) and
`ahc-review` (recovery of in-flight reviews, then one receipt run at a time). Lingering keeps them running with
nobody logged in and starts them at boot, so recovery runs before any dispatch (each role recovers or ingests at the
top of its first tick).

install:   records whether lingering was on (once: a re-install never overwrites the first record), writes both
           unit files (an existing one is copied aside first), the `ahc` wrapper in ~/.local/bin and the default
           `ops_ticket` in the coordinator config (only if absent), then enables lingering if it was off and runs
           `systemctl --user daemon-reload` and `enable --now` for both units.
uninstall: disables and stops both units, removes the unit files and the wrapper, puts lingering back as the install
           record found it (a missing record leaves lingering alone), and keeps the ledger, clones, inbox, reports
           and digest in place, printing their paths. Deleting those is a separate manual step after a verified
           backup.
Without --apply both print what they would do and change nothing. Every child is an argv list through `run`, so
tests never touch the real systemctl or loginctl. systemd only: another platform is refused, never half-installed.
"""
from __future__ import annotations

import json
import os
import platform
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ahc_core as core  # noqa: E402
import ahc_fs as fs  # noqa: E402

UNITS = ("ahc-core", "ahc-review")
RECORD = "install.json"
RECORD_MAX_BYTES = 1_000_000
DEFAULT_OPS_TICKET = "GoodQA goodqa#16034"
WRAPPER_MARK = "# ahc wrapper (goodqa#16034)"
MEMORY = {"ahc-core": "512M", "ahc-review": "2G"}   # spec footprint: daemon < 100 MB (cap 512 MB); a review ~600 MB
NICE = {"ahc-core": 5, "ahc-review": 10}
ROLE = {"ahc-core": "core", "ahc-review": "review"}
DESCRIPTION = {"ahc-core": "ahc coordinator core: ingest, escalation, effects (GoodQA goodqa#16034)",
               "ahc-review": "ahc coordinator review: exact-head receipt runs (GoodQA goodqa#16034)"}


def default_run(argv, timeout=60):
    """(rc, stdout) of one argv child; never a shell. A missing binary is rc 127."""
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
                              check=False)
        return proc.returncode, proc.stdout
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


def unit_dir(home: Path) -> Path:
    return home / ".config" / "systemd" / "user"


def unit_text(name: str) -> str:
    """The unit file. Exit 3 (schema refusal) and 75 (another instance holds the role lock) never restart, so a
    failed migration cannot loop making backups and a duplicate cannot spin. A user unit does not inherit a login
    shell's PATH, so the unit states one that finds gh and the reviewer CLIs in the usual per-user locations."""
    return f"""[Unit]
Description={DESCRIPTION[name]}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=900
StartLimitBurst=20

[Service]
Type=simple
ExecStart=/usr/bin/env python3 -I %h/.claude/hooks/ahc_runner.py run --role {ROLE[name]}
Environment=PATH=%h/.local/bin:%h/bin:%h/.npm-global/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=15
RestartPreventExitStatus=3 75
TimeoutStopSec=90
Nice={NICE[name]}
MemoryMax={MEMORY[name]}
MemorySwapMax=0
NoNewPrivileges=yes

[Install]
WantedBy=default.target
"""


def wrapper_text() -> str:
    return ("#!/bin/sh\n%s\nexec /usr/bin/env python3 -I \"$HOME/.claude/hooks/ahc_runner.py\" \"$@\"\n" % WRAPPER_MARK)


def installed_files(home: Path) -> dict:
    """{path: expected text} of every launch file install writes: both unit files and the ~/.local/bin wrapper. The
    migration preflight checks these against this code's text (PR 247 F5), never against what is installed."""
    files = {str(unit_dir(home) / ("%s.service" % name)): unit_text(name) for name in UNITS}
    files[str(home / ".local" / "bin" / "ahc")] = wrapper_text()
    return files


def _user() -> str:
    return os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name


def linger_on(run) -> bool | None:
    """True or False from loginctl, None when it cannot be read."""
    rc, out = run(["loginctl", "show-user", _user(), "-p", "Linger", "--value"])
    if rc != 0:
        return None
    value = (out or "").strip()
    return True if value == "yes" else False if value == "no" else None


def _record_path(paths) -> Path:
    return paths.root / RECORD


def read_record(paths) -> dict | None:
    try:
        data = json.loads(core.read_regular(_record_path(paths), RECORD_MAX_BYTES).decode("utf-8"))
    except (OSError, ValueError, core.Unreadable):
        return None
    return data if isinstance(data, dict) else None


def _write_in_root(paths, path: Path, text: str) -> None:
    """A file under the ahc root (install.json, config.json): through ahc_fs, never a path-based write."""
    fs.write_file(paths.root, path, text)


def _write_private(path: Path, text: str, mode=0o600) -> None:
    """A file OUTSIDE the ahc root: a systemd user unit or the ~/.local/bin wrapper. These locations belong to the
    user's own configuration, not to ahc's root. They are allowlisted in tests/test_ahc_fs.py with this reason."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".%s.%d.tmp" % (path.name, os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(str(tmp), mode)
    os.replace(str(tmp), str(path))


def kept_paths(paths) -> list:
    return [("ledger", paths.root / "ledger.sqlite3"), ("clones", paths.clones), ("inbox", paths.inbox),
            ("reports", paths.reports), ("digest", paths.digest), ("item journals", paths.items)]


def _refuse_platform(system: str, out) -> int | None:
    if system != "Linux":
        out("ahc install: systemd user units only (this host is %s); nothing changed. Run it on a Linux host."
            % system)
        return 2
    return None


def install(paths, home: Path, apply: bool, run=default_run, system=None, out=print, now=None) -> int:
    refused = _refuse_platform(system or platform.system(), out)
    if refused is not None:
        return refused
    if apply and shutil.which("systemctl") is None and run is default_run:
        out("ahc install: systemctl not found; nothing changed")
        return 2
    verb = "" if apply else "would "
    paths.ensure()
    record = read_record(paths)
    linger = linger_on(run)
    files = sorted(installed_files(home))
    if record is None:
        record = {"linger_before": linger, "installed_at": now or time.time(), "user": _user(), "files": files}
        out("%srecord install state %s (lingering was %s)" % (verb, _record_path(paths),
                                                             {True: "on", False: "off", None: "unknown"}[linger]))
        if apply:
            _write_in_root(paths, _record_path(paths), json.dumps(record, sort_keys=True) + "\n")
    else:
        out("keep the first install record %s (lingering was %s before ahc)"
            % (_record_path(paths), {True: "on", False: "off", None: "unknown"}[record.get("linger_before")]))
        if record.get("files") != files:
            # an earlier install (4d45fe40) recorded no launch files: add them, keeping linger_before
            out("%srecord the installed launch files in %s" % (verb, _record_path(paths)))
            if apply:
                _write_in_root(paths, _record_path(paths), json.dumps(dict(record, files=files), sort_keys=True) + "\n")
    for name in UNITS:
        target = unit_dir(home) / ("%s.service" % name)
        if target.exists() and target.read_text(encoding="utf-8", errors="replace") != unit_text(name):
            backup = target.with_name(target.name + ".bak-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
            out("%scopy the existing %s aside to %s" % (verb, target.name, backup.name))
            if apply:
                shutil.copy2(str(target), str(backup))
        out("%swrite %s" % (verb, target))
        if apply:
            _write_private(target, unit_text(name), 0o644)
    wrapper = home / ".local" / "bin" / "ahc"
    out("%swrite the ahc wrapper %s" % (verb, wrapper))
    if apply:
        _write_private(wrapper, wrapper_text(), 0o755)
    config = paths.root / "config.json"
    try:
        current = json.loads(core.read_regular(config, RECORD_MAX_BYTES).decode("utf-8")) \
            if os.path.lexists(str(config)) else {}
    except (OSError, ValueError, core.Unreadable):
        current = None
    if current is None:
        out("leave %s alone: it is not valid JSON (fix it by hand)" % config)
    elif "ops_ticket" not in current:
        out("%sset ops_ticket=%s in %s" % (verb, DEFAULT_OPS_TICKET, config))
        if apply:
            _write_in_root(paths, config, json.dumps(dict(current, ops_ticket=DEFAULT_OPS_TICKET), indent=1,
                                                     sort_keys=True) + "\n")
    cmds = []
    if linger is not True:
        cmds.append(["loginctl", "enable-linger", _user()])
    cmds += [["systemctl", "--user", "daemon-reload"],
             ["systemctl", "--user", "enable", "--now"] + ["%s.service" % n for n in UNITS]]
    failed = 0
    for argv in cmds:
        out("%srun %s" % (verb, " ".join(argv)))
        if apply:
            rc, _ = run(argv)
            if rc != 0:
                failed += 1
                out("  failed: exit %s" % rc)
    if apply and not failed:
        for name in UNITS:
            rc, state = run(["systemctl", "--user", "is-active", "%s.service" % name])
            out("%s: %s" % (name, (state or "").strip() or "unknown"))
    return 1 if failed else 0


def uninstall(paths, home: Path, apply: bool, run=default_run, system=None, out=print) -> int:
    refused = _refuse_platform(system or platform.system(), out)
    if refused is not None:
        return refused
    verb = "" if apply else "would "
    failed = 0
    # PR 247 receipt F3: a retry after a partial uninstall disables only the units whose files are still there
    present = [n for n in UNITS if (unit_dir(home) / ("%s.service" % n)).exists()]
    if present:
        argv = ["systemctl", "--user", "disable", "--now"] + ["%s.service" % n for n in present]
        out("%srun %s" % (verb, " ".join(argv)))
        if apply and run(argv)[0] != 0:
            failed += 1
            out("  failed")
    else:
        out("no ahc unit file is installed; nothing to disable")
    # PR 247 receipt F3: nothing that manages a service is removed while it may still run
    out("%scheck that both units are stopped" % verb)
    if apply:
        running = [n for n in UNITS if _maybe_running(run, n)]
        if running:
            out("ahc: %s may still be running; nothing was removed (the unit files, the wrapper and the install "
                "record are kept). Stop them, then rerun `ahc uninstall --apply`." % ", ".join(running))
            return 1
    for name in UNITS:
        target = unit_dir(home) / ("%s.service" % name)
        out("%sremove %s" % (verb, target))
        if apply:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
    for argv in (["systemctl", "--user", "daemon-reload"],):
        out("%srun %s" % (verb, " ".join(argv)))
        if apply and run(argv)[0] != 0:
            failed += 1
    wrapper = home / ".local" / "bin" / "ahc"
    try:
        ours = WRAPPER_MARK in wrapper.read_text(encoding="utf-8", errors="replace")
    except OSError:
        ours = False
    if ours:
        out("%sremove the ahc wrapper %s" % (verb, wrapper))
        if apply:
            wrapper.unlink()
    record = read_record(paths)
    before = (record or {}).get("linger_before")
    if before is False:
        argv = ["loginctl", "disable-linger", _user()]
        out("%srun %s (lingering was off before ahc)" % (verb, " ".join(argv)))
        if apply and run(argv)[0] != 0:
            failed += 1
    elif before is True:
        out("leave lingering on (it was on before ahc)")
    else:
        out("leave lingering as it is (no record of its state before ahc)")
    if record is not None and failed:
        # PR 247 receipt F3: the record (lingering's state before ahc) is what a retry needs to finish the rollback
        out("keep the install record %s: %d step(s) failed; rerun `ahc uninstall --apply` to finish"
            % (_record_path(paths), failed))
    elif record is not None:
        out("%sremove the install record %s" % (verb, _record_path(paths)))
        if apply:
            fs.unlink(paths.root, _record_path(paths))
    out("kept for audit (delete only after a verified backup):")
    for label, path in kept_paths(paths):
        out("  %s: %s" % (label, path))
    return 1 if failed else 0


def _maybe_running(run, name) -> bool:
    """Whether a unit may still run: anything but a plain "inactive" or "failed" from is-active, including an
    is-active that cannot answer (fail closed)."""
    _rc, text = run(["systemctl", "--user", "is-active", "%s.service" % name])
    return (text or "").strip() not in ("inactive", "failed")


def unit_states(run=default_run, system=None) -> dict:
    """{unit: active|inactive|failed|...} for status; empty off Linux."""
    if (system or platform.system()) != "Linux":
        return {}
    states = {}
    for name in UNITS:
        rc, out = run(["systemctl", "--user", "is-active", "%s.service" % name])
        states[name] = (out or "").strip() or ("unknown" if rc != 0 else "active")
    return states


if __name__ == "__main__":
    sys.exit("use: python3 ahc_runner.py install|uninstall [--apply]")
