#!/usr/bin/env python3
"""AC-12 live-gate run kit (goodqa#16049 slice 1 (b), spec r9). NOT run by this slice: it runs on the Linux host main
names (t2-dev), before the coordinator runs live, and its result is recorded as a REALLY_TESTED entry there.

One real R3-shaped unit is started with the R3 template's properties: DynamicUser (system scope), --collect,
NoNewPrivileges, PrivateTmp, RemainAfterExit, RuntimeMaxSec (a probe bound of 300 s; the daemon uses 3600) and
ReadWritePaths naming one fresh 0700 directory, plus LoadCredential and LC_ALL=C. Its socket is created under the
daemon root's sock/ directory (default ~/.agent-harness/ahc/sock), as core's review.sock is in production. It is
checked leg by leg:
  L1  DynamicUser (system manager) or the sandbox's `systemd-run --user` deviation (R-c): the unit's uid is
      allocated by systemd and differs from core's.
  L2  LoadCredential: the unit reads a non-secret probe credential from $CREDENTIALS_DIRECTORY.
  L3  InvocationID read back through `systemctl [--user] show` and equal to the one the unit reports.
  L4  The peer uid core reads from its own socket (SO_PEERCRED) equals the unit's uid.
The remaining live-gate items are on the checklist this script prints (the R3 completion wrapper and the report
grant are PENDING_REAL_TEST PRT-r3-wrapper and PRT-r3-grant; the coordinator stays in shadow, W21 off).

Results that are the kit's or the path's, not the daemon's, are reported apart from the legs:
  exit 3  "path: ... not traversable by other uids": a directory above the socket denies search to a DynamicUser,
          found before any unit starts (with the production layout this is itself the PRT-peercred finding).
  exit 4  "kit: no connection within Ns": the unit never connected; ActiveState/Result are printed.

Usage:  python3 scripts/ahc_ac12_live_gate.py --dry-run            # print the plan and the checklist only
        python3 scripts/ahc_ac12_live_gate.py --scope system|user [--root DIR]  # run the probe unit (Linux)
Exit 0 only when every leg passes. No secret is used: the probe credential is a fixed public string.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))

PROBE_TEXT = "ahc-ac12 probe: public text, loaded through LoadCredential\n"
CHECKLIST = """AC-12 live-gate checklist (post the filled copy on goodqa#16049; REALLY_TESTED names this host and commit)
[ ] host named by main: ______ (t2-dev unless main names another)   commit: ______
[ ] L1 DynamicUser (system) or `systemd-run --user` (R-c, sandbox repo only): unit uid ____ != core uid ____
[ ] L2 LoadCredential: probe credential sha256 matched inside the unit
[ ] L3 InvocationID via `systemctl show`: ____ == the unit's $INVOCATION_ID
[ ] L4 peer uid on core's socket (SO_PEERCRED) == the unit's uid
[ ] PRT-r3-wrapper: the R3 completion wrapper (follow-up ticket) sends row, intent, InvocationID, report sha256 only
[ ] PRT-r3-grant: the report directory is granted to the unit's dynamic uid only (no world-writable path)
[ ] PRT-peercred / PRT-bootid / PRT-mig-v5: the Linux legs of the slice suites pass on this host
[ ] shadow only: AHC_SHADOW=1, shadow_repos = [agent-harness] (main's ASSUMPTION), AHC_W21_SEND unset (W21 off)
[ ] zero mutating GitHub calls in the run's log; no E2 dispatch; no daemon PASS used as a merge authorization
"""

CLIENT = r"""
import hashlib, json, os, socket, sys
cred = open(os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "probe"), "rb").read()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(json.dumps({"uid": os.getuid(), "invocation_id": os.environ.get("INVOCATION_ID", ""),
                      "cred_sha256": hashlib.sha256(cred).hexdigest()}).encode())
s.close()
"""


PROBE_MAX_SEC = 300
ACCEPT_SECONDS = 60


class KitTimeout(Exception):
    """The probe unit never connected: a kit or host finding, not a daemon peer-uid failure."""


def socket_path(root, tag):
    """The probe's socket under the daemon root's sock/ (core's own socket there is review.sock)."""
    return str(Path(root) / "sock" / ("ac12-%s.sock" % tag))


def untraversable(sock, below=None):
    """Directories from / down to the socket's directory that deny search (o+x) to a uid that is neither owner nor
    group, as a DynamicUser is. Empty means a dynamic uid can reach the socket's directory. `below` (tests only)
    limits the walk to directories under it."""
    parent = Path(sock).parent.resolve()
    chain = list(reversed(parent.parents)) + [parent]
    if below is not None:
        chain = [d for d in chain if Path(below).resolve() in d.parents]
    return [str(d) for d in chain if not os.stat(str(d)).st_mode & 0o001]


def accept_within(srv, seconds):
    srv.settimeout(seconds)
    try:
        return srv.accept()[0]
    except socket.timeout:
        raise KitTimeout("kit: no connection within %ss (the unit did not reach the socket)" % seconds) from None


def plan(scope, unit, sock, cred, out_dir, python):
    sr = ["systemd-run"] + (["--user"] if scope == "user" else [])
    props = ["--unit=" + unit, "--slice=ahc-review.slice", "--collect", "--quiet",
             "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=RemainAfterExit=yes",
             "--property=RuntimeMaxSec=%d" % PROBE_MAX_SEC, "--property=ReadWritePaths=" + out_dir,
             "--property=LoadCredential=probe:" + cred, "--setenv=LC_ALL=C"]
    if scope == "system":
        props.insert(4, "--property=DynamicUser=yes")
    return sr + props + ["--", python, "-c", CLIENT, sock]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0], allow_abbrev=False)
    ap.add_argument("--scope", choices=("system", "user"), default="system")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--work", default=str(Path.home() / ".agent-harness" / "ahc-ac12"))
    ap.add_argument("--root", default=str(Path.home() / ".agent-harness" / "ahc"), help="the daemon root")
    args = ap.parse_args(argv)
    tag = uuid.uuid4().hex[:12]
    unit = "ahc-review-ac12-%s.service" % tag
    work = Path(args.work) / time.strftime("%Y%m%dT%H%M%S")
    sock, cred, out_dir = socket_path(args.root, tag), str(work / "probe.cred"), str(work / "out")
    cmd = plan(args.scope, unit, sock, cred, out_dir, "/usr/bin/python3")
    if args.dry_run or not sys.platform.startswith("linux"):
        print("plan (not run%s):" % ("" if args.dry_run else ": not Linux"))
        print("  " + " ".join(c if c != CLIENT else "<client>" for c in cmd))
        print(CHECKLIST)
        return 0 if args.dry_run else 2
    import ahc_review  # noqa: PLC0415 - the daemon's own peer-uid reader
    Path(sock).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    blocked = untraversable(sock) if args.scope == "system" else []
    if blocked:
        print("path: %s not traversable by other uids: a DynamicUser unit cannot reach %s (kit/path finding, "
              "not a daemon fault; with the production layout this is the PRT-peercred finding)"
              % (", ".join(blocked), sock))
        return 3
    work.mkdir(parents=True, mode=0o711)
    os.mkdir(out_dir, 0o700)
    Path(cred).write_text(PROBE_TEXT)
    os.chmod(cred, 0o644)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock)
    os.chmod(sock, 0o666)                      # the probe unit's dynamic uid must connect; core checks its uid
    srv.listen(1)
    legs = {}
    ctl = ["systemctl"] + (["--user"] if args.scope == "user" else [])
    try:
        started = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if started.returncode != 0:
            print("systemd-run failed: %s" % started.stderr.strip()[:300])
            return 1
        try:
            conn = accept_within(srv, ACCEPT_SECONDS)
        except KitTimeout as error:
            state = subprocess.run(ctl + ["show", "-p", "ActiveState,Result", unit], capture_output=True, text=True,
                                   timeout=30).stdout.split()
            print("%s; unit %s" % (error, " ".join(state)))
            return 4
        peer = ahc_review.peer_uid(conn)
        msg = json.loads(ahc_review.read_final(conn).decode())
        conn.close()
        shown = subprocess.run(ctl + ["show", "-p", "InvocationID,ActiveState,Result", unit], capture_output=True,
                               text=True, timeout=30).stdout
        props = dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)
        legs["L1 allocated uid differs from core"] = msg["uid"] != os.getuid() if args.scope == "system" else True
        legs["L2 LoadCredential"] = msg["cred_sha256"] == hashlib.sha256(PROBE_TEXT.encode()).hexdigest()
        legs["L3 InvocationID via systemctl show"] = bool(props.get("InvocationID")) and \
            props.get("InvocationID") == msg["invocation_id"]
        legs["L4 peer uid on core's socket"] = peer == msg["uid"]
    finally:
        subprocess.run(ctl + ["stop", unit], capture_output=True, timeout=30)
        srv.close()
        try:
            os.unlink(sock)
        except FileNotFoundError:
            pass
    for leg, ok in legs.items():
        print("%s  %s" % ("PASS" if ok else "FAIL", leg))
    (work / "result.json").write_text(json.dumps({"unit": unit, "scope": args.scope, "legs": legs}, indent=1))
    print(CHECKLIST)
    return 0 if legs and all(legs.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
