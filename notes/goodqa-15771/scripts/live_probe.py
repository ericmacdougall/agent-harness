"""Read-only live probe for goodqa#15771: check_proxmox_pool with the real runner (one ssh call, fixed read-only
script) against <login>@<pve-host> storage local. Prints the parsed alerts (keys, severities, detail) only, never raw
remote rows. Usage: python3 -B live_probe.py <worktree>"""
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "harness/hooks"))
import ops_watch as ow  # noqa: E402

cfg = ow.load_config(Path(tempfile.mkdtemp()), host="probe", overrides={})
cfg["proxmox_pools"] = [{"host": "<login>@<pve-host>", "storage": "local", "mount": "/var/lib/vz", "watch_vms": [102, 103]}]
calls = []


def timed(argv, timeout, **kw):
    t = time.monotonic()
    rc, out = ow.run(argv, timeout, **kw)
    calls.append({"rc": rc, "seconds": round(time.monotonic() - t, 2), "bytes": len(out or ""),
                  "markers": [l for l in (out or "").splitlines() if l.startswith("##RC")]})
    return rc, out


alerts = ow.check_proxmox_pool(cfg, {}, timed, time.time())
print("head script:", "pvesm list + find" if "##VOLS" in ow.pool_script("local", "/var/lib/vz", [102]) else "old")
print("ssh calls:", json.dumps(calls))
for a in alerts:
    print(json.dumps({k: a[k] for k in ("key", "severity", "message", "detail") if k in a}, sort_keys=True))
