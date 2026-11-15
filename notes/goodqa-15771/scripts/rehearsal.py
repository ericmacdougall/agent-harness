"""F2 rehearsal (goodqa#15771): one pool, the actual runner (ops_watch.run, real ssh, read-only) on the Mac against
<login>@<pve-host> storage local, through run_once with a throwaway home (ring and state stay under <home>).
Run 1 good, run 2 deliberately failed (storage name "nosuchpool" in a throwaway config copy), run 3 good again.
Sinks are forced off (no comment, no deadman). Prints durations, the pool ring events and stored samples only.
Usage: python3 -B rehearsal.py <worktree> <fresh home dir>"""
import copy
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "harness/hooks"))
import ops_watch as ow  # noqa: E402

home = Path(sys.argv[2])
home.mkdir(parents=True, exist_ok=False)
cfg = ow.load_config(home, host="rehearsal", overrides={})
cfg["sinks"] = {"comment": {"mode": "none"}, "deadman": [], "comment_min_interval_s": 1800}
cfg["proxmox_pools"] = [{"host": "<login>@<pve-host>", "storage": "local", "mount": "/var/lib/vz", "watch_vms": [102, 103]}]
bad = copy.deepcopy(cfg)
bad["proxmox_pools"][0]["storage"] = "nosuchpool"
seen = 0
for label, c in (("run1 good", cfg), ("run2 bad storage", bad), ("run3 good", cfg)):
    t = time.monotonic()
    rc = ow.run_once(c, home, checks={"proxmox_pool": ow.check_proxmox_pool})
    took = round(time.monotonic() - t, 2)
    ring = [e for e in ow.read_ring(ow.ring_path(home)) if str(e.get("key", "")).startswith("disk:")]
    new, seen = ring[seen:], len(ring)
    state = ow.load_state(home)
    rec = next(iter(state.get("proxmox_pools", {}).values()), {})
    samples = rec.get("samples", [])
    active = sorted(k for k in state.get("active", {}) if k.startswith("disk:"))
    print(json.dumps({"run": label, "rc": rc, "seconds": took,
                      "ring_events": [(e.get("event"), e.get("key"), e.get("severity")) for e in new],
                      "active": active, "samples": len(samples),
                      "last_sample_vms": sorted(samples[-1][2]) if samples else None}))
    time.sleep(2)
