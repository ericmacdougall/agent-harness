"""F2 rollback rehearsal (goodqa#15771): on the rehearsal home from rehearsal.py, disable the check the way the
rollback does (empty `proxmox_pools`), run once, then re-enable and run once. Shows what the ring records and what
happens to the stored samples. No ssh is made while disabled. Usage: python3 -B rollback_rehearsal.py <worktree> <home>"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "harness/hooks"))
import ops_watch as ow  # noqa: E402

home = Path(sys.argv[2])
cfg = ow.load_config(home, host="rehearsal", overrides={})
cfg["sinks"] = {"comment": {"mode": "none"}, "deadman": [], "comment_min_interval_s": 1800}
entry = {"host": "<login>@<pve-host>", "storage": "local", "mount": "/var/lib/vz", "watch_vms": [102, 103]}
seen = len(ow.read_ring(ow.ring_path(home)))
for label, pools in (("disabled (proxmox_pools = [])", []), ("re-enabled", [entry])):
    cfg["proxmox_pools"] = pools
    calls = []

    def counting(argv, timeout, **kw):
        calls.append(argv[0])
        return ow.run(argv, timeout, **kw)
    ow.run_once(cfg, home, runner=counting, checks={"proxmox_pool": ow.check_proxmox_pool})
    ring = ow.read_ring(ow.ring_path(home))
    new, seen = ring[seen:], len(ring)
    state = ow.load_state(home)
    rec = next(iter(state.get("proxmox_pools", {}).values()), {})
    print(json.dumps({"run": label, "ssh_calls": calls.count("ssh"),
                      "ring_events": [(e.get("event"), e.get("key")) for e in new],
                      "active": sorted(k for k in state.get("active", {}) if k.startswith("disk:")),
                      "stored_samples": len(rec.get("samples", []))}))
