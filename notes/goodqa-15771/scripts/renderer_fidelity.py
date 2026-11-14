"""F1 evidence (goodqa#15771): the test fixture renderer pvesm_list() reproduces the live `pvesm list local` output
byte for byte. Reads live output read-only over ssh, parses each row into (volid, format, content, size, vmid),
re-renders it and compares. Prints only counts and the comparison, never the rows.
Usage: python3 -B renderer_fidelity.py <worktree>"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1])))
sys.path.insert(0, str(Path(sys.argv[1]) / "harness/hooks"))
from tests.test_ops_watch_proxmox import pvesm_list  # noqa: E402

live = subprocess.run(["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes",
                       "-o", "ControlMaster=no", "-o", "ControlPath=none", "--", "<login>@<pve-host>",
                       "timeout 8 pvesm list local"], capture_output=True, text=True, timeout=30)
rows = []
for line in live.stdout.splitlines()[1:]:
    c = line.split()
    rows.append((c[0], c[1], c[2], None if c[3] == "-" else int(c[3]), int(c[4]) if len(c) == 5 else None))
rendered = pvesm_list(rows)
kinds = sorted({(r[2], r[1]) for r in rows})
print(f"live rc={live.returncode} rows={len(rows)} with_vmid={sum(1 for r in rows if r[4])} kinds={kinds}")
print(f"byte_identical={rendered == live.stdout} live_bytes={len(live.stdout)} rendered_bytes={len(rendered)}")
sys.exit(0 if rendered == live.stdout and live.returncode == 0 else 1)
