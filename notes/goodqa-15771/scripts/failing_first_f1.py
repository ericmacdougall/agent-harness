"""r2 F1 reproducer (goodqa#15771): the same host truth rendered as the real host answers the db2f6b11 script.

Host truth: the 1536G of test VM disks on `local`, plus
  (a) LXC container 120 with a 300G rootdir volume local:120/vm-120-disk-0.raw (pct, not in qm list), or
  (b) VM 103 with a detached disk `unused0: local:103/vm-103-disk-2.raw` (300G file; qm config prints no size).
Expected of a correct check: provisioned includes the 300G (1836G), or allocation_complete is false.
Usage: python3 -B failing_first_f1.py <dir holding ops_watch.py>
"""
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import ops_watch as ow  # noqa: E402

GIB = 1024 ** 3
QM = {
    100: "scsi0: local:100/vm-100-disk-0.qcow2,size=664G\nname: t2-dev\n",
    102: "scsi0: local:102/vm-102-disk-0.raw,discard=on,size=200G\nname: gq-prod-app\n",
    103: "scsi0: local:103/vm-103-disk-0.raw,discard=on,size=400G\nscsi1: local:103/vm-103-disk-1.raw,size=100G\nname: db\n",
    105: "scsi0: local:105/vm-105-disk-0.raw,size=16G\nname: a\n",
    106: "scsi0: local:106/vm-106-disk-0.raw,size=40G\nname: b\n",
    108: "scsi0: local:108/vm-108-disk-0.qcow2,size=60G\nname: c\n",
    109: "scsi0: local:109/vm-109-disk-0.raw,size=16G\nname: d\n",
    15662: "scsi0: local:15662/vm-15662-disk-0.qcow2,size=40G\nname: e\n",
}
PVESM = ("Name         Type     Status     Total (KiB)      Used (KiB) Available (KiB)        %\n"
         "local         dir     active       916398132       856463396        50596800   93.46%\n")


def old_probe(qm):
    out = "##PVESM\n" + PVESM + "##RC PVESM 0\n##QM\n##RC LIST 0\n"
    for vm, cfg in qm.items():
        out += f"##VM {vm}\n{cfg}##RC {vm} 0\n"
    return out + "##DU\n" + "".join(f"{g * 1048576}\t/var/lib/vz/images/{v}\n" for v, g in ((102, 15), (103, 28))) + "##END\n"


def run(text):
    cfg = ow.load_config(Path(tempfile.mkdtemp()), host="t", overrides={})
    cfg["proxmox_pools"] = [{"host": "<pve-host>", "storage": "local", "mount": "/var/lib/vz", "watch_vms": [102, 103]}]
    alerts = {a["key"]: a for a in ow.check_proxmox_pool(cfg, {}, lambda argv, timeout, **k: (0, text), 1794100000.0)}
    d = alerts["disk:volume:<pve-host>:/var/lib/vz"]["detail"]
    return d["allocation_complete"], d["provisioned_gib"], d["overcommit_ratio"], "disk:allocunknown:<pve-host>:/var/lib/vz" in alerts


def new_probe(extra_rows):
    """The same host as the new script reads it: pvesm list (bytes) and the image file names."""
    rows = [r for vm, cfg in QM.items() for r in
            [(vm, n, "images", int(sz)) for n, sz in re.findall(r"local:\d+/(\S+?),(?:\S*,)?size=(\d+)G", cfg)]]
    rows += extra_rows
    vols = "Volid Format Type Size VMID\n" + "".join(f"local:{vm}/{n} raw {t} {g * GIB} {vm}\n" for vm, n, t, g in rows)
    files = "".join(f"/var/lib/vz/images/{vm}/{n}\n" for vm, n, _, _ in rows)
    return ("##PVESM\n" + PVESM + "##RC PVESM 0\n##VOLS\n" + vols + "##RC VOLS 0\n##FILES\n" + files
            + "##RC FILES 0\n##DU\n" + "".join(f"{g * 1048576}\t/var/lib/vz/images/{v}\n" for v, g in ((102, 15), (103, 28)))
            + "##END\n")


NEW = "##VOLS" in ow.pool_script("local", "/var/lib/vz", [102])
print("script format:", "pvesm list + find (new)" if NEW else "qm list/config (db2f6b11)")
scenarios = {
    "container rootdir 300G (qm list does not show CT 120)":
        new_probe([(120, "vm-120-disk-0.raw", "rootdir", 300)]) if NEW else old_probe(QM),
    "unused0 detached 300G disk on VM 103":
        new_probe([(103, "vm-103-disk-2.raw", "images", 300)]) if NEW
        else old_probe({**QM, 103: QM[103] + "unused0: local:103/vm-103-disk-2.raw\n"}),
}
fails = 0
for name, text in scenarios.items():
    complete, prov, ratio, allocunknown = run(text)
    ok = (not complete and allocunknown) or (prov is not None and prov >= 1836)
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}: {name}: allocation_complete={complete} provisioned_gib={prov} "
          f"overcommit_ratio={ratio} allocunknown={allocunknown} (needs provisioned>=1836 or incomplete)")
print(f"{fails} of {len(scenarios)} scenarios under-report")
sys.exit(1 if fails else 0)
