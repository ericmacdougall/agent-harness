"""ops_watch proxmox_pool check (goodqa#15771): thresholds, growth, overcommit, fail-closed UNKNOWN, read-only command.
Recorded fixture output only; stdlib only; no network."""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ops_watch as ow  # noqa: E402

GIB = 1024 ** 3
KEY = "disk:volume:t2-proxmox:/var/lib/vz"
GROWTH = "disk:growth:t2-proxmox:/var/lib/vz"
UNKNOWN = "disk:unknown:t2-proxmox:/var/lib/vz"
NOW = 1794100000.0


def gib_kib(g):
    return int(g * 1024 * 1024)


def pvesm(total_g=916, used_g=848, avail_g=56, status="active", name="local"):
    return ("Name         Type     Status           Total            Used       Available        %\n"
            f"{name:<12} dir     {status:<8} {gib_kib(total_g):>12} {gib_kib(used_g):>12} {gib_kib(avail_g):>12}"
            f"   {100.0 * used_g / total_g:.2f}%\n")


VOLS = {
    100: [("vm-100-disk-0.qcow2", 664)],
    102: [("vm-102-disk-0.raw", 200)],
    103: [("vm-103-disk-0.raw", 400), ("vm-103-disk-1.raw", 100)],
    105: [("vm-105-disk-0.raw", 16)],
    106: [("vm-106-disk-0.raw", 40)],
    108: [("vm-108-disk-0.qcow2", 60)],
    109: [("vm-109-disk-0.raw", 16)],
    15662: [("vm-15662-disk-0.qcow2", 40)],
}  # guest volumes on local, GiB: 1536 in all
# non-guest content on the same storage never counts as provisioned, even a backup that names a VM
OTHER = [("local:iso/noble-server-cloudimg-amd64.img", "iso", "iso", 625256960, None),
         ("local:snippets/dev-user.yaml", "snippet", "snippets", 635, None),
         ("local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst", "tzst", "vztmpl", 123731847, None),
         ("local:backup/vzdump-qemu-103-2026_11_01-00_00_00.vma.zst", "vma.zst", "backup", 999999999999, 103)]
DU = {100: 653, 102: 15, 103: 28, 105: 8, 106: 9, 108: 57, 109: 5, 15662: 13}


def pvesm_list(rows):
    """`pvesm list STORAGE` text exactly as libpve-storage-perl 9.1.10 prints it: $print_content in
    /usr/share/perl5/PVE/CLI/pvesm.pm (lines 197-241 on t2-proxmox, read 2026-11-13). rows are
    (volid, format, content, size, vmid); PVE::Storage::volume_list hands them over sorted by lowercase volid; rows
    with a VMID print first in that order, the rest after, sorted by format; an undefined size prints "-". A str
    size is passed through untouched (a deliberately garbled fixture). The renderer was checked byte for byte
    against the live `pvesm list local` output (see the PR packet)."""
    rows = sorted(rows, key=lambda r: r[0].lower())
    name_w = max([len(r[0]) for r in rows], default=0)
    size_w = len(str(max([r[3] for r in rows if isinstance(r[3], int)] + [0])))

    def line(r):
        size = "-" if r[3] is None else str(r[3])
        return f"{r[0]:<{name_w}} {r[1]:<7} {r[2]:<9} {size:>{size_w}}"
    out = f"{'Volid':<{name_w}} {'Format':<7} {'Type':<9} {'Size':>{size_w}} VMID\n"
    out += "".join(f"{line(r)} {r[4]}\n" for r in rows if r[4])
    return out + "".join(f"{line(r)}\n" for r in sorted((r for r in rows if not r[4]), key=lambda r: r[1]))


def guest_rows(vols=None, content="images"):
    """Rows for VM disks as Plugin.pm list_images reports them on a dir storage: volid STORAGE:<vmid>/<name>,
    format from the extension, size in bytes (GiB in the fixture), VMID the owner directory."""
    vols = VOLS if vols is None else vols
    return [(f"local:{vm}/{n}", n.rsplit(".", 1)[-1], content, int(g * GIB) if isinstance(g, (int, float)) else g, vm)
            for vm, disks in vols.items() for n, g in disks]


def vols_text(vols=None, rows="", extra=()):
    """The listing for `vols` plus the non-guest content and any `extra` rows, then raw `rows` text appended (for
    malformed lines that print_content never produces)."""
    return pvesm_list(guest_rows(vols) + OTHER + list(extra)) + rows


def files_text(vols=None, extra=()):
    vols = VOLS if vols is None else vols
    names = [f"/var/lib/vz/images/{vm}/{n}" for vm, disks in vols.items() for n, _ in disks] + list(extra)
    return "".join(n + "\n" for n in names)


def probe(pvesm_text=None, vols=None, du=None, end=True, extra="", vols_rc=0, files_rc=0, vols_out=None,
          files_out=None, du_rc=None):
    """The fixed script's output. vols/files default to the VOLS fixture; vols_rc/files_rc None drops that ##RC.
    du_rc maps a VM id to its du exit status (default 0; None drops that ##RC line)."""
    du = DU if du is None else du
    du_rc = du_rc or {}
    out = "##PVESM\n" + (pvesm() if pvesm_text is None else pvesm_text) + "##RC PVESM 0\n"
    out += "##VOLS\n" + (vols_text(vols) if vols_out is None else vols_out)
    out += "" if vols_rc is None else f"##RC VOLS {vols_rc}\n"
    out += "##FILES\n" + (files_text(vols) if files_out is None else files_out)
    out += "" if files_rc is None else f"##RC FILES {files_rc}\n"
    out += "##DU\n" + "".join(f"{gib_kib(g)}\t/var/lib/vz/images/{vm}\n"
                               + ("" if du_rc.get(vm, 0) is None else f"##RC DU {vm} {du_rc.get(vm, 0)}\n")
                               for vm, g in du.items())
    return out + extra + ("##END\n" if end else "")


class Runner:
    def __init__(self, result):
        self.result, self.calls = result, []

    def __call__(self, argv, timeout, stdin=None, env=None, cwd=None, **kw):
        self.calls.append((list(argv), timeout))
        self.kw = kw
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = ow.load_config(Path(self.tmp.name), host="testhost", overrides={})
        self.cfg["proxmox_pools"] = [{"host": "t2-proxmox", "storage": "local", "mount": "/var/lib/vz",
                                      "watch_vms": [102, 103]}]

    def run_check(self, result, state=None, now=NOW):
        state = {} if state is None else state
        runner = Runner(result)
        return {a["key"]: a for a in ow.check_proxmox_pool(self.cfg, state, runner, now)}, state, runner

    def pool(self, **kw):
        return self.run_check((0, probe(pvesm(**kw))))[0]


class ThresholdTests(Base):
    def test_current_pool_state_is_high_with_overcommit_and_vm_detail(self):
        a = self.pool()[KEY]
        self.assertEqual(a["severity"], "high")
        self.assertIn("92.6% used", a["message"])
        self.assertEqual(a["check"], "proxmox_pool")
        d = a["detail"]
        self.assertEqual(d["total_gib"], 916.0)
        self.assertEqual(d["provisioned_gib"], 1536.0)
        self.assertEqual(d["overcommit_ratio"], 1.68)
        self.assertEqual(d["vms"]["102"], {"allocated_gib": 200.0, "actual_gib": 15.0, "growth_gib_day": None})
        self.assertEqual(d["vms"]["103"]["allocated_gib"], 500.0)
        self.assertEqual(d["vms"]["103"]["actual_gib"], 28.0)
        self.assertNotIn("100", d["vms"])

    def test_each_threshold_and_the_floor(self):
        cases = [(84.9, 'none'), (85.0, "warning"), (91.9, "warning"), (92.0, "high"), (96.9, "high"),
                 (97.0, "critical")]
        for pct, sev in cases:
            with self.subTest(pct=pct):
                got = self.pool(total_g=1000, used_g=pct * 10, avail_g=1000 - pct * 10)
                if sev == "none":
                    self.assertNotIn(KEY, got)
                else:
                    self.assertEqual(got[KEY]["severity"], sev)

    def test_free_floor_is_critical_even_at_a_low_percentage(self):
        got = self.pool(total_g=30, used_g=11, avail_g=19)
        self.assertEqual(got[KEY]["severity"], "critical")
        self.assertNotIn(KEY, self.pool(total_g=100, used_g=70, avail_g=30))
        # acceptance review r2 F2: exactly 20 GiB free is not under the floor
        self.assertNotIn(KEY, self.pool(total_g=100, used_g=80, avail_g=20))

    def test_provisioned_counts_only_guest_volumes_not_iso_template_or_backup(self):
        self.assertEqual(self.pool()[KEY]["detail"]["provisioned_gib"], 1536.0)  # OTHER holds a 931G backup


class UnknownTests(Base):
    def assert_unknown(self, got, sev="warning"):
        self.assertIn(UNKNOWN, got)
        self.assertEqual(got[UNKNOWN]["severity"], sev)
        self.assertTrue(got[UNKNOWN]["message"].startswith("UNKNOWN"))
        self.assertNotIn(KEY, got)

    def test_unreachable_nonzero_exit_and_timeout_are_unknown_never_green(self):
        for result in ((255, ""), (1, probe()), subprocess.TimeoutExpired("ssh", 25), OSError("x")):
            with self.subTest(result=repr(result)):
                self.assert_unknown(self.run_check(result)[0])

    def test_unknown_turns_high_after_30_minutes_without_a_good_read(self):
        state = {}
        self.run_check((255, ""), state, NOW)
        self.assert_unknown(self.run_check((255, ""), state, NOW + 1801)[0], "high")

    def test_last_good_alerts_are_carried_forward_during_an_outage(self):
        state = {}
        self.run_check((0, probe()), state, NOW)
        got = self.run_check((255, ""), state, NOW + 600)[0]
        self.assertEqual(got[KEY]["severity"], "high")
        self.assertIn(UNKNOWN, got)

    def test_recovery_clears_unknown(self):
        state = {}
        self.run_check((255, ""), state, NOW)
        self.assertNotIn(UNKNOWN, self.run_check((0, probe()), state, NOW + 600)[0])

    def test_malformed_pvesm_output_fails_closed(self):
        bad = {
            "empty": "",
            "no header": "local dir active 1 1 1 1%\n",
            "short row": "Name Type Status Total Used Available %\nlocal dir active 1\n",
            "non numeric": "Name Type Status Total Used Available %\nlocal dir active x y z 1%\n",
            "negative": "Name Type Status Total Used Available %\nlocal dir active 100 -5 105 1%\n",
            "used above total": pvesm(total_g=100, used_g=120, avail_g=0),
            "zero total": "Name Type Status Total Used Available %\nlocal dir active 0 0 0 0%\n",
            "avail above total": pvesm(total_g=100, used_g=10, avail_g=900),
            "inactive": pvesm(status="inactive"),
            "storage absent": pvesm(name="other"),
            "nan": "Name Type Status Total Used Available %\nlocal dir active nan nan nan 1%\n",
        }
        for label, text in bad.items():
            with self.subTest(label):
                self.assert_unknown(self.run_check((0, probe(text)))[0])

    def test_truncated_probe_without_end_marker_is_unknown(self):
        self.assert_unknown(self.run_check((0, probe(end=False)))[0])

    def test_no_remote_text_secret_or_address_reaches_the_alert(self):
        secret = "sk-live-PROXMOXSECRET123456789 192.0.2.77 root@pve-secret-host"
        got = self.run_check((0, probe(pvesm(name="x-" + secret.split()[0]), extra=secret + "\n")))[0]
        self.assert_unknown(got)
        for text in (json.dumps(got), json.dumps(self.run_check((255, secret))[0])):
            self.assertNotIn("PROXMOXSECRET", text)
            self.assertNotIn("192.0.2.77", text)
            self.assertNotIn("pve-secret-host", text)
        ok = json.dumps(self.run_check((0, probe(extra=secret + "\n")))[0])
        self.assertNotIn("PROXMOXSECRET", ok)


class VmDetailTests(Base):
    def test_garbled_vm_lines_degrade_that_vm_not_the_pool_alert(self):
        vols = {**VOLS, 102: [("vm-102-disk-0.raw", "garbage")]}
        du = {k: v for k, v in DU.items() if k != 103}
        got = self.run_check((0, probe(vols=vols, du=du)))[0][KEY]
        self.assertEqual(got["severity"], "high")
        self.assertIsNone(got["detail"]["vms"]["102"]["allocated_gib"])
        self.assertIsNone(got["detail"]["vms"]["103"]["actual_gib"])
        self.assertIn("102", got["detail"]["unsized_vms"])

    def test_sizes_are_bytes(self):
        vols = {102: [("a.raw", str(2 * 1024 ** 4)), ("b.raw", str(512 * 1024 ** 2)), ("c.raw", str(1024 ** 2))]}
        d = self.run_check((0, probe(vols=vols, du={102: 1})))[0][KEY]["detail"]
        self.assertEqual(d["vms"]["102"]["allocated_gib"], round(2048 + 0.5 + 1 / 1024, 2))


class GrowthTests(Base):
    def sample(self, state, used_g, now, v103=28, total=916):
        self.run_check((0, probe(pvesm(total_g=total, used_g=used_g, avail_g=total - used_g),
                                 du={**DU, 103: v103})), state, now)

    def test_growth_over_threshold_alerts_and_fills_vm_growth(self):
        state = {}
        self.sample(state, 800, NOW - 24 * 3600, v103=10)
        got = self.run_check((0, probe(pvesm(used_g=848, avail_g=68))), state, NOW)[0]
        g = got[GROWTH]
        self.assertIn(g["severity"], ("warning", "high"))
        self.assertEqual(g["detail"]["growth_gib_day"], 48.0)
        self.assertEqual(got[KEY]["detail"]["vms"]["103"]["growth_gib_day"], 18.0)
        self.assertEqual(got[KEY]["detail"]["vms"]["102"]["growth_gib_day"], 0.0)

    def test_fast_growth_with_little_headroom_is_high(self):
        state = {}
        self.sample(state, 800, NOW - 24 * 3600)
        self.assertEqual(self.run_check((0, probe(pvesm(used_g=848, avail_g=56))), state, NOW)[0][GROWTH]["severity"], "high")

    def test_growth_boundary_is_strictly_more_than_10_gib_a_day(self):
        # acceptance review r2 F2: exactly 10 GiB/day is silent, just over alerts
        state = {}
        self.sample(state, 800, NOW - 24 * 3600)
        self.assertNotIn(GROWTH, self.run_check((0, probe(pvesm(used_g=810, avail_g=106))), state, NOW)[0])
        state = {}
        self.sample(state, 800, NOW - 24 * 3600)
        self.assertIn(GROWTH, self.run_check((0, probe(pvesm(used_g=811, avail_g=105))), state, NOW)[0])

    def test_slow_growth_is_silent(self):
        state = {}
        self.sample(state, 840, NOW - 24 * 3600)
        self.assertNotIn(GROWTH, self.run_check((0, probe(pvesm(used_g=848, avail_g=68))), state, NOW)[0])

    def test_too_fresh_baseline_gives_no_growth_alert(self):
        state = {}
        self.sample(state, 700, NOW - 3600)
        self.assertNotIn(GROWTH, self.run_check((0, probe()), state, NOW)[0])

    def test_shrink_and_counter_reset_give_no_growth_alert(self):
        state = {}
        self.sample(state, 900, NOW - 24 * 3600)
        got = self.run_check((0, probe()), state, NOW)[0]
        self.assertNotIn(GROWTH, got)
        self.assertEqual(got[KEY]["detail"]["vms"]["103"]["growth_gib_day"], 0.0)

    def test_samples_are_bounded_and_ignore_failed_reads(self):
        state = {}
        for i in range(400):
            self.sample(state, 800, NOW + i * 1900)
        self.run_check((255, ""), state, NOW + 999999)
        (rec,) = state["proxmox_pools"].values()
        self.assertLessEqual(len(rec["samples"]), 120)
        self.assertTrue(all(s[1] > 0 for s in rec["samples"]))

    def test_clock_going_backwards_does_not_divide_by_zero(self):
        state = {}
        self.sample(state, 800, NOW)
        self.run_check((0, probe()), state, NOW - 5)
        self.run_check((0, probe()), state, NOW)


class RedTeamRound1Tests(Base):
    """F1 partial read is visible, F3 window to 48 h, F4 unsized/cdrom, F6 mount normalised."""

    def test_partial_read_below_every_threshold_still_raises_unknown_for_watched_vms(self):
        text = "##PVESM\n" + pvesm(total_g=1000, used_g=500, avail_g=500) + "##RC PVESM 0\n##DU\n##END\n"
        got = self.run_check((0, text))[0]
        self.assertEqual(sorted(k for k in got if k.startswith("disk:vmunknown:")),
                         [f"disk:vmunknown:t2-proxmox:/var/lib/vz:{v}" for v in (102, 103)])
        self.assertTrue(all(a["message"].startswith("UNKNOWN") for k, a in got.items() if "vmunknown" in k))

    def test_a_watched_vm_with_no_volume_on_the_pool_is_unknown_even_with_other_vms_present(self):
        vols = {k: v for k, v in VOLS.items() if k != 103}
        got = self.run_check((0, probe(vols=vols)))[0]
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)
        self.assertNotIn("disk:vmunknown:t2-proxmox:/var/lib/vz:102", got)

    def test_complete_read_has_no_vmunknown(self):
        self.assertFalse([k for k in self.pool() if "vmunknown" in k])

    def test_growth_window_reaches_48_hours(self):
        state = {}
        GrowthTests.sample(self, state, 700, NOW - 30 * 3600)
        got = self.run_check((0, probe()), state, NOW)[0]
        self.assertIn(GROWTH, got)
        self.assertEqual(got[GROWTH]["detail"]["growth_gib_day"], 118.4)
        state = {}
        GrowthTests.sample(self, state, 700, NOW - 49 * 3600)
        self.assertNotIn(GROWTH, self.run_check((0, probe()), state, NOW)[0])

    def test_baseline_closest_to_a_day_is_preferred(self):
        samples = [[NOW - 40 * 3600, 1, {}], [NOW - 25 * 3600, 2, {}], [NOW - 7 * 3600, 3, {}]]
        self.assertEqual(ow.pool_baseline(samples, NOW)[1], 2)

    def test_unsized_volume_keeps_sized_siblings_and_iso_does_not_count(self):
        vols = {**VOLS, 103: VOLS[103] + [("subvol-103-disk-2.subvol", "0")]}  # dir-storage subvol: no size
        d = self.run_check((0, probe(vols=vols)))[0][KEY]["detail"]
        self.assertEqual(d["vms"]["103"]["allocated_gib"], 500.0)
        self.assertIn("103", d["unsized_vms"])

    def test_trailing_slash_mount_keeps_one_key_and_state_record(self):
        self.cfg["proxmox_pools"][0]["mount"] = "/var/lib/vz/"
        got, state, _ = self.run_check((0, probe()))
        self.assertIn(KEY, got)
        self.assertEqual(list(state["proxmox_pools"]), ["t2-proxmox:/var/lib/vz"])


REAL_PVESM = ("Name         Type     Status     Total (KiB)      Used (KiB) Available (KiB)        %\n"
              "local         dir     active       916398132       856463396        50596800   93.46%\n")


class VolumeListFormatTests(Base):
    """Plan review F3, carried to pvesm list: garbled or partial listing output is never a valid zero allocation."""
    ALLOC = "disk:allocunknown:t2-proxmox:/var/lib/vz"

    def got(self, **kw):
        return self.run_check((0, probe(PVESM_LOW, **kw)))[0]

    def unknown_vms(self, got):
        return sorted(k.rsplit(":", 1)[1] for k in got if "vmunknown" in k)

    def test_error_only_listing_is_unknown_below_thresholds(self):
        got = self.got(vols_out="storage 'local' does not exist\n", files_out="")
        self.assertIn(self.ALLOC, got)
        self.assertEqual(self.unknown_vms(got), ["102", "103"])

    def test_missing_or_changed_header_is_unknown(self):
        for out in (vols_text().split("\n", 1)[1], vols_text().replace("VMID", "Owner")):
            with self.subTest(out=out[:20]):
                self.assertIn(self.ALLOC, self.got(vols_out=out))

    def test_guest_row_that_cannot_be_tied_to_one_vm_is_unknown(self):
        rows = ("local:103/vm-103-disk-5.raw raw images 1073741824\n",  # no VMID column
                "local:103/vm-103-disk-5.raw raw images 1073741824 xyz\n",  # non-numeric VMID
                "local:104/vm-103-disk-5.raw raw images 1073741824 103\n",  # volid owner is not the VMID
                "other:103/vm-103-disk-5.raw raw images 1073741824 103\n",  # another storage
                "garbled\n")
        for row in rows:
            with self.subTest(row=row):
                got = self.got(vols_out=vols_text(rows=row))
                self.assertIn(self.ALLOC, got)
                self.assertEqual(self.unknown_vms(got), ["102", "103"])

    def test_non_numeric_or_zero_size_flags_that_vm_only(self):
        for size in ("garbage", "0", "-5", "1.5e3", "-", "~1073741824"):  # "-" and "~N": print_content forms
            with self.subTest(size=size):
                got = self.got(vols={**VOLS, 105: [("vm-105-disk-0.raw", size)]})
                self.assertIn(self.ALLOC, got)
                self.assertEqual(self.unknown_vms(got), [])

    def test_unwatched_vm_without_volumes_is_fine(self):
        got = self.got(vols={k: v for k, v in VOLS.items() if k != 109})
        self.assertNotIn(self.ALLOC, got)
        self.assertEqual(self.unknown_vms(got), [])


PVESM_LOW = pvesm(total_g=1000, used_g=500, avail_g=500)


class CompletionStatusTests(Base):
    """PR review F1: the script exits 0 and prints ##END even when a command failed or timed out, so each
    command's own status (##RC) decides whether its data is complete. Carried over from qm list/config to pvesm list
    and the file listing: a listing that failed or was cut leaves every VM subtotal unknown."""
    ALLOC = "disk:allocunknown:t2-proxmox:/var/lib/vz"

    def got(self, text):
        return self.run_check((0, text))[0]

    def cut(self, upto):
        """The listing as printed before a timeout: header and the rows before `upto`, no non-guest rows."""
        lines = pvesm_list(guest_rows()).splitlines(keepends=True)
        return "".join(lines[:upto + 1])  # header plus the first `upto` rows

    def test_listing_that_fails_after_a_valid_prefix_is_unknown_not_partial(self):
        got = self.got(probe(PVESM_LOW, vols_out=self.cut(2), vols_rc=124))  # 100 and 102 printed, 103 cut off
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:102", got)  # a printed prefix is not trusted either
        self.assertIn(self.ALLOC, got)

    def test_failure_after_one_sized_disk_does_not_pass_as_a_complete_subtotal(self):
        got = self.got(probe(vols_out=self.cut(3), vols_rc=124))  # 103's first 400G disk printed, its 100G cut off
        d = got[KEY]["detail"]
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)
        self.assertIsNone(d["vms"]["103"]["allocated_gib"])
        self.assertIsNone(d["overcommit_ratio"])
        self.assertIsNone(d["provisioned_gib"])
        self.assertFalse(d["allocation_complete"])
        self.assertEqual(got[KEY]["severity"], "high")  # usable pool capacity numbers are kept

    def test_missing_status_line_for_the_listing_is_incomplete(self):
        got = self.got(probe(vols_rc=None))
        self.assertIn(self.ALLOC, got)
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:102", got)

    def test_failed_listing_is_unknown_and_keeps_pool_capacity(self):
        got = self.got(probe(PVESM_LOW, vols_out="", du=DU, vols_rc=2))
        self.assertIn(self.ALLOC, got)
        self.assertEqual(sorted(k[-3:] for k in got if "vmunknown" in k), ["102", "103"])
        high = self.got(probe(vols_rc=124))
        self.assertEqual(high[KEY]["severity"], "high")
        self.assertIsNone(high[KEY]["detail"]["overcommit_ratio"])
        self.assertIn("unknown", high[KEY]["message"])

    def test_failed_or_missing_file_listing_status_is_incomplete(self):
        for rc in (1, 124, None):
            with self.subTest(rc=rc):
                got = self.got(probe(files_rc=rc))
                self.assertIn(self.ALLOC, got)
                self.assertFalse(got[KEY]["detail"]["allocation_complete"])
                self.assertIsNone(got[KEY]["detail"]["overcommit_ratio"])
                self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)  # a skipped file could be 103's

    def test_one_unsized_unwatched_volume_marks_allocation_unknown_only(self):
        got = self.got(probe(PVESM_LOW, vols={**VOLS, 105: [("vm-105-disk-0.raw", "0")]}))
        self.assertIn(self.ALLOC, got)
        self.assertNotIn("disk:vmunknown:t2-proxmox:/var/lib/vz:102", got)

    def test_complete_read_reports_overcommit_and_no_allocunknown(self):
        got = self.got(probe())
        self.assertNotIn(self.ALLOC, got)
        self.assertEqual(got[KEY]["detail"]["overcommit_ratio"], 1.68)
        self.assertTrue(got[KEY]["detail"]["allocation_complete"])

    def test_failed_pvesm_status_is_unusable_even_with_a_good_looking_table(self):
        text = probe().replace("##RC PVESM 0", "##RC PVESM 124")
        self.assertIn(UNKNOWN, self.got(text))

    def test_script_records_each_command_status(self):
        script = ow.pool_script("local", "/var/lib/vz", [102])
        for marker in ('echo "##RC PVESM $?"', 'echo "##RC VOLS $?"', 'echo "##RC FILES $?"'):
            self.assertIn(marker, script)


class AllVolumesTests(Base):
    """PR review r2 F1: qm list/qm config missed container volumes and detached unusedN disks, so allocation read
    complete with a low overcommit. pvesm list covers every volume on the storage; the file listing catches an image
    pvesm skips (it drops a file it cannot size with only a stderr warning and exit 0)."""
    ALLOC = "disk:allocunknown:t2-proxmox:/var/lib/vz"

    def detail(self, **kw):
        got = self.run_check((0, probe(**kw)))[0]
        return got, got[KEY]["detail"]

    # Container fixtures come from the plugin source on t2-proxmox (libpve-storage-perl 9.1.10, pve-container
    # 6.1.14), not from a live container (none exists and none is created): PVE::LXC allocates a dir-storage rootfs
    # as raw "vm-<ct>-disk-N.raw" when it has a size, or as a size-less "subvol-<ct>-disk-N.subvol" directory
    # (Plugin.pm alloc_image refuses a subvol with a size there); list_images sizes a directory as 0; list_volumes
    # marks a volume "rootdir" when its owner is an LXC guest, and drops it when the storage's enabled content
    # types (volume_list) leave rootdir out.
    def test_raw_container_volume_counts(self):
        ct = ("local:120/vm-120-disk-0.raw", "raw", "rootdir", 300 * GIB, 120)
        got, d = self.detail(vols_out=vols_text(extra=[ct]),
                             files_out=files_text(extra=["/var/lib/vz/images/120/vm-120-disk-0.raw"]))
        self.assertTrue(d["allocation_complete"])
        self.assertEqual(d["provisioned_gib"], 1836.0)
        self.assertEqual(d["overcommit_ratio"], 2.0)
        self.assertNotIn(self.ALLOC, got)

    def test_container_on_a_storage_without_rootdir_content_is_incomplete(self):
        # volume_list asks only for enabled content types: the CT row is missing, its file is not
        got, d = self.detail(files_out=files_text(extra=["/var/lib/vz/images/120/vm-120-disk-0.raw"]))
        self.assertFalse(d["allocation_complete"])
        self.assertIn("120", d["unsized_vms"])
        self.assertIn(self.ALLOC, got)

    def test_orphan_volume_without_a_guest_counts(self):
        orphan = ("local:130/vm-130-disk-0.raw", "raw", "images", 10 * GIB, 130)  # owner not in the vmlist
        got, d = self.detail(vols_out=vols_text(extra=[orphan]),
                             files_out=files_text(extra=["/var/lib/vz/images/130/vm-130-disk-0.raw"]))
        self.assertTrue(d["allocation_complete"])
        self.assertEqual(d["provisioned_gib"], 1546.0)

    def test_snapshot_chain_file_pvesm_skips_is_incomplete(self):
        # restricted layout: list_images skips snap-*.qcow2 (parse_name_dir dies on it), so a host using qcow2
        # snapshot chains on this storage reads allocation unknown rather than a low total
        got, d = self.detail(files_out=files_text(extra=["/var/lib/vz/images/103/snap-pre-vm-103-disk-0.qcow2"]))
        self.assertFalse(d["allocation_complete"])
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)

    def test_detached_unused_disk_counts_toward_its_vm(self):
        vols = {**VOLS, 103: VOLS[103] + [("vm-103-disk-2.raw", 300)]}  # unused0 in the config: listed all the same
        got, d = self.detail(vols=vols)
        self.assertTrue(d["allocation_complete"])
        self.assertEqual(d["provisioned_gib"], 1836.0)
        self.assertEqual(d["vms"]["103"]["allocated_gib"], 800.0)
        self.assertNotIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)

    def test_subvol_container_volume_without_size_is_incomplete(self):
        ct = ("local:121/subvol-121-disk-0.subvol", "subvol", "rootdir", 0, 121)
        got, d = self.detail(vols_out=vols_text(extra=[ct]),
                             files_out=files_text(extra=["/var/lib/vz/images/121/subvol-121-disk-0.subvol"]))
        self.assertFalse(d["allocation_complete"])
        self.assertIsNone(d["overcommit_ratio"])
        self.assertIn("121", d["unsized_vms"])
        self.assertIn(self.ALLOC, got)

    def test_image_file_pvesm_did_not_list_is_incomplete(self):
        got, d = self.detail(files_out=files_text(extra=["/var/lib/vz/images/103/vm-103-disk-2.qcow2"]))
        self.assertFalse(d["allocation_complete"])
        self.assertIsNone(d["provisioned_gib"])
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)
        self.assertEqual(d["vms"]["103"]["allocated_gib"], 500.0)  # the sized siblings stay visible
        self.assertIn(self.ALLOC, got)

    def test_unusable_file_listing_line_is_incomplete(self):
        for line in ("/var/lib/vz/images/abc/x.raw", "/elsewhere/images/103/x.raw", "/var/lib/vz/images/103/a b.raw",
                     "find: '/var/lib/vz/images/7': Permission denied"):
            with self.subTest(line=line):
                got, d = self.detail(files_out=files_text(extra=[line]))
                self.assertFalse(d["allocation_complete"])
                self.assertIn(self.ALLOC, got)
                self.assertIsNone(d["vms"]["102"]["allocated_gib"])

    def test_linked_clone_volid_is_tied_to_its_owner(self):
        clone = ("local:100/base-100-disk-0.raw/104/vm-104-disk-0.qcow2", "qcow2", "images", 10 * GIB, 104)
        got, d = self.detail(vols_out=vols_text(extra=[clone]),
                             files_out=files_text(extra=["/var/lib/vz/images/104/vm-104-disk-0.qcow2"]))
        self.assertTrue(d["allocation_complete"])
        self.assertEqual(d["provisioned_gib"], 1546.0)

    def test_truncated_listing_with_status_zero_cannot_hide_a_volume(self):
        # pvesm printed only part of its rows yet exited 0: the files it did not list still flag allocation
        got, d = self.detail(vols_out=pvesm_list(guest_rows({102: VOLS[102]})))
        self.assertFalse(d["allocation_complete"])
        self.assertIn(self.ALLOC, got)
        self.assertIn("disk:vmunknown:t2-proxmox:/var/lib/vz:103", got)


class DuStatusTests(Base):
    """PR review r3 F1: du can print a plausible subtotal and still fail (I/O or traversal error, timeout), so each
    watched directory's du carries its own ##RC DU line and only a status-0 subtotal is trusted. A failed one is
    unknown usage, raises disk:vmunknown and never enters the stored growth sample; the pool sample, read by
    pvesm status with its own status, is still kept."""
    VMUNK = "disk:vmunknown:t2-proxmox:/var/lib/vz:"

    def check(self, **kw):
        got, state, _ = self.run_check((0, probe(PVESM_LOW, **kw)))
        (rec,) = state["proxmox_pools"].values()
        return got, rec["samples"][-1]

    def assert_103_unknown(self, got, sample):
        self.assertIn(self.VMUNK + "103", got)
        self.assertNotIn(self.VMUNK + "102", got)
        self.assertNotIn("103", sample[2])  # no growth sample from a failed read
        self.assertEqual(sample[2].get("102"), 15 * GIB)  # the independently valid read is kept
        self.assertEqual(sample[1], 500 * GIB)  # pool usage sample kept (pvesm status had status 0)

    def detail(self, **kw):
        got = self.run_check((0, probe(**kw)))[0]
        return got[KEY]["detail"]["vms"]

    def test_du_that_fails_but_prints_a_plausible_subtotal_is_unknown(self):
        got, sample = self.check(du_rc={103: 1})
        self.assert_103_unknown(got, sample)
        vms = self.detail(du_rc={103: 1})
        self.assertIsNone(vms["103"]["actual_gib"])
        self.assertEqual(vms["102"]["actual_gib"], 15.0)

    def test_du_with_missing_status_is_unknown(self):
        got, sample = self.check(du_rc={103: None})
        self.assert_103_unknown(got, sample)

    def test_du_that_times_out_after_a_valid_prefix_is_unknown(self):
        got, sample = self.check(du={102: 15, 103: 3}, du_rc={103: 124})  # 102 done; 103 cut with a low partial
        self.assert_103_unknown(got, sample)
        self.assertIsNone(self.detail(du={102: 15, 103: 3}, du_rc={103: 124})["103"]["actual_gib"])

    def test_failed_du_does_not_feed_vm_growth(self):
        state = {}
        GrowthTests.sample(self, state, 800, NOW - 24 * 3600, v103=10)
        got = self.run_check((0, probe(pvesm(used_g=848, avail_g=68), du_rc={103: 1})), state, NOW)[0]
        self.assertIsNone(got[KEY]["detail"]["vms"]["103"]["growth_gib_day"])
        self.assertEqual(got[KEY]["detail"]["vms"]["102"]["growth_gib_day"], 0.0)

    def test_a_status_without_its_subtotal_or_a_duplicate_subtotal_is_unknown(self):
        got = self.run_check((0, probe(PVESM_LOW, du={102: 15}, extra="##RC DU 103 0\n")))[0]
        self.assertIn(self.VMUNK + "103", got)
        dup = probe(PVESM_LOW).replace("##RC DU 103 0\n", f"{gib_kib(1)}\t/var/lib/vz/images/103\n##RC DU 103 0\n")
        self.assertIn(self.VMUNK + "103", self.run_check((0, dup))[0])

    def test_every_remote_command_reports_its_own_status(self):
        script = ow.pool_script("local", "/var/lib/vz", [102, 103])
        cmds = [c.strip() for c in script.split(";") if c.strip()]
        timed = [i for i, c in enumerate(cmds) if c.startswith("timeout ")]
        self.assertEqual(len(timed), 5)  # pvesm status, pvesm list, find, du 102, du 103
        for i in timed:
            self.assertRegex(cmds[i + 1], r'^echo "##RC [A-Z]+( \d+)? \$\?"$', cmds[i])
        self.assertTrue(all(c.startswith(("timeout ", "echo ")) for c in cmds))


class BoundedRunTests(unittest.TestCase):
    """Plan review 1b F3: subprocess.run(capture_output=True) buffered everything before the 1 MiB check, so a
    runaway producer could grow this process without bound. The default runner now reads both streams
    incrementally under a byte cap; on overflow it kills and reaps the child and the pool reads UNKNOWN."""
    CAP = 1 << 20

    def child(self, stream, size):
        """A child that records its pid, floods `stream` with `size` bytes, then sleeps for 30 s."""
        pidfile = Path(self.tmp.name) / f"{stream}.pid"
        code = (f"import os, sys, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); "
                f"sys.{stream}.write('x' * {size}); sys.{stream}.flush(); time.sleep(30)")
        return [sys.executable, "-c", code], pidfile

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def assert_gone(self, pidfile):
        pid = pidfile.read_text().strip()
        state = subprocess.run(["ps", "-o", "stat=", "-p", pid], capture_output=True, text=True).stdout.strip()
        self.assertEqual(state, "", f"child {pid} still present (state {state!r}): not killed or not reaped")

    def test_stdout_overflow_kills_reaps_and_reports_overflow(self):
        argv, pidfile = self.child("stdout", 3 * self.CAP)
        start = time.monotonic()
        self.assertEqual(ow.run(argv, 20, max_bytes=self.CAP), (ow.RUN_OVERFLOW_RC, ""))
        self.assertLess(time.monotonic() - start, 10)  # did not wait out the 30 s sleep
        self.assert_gone(pidfile)

    def test_stderr_overflow_is_capped_too(self):
        argv, pidfile = self.child("stderr", 3 * self.CAP)
        self.assertEqual(ow.run(argv, 20, max_bytes=self.CAP), (ow.RUN_OVERFLOW_RC, ""))
        self.assert_gone(pidfile)

    def test_output_under_the_cap_is_returned_and_stderr_discarded(self):
        code = "import sys; d = sys.stdin.read(); sys.stderr.write('noise'); print(d.upper()); sys.exit(3)"
        self.assertEqual(ow.run([sys.executable, "-c", code], 20, stdin="abc", max_bytes=self.CAP), (3, "ABC\n"))
        big = ow.run([sys.executable, "-c", f"print('y' * {self.CAP - 100})"], 20, max_bytes=self.CAP)
        self.assertEqual((big[0], len(big[1])), (0, self.CAP - 99))

    def test_timeout_still_raises_and_reaps(self):
        argv, pidfile = self.child("stdout", 10)
        with self.assertRaises(subprocess.TimeoutExpired):
            ow.run(argv, 1, max_bytes=self.CAP)
        self.assert_gone(pidfile)

    def test_pool_probe_is_capped_at_1_mib_and_overflow_is_unknown(self):
        cfg = ow.load_config(Path(self.tmp.name), host="testhost", overrides={})
        cfg["proxmox_pools"] = [{"host": "t2-proxmox", "storage": "local", "watch_vms": [102]}]
        runner = Runner((ow.RUN_OVERFLOW_RC, ""))
        got = {a["key"]: a for a in ow.check_proxmox_pool(cfg, {}, runner, NOW)}
        self.assertEqual(runner.kw.get("max_bytes"), 1048576)
        self.assertIn(UNKNOWN, got)
        self.assertIn("output over the size limit", got[UNKNOWN]["message"])


class FakeKey:
    def __init__(self, fileobj, data, fd):
        self.fileobj, self.data, self.fd = fileobj, data, fd


class FakeSelector:
    """A scripted selector: each select() returns the next batch of (stream, chunk) events, in that order, and
    stages the chunks for the fake read. No real fd is polled and no process is signalled."""

    def __init__(self, batches):
        self.batches, self.keys, self.staged, self.reads = [list(b) for b in batches], {}, {}, []

    def register(self, fileobj, events, data):
        self.keys[data] = FakeKey(fileobj, data, 9000 + len(self.keys))

    def unregister(self, fileobj):
        self.keys = {d: k for d, k in self.keys.items() if k.fileobj is not fileobj}

    def get_map(self):
        return self.keys if self.batches else {}

    def select(self, timeout=None):
        batch = self.batches.pop(0)
        for name, chunk in batch:
            self.staged.setdefault(self.keys[name].fd, []).append(chunk)
        return [(self.keys[name], 1) for name, _ in batch]

    def read(self, fd, n):
        self.reads.append(fd)
        return self.staged[fd].pop(0)

    def close(self):
        pass


class OverflowOrderTests(unittest.TestCase):
    """PR review r5 F1: the overflow flag was reassigned on every chunk, so in one select batch a small chunk on
    the other stream reset an overflow seen just before it. Overflow must be irreversible and stop the batch at
    once, in either order. Deterministic: a scripted selector and read, no real streams, no signals."""
    CAP = 1000
    EOF = [("out", b""), ("err", b"")]

    def read_capped(self, batches):
        sel = FakeSelector(batches)
        sel.register(object(), 1, "out")
        sel.register(object(), 1, "err")
        out, overflow = ow._read_capped(sel, None, time.monotonic() + 30, self.CAP, ["x"], 30, read=sel.read)
        return out, overflow, sel

    def test_stdout_overflow_then_small_stderr_in_one_batch_stays_overflow(self):
        _, overflow, sel = self.read_capped([[("out", b"x" * (self.CAP + 1)), ("err", b"e")], self.EOF])
        self.assertTrue(overflow)
        self.assertEqual(len(sel.reads), 1)  # stopped at once: the stderr chunk was never read

    def test_stderr_overflow_then_small_stdout_in_one_batch_stays_overflow(self):
        _, overflow, sel = self.read_capped([[("err", b"e" * (self.CAP + 1)), ("out", b"o")], self.EOF])
        self.assertTrue(overflow)
        self.assertEqual(len(sel.reads), 1)

    def test_overflow_across_batches_and_exact_cap_is_not_overflow(self):
        _, overflow, _ = self.read_capped([[("out", b"x" * 600)], [("err", b"e" * 10), ("out", b"x" * 401)], self.EOF])
        self.assertTrue(overflow)
        out, overflow, _ = self.read_capped([[("out", b"x" * self.CAP), ("err", b"e" * self.CAP)], self.EOF])
        self.assertFalse(overflow)
        self.assertEqual(len(out), self.CAP)

    def run_with(self, batches):
        """run() end to end with the scripted selector in place of the real one; the Popen object is recorded so
        reaping is checked from its returncode."""
        sel, procs = FakeSelector(batches), []
        real_read, real_popen = os.read, subprocess.Popen

        def popen(*a, **kw):
            procs.append(real_popen(*a, **kw))
            return procs[-1]
        argv = [sys.executable, "-c", "import time; time.sleep(5)"]
        with mock.patch("selectors.DefaultSelector", lambda: sel), mock.patch("subprocess.Popen", popen), \
                mock.patch("os.read", lambda fd, n: sel.read(fd, n) if fd in sel.staged else real_read(fd, n)):
            got = ow.run(argv, 30, max_bytes=self.CAP)
        return got, procs[0]

    def test_run_returns_overflow_with_empty_output_in_either_order(self):
        for first, second in (("out", "err"), ("err", "out")):
            with self.subTest(first=first):
                start = time.monotonic()
                got, proc = self.run_with([[(first, b"z" * (self.CAP + 1)), (second, b"s")], self.EOF])
                self.assertEqual(got, (ow.RUN_OVERFLOW_RC, ""))
                self.assertIsNotNone(proc.returncode)  # waited for: reaped, not left as a zombie
                self.assertLess(time.monotonic() - start, 4)  # stopped, not waited out


class RealFormatTests(Base):
    """Recorded from the live t2-proxmox pool on 2026-11-13: the header carries (KiB) units."""

    def test_real_pvesm_header_with_kib_units_parses(self):
        got = self.run_check((0, probe(REAL_PVESM)))[0]
        self.assertNotIn(UNKNOWN, got)
        self.assertEqual(got[KEY]["severity"], "high")
        self.assertIn("93.5% used", got[KEY]["message"])
        self.assertEqual(got[KEY]["detail"]["free_bytes"], 50596800 * 1024)  # absolute units, not just percentages
        self.assertEqual(got[KEY]["detail"]["total_gib"], round(916398132 / 1048576, 2))

    def test_login_user_is_used_for_ssh_but_never_shown_in_alerts(self):
        self.cfg["proxmox_pools"][0]["host"] = "root@t2-proxmox"
        got, _, runner = self.run_check((0, probe(REAL_PVESM)))
        self.assertIn("root@t2-proxmox", runner.calls[0][0])
        self.assertIn(KEY, got)
        self.assertNotIn("root", json.dumps(got))

    def test_both_header_styles_parse_to_the_same_numbers(self):
        a = ow.parse_pool_status(REAL_PVESM, "local")
        b = ow.parse_pool_status(pvesm(total_g=916, used_g=848, avail_g=56), "local")
        self.assertEqual(a, (916398132 * 1024, 856463396 * 1024, 50596800 * 1024))
        self.assertIsNotNone(b)


class CommandAndConfigTests(Base):
    READ_WORDS = {"echo", "timeout", "pvesm", "status", "--storage", "list", "find", "-mindepth", "-maxdepth", "du",
                  "-sk", "local"}

    def test_the_remote_script_is_one_fixed_read_only_call(self):
        runner = self.run_check((0, probe()))[2]
        (argv, timeout), = runner.calls
        self.assertEqual(argv[:6], ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"])
        for opt in ("StrictHostKeyChecking=yes", "ControlMaster=no", "ControlPath=none"):
            self.assertIn(opt, argv)
        self.assertEqual(argv[-3:-1], ["--", "t2-proxmox"])
        self.assertLessEqual(timeout, 30)
        script = argv[-1]
        scrubbed = re.sub(r"'##[A-Z ]+'", "", script)
        scrubbed = re.sub(r'"##RC [A-Z]+( \d+)? \$\?"', "", scrubbed)  # echoed status markers and their $?
        for verb in ("fstrim", "resize", "destroy", "set", "create", "start", "stop", "shutdown", "migrate", "rm ",
                     "mv ", "delete", "move", "restore", "unlock", "template", "snapshot", "rollback", "reboot", "qm",
                     "-exec", "-delete", "-fprint", "$", ">", "<", "`", "&", "|", "sudo", "tee", "*"):
            self.assertNotIn(verb, scrubbed, verb)
        self.assertIn("timeout 8 pvesm status --storage local", script)
        self.assertIn("timeout 8 pvesm list local;", script)
        self.assertIn("timeout 3 find /var/lib/vz/images -mindepth 2 -maxdepth 2;", script)
        self.assertIn('timeout 5 du -sk /var/lib/vz/images/102; echo "##RC DU 102 $?"; '
                      'timeout 5 du -sk /var/lib/vz/images/103; echo "##RC DU 103 $?";', script)
        self.assertNotIn("images/*", script)  # unwatched VM directories are never traversed by du
        for cmd in script.split(";"):
            words = cmd.split()
            if not words:
                continue
            self.assertIn(words[0], {"echo", "timeout"}, cmd)
            if words[0] == "timeout":
                self.assertTrue(words[1].isdigit(), cmd)
                rest = [w for w in words[2:] if not w.startswith("/var/lib/vz/images")]
                self.assertTrue(set(rest) <= self.READ_WORDS | {"2"}, cmd)

    def test_unsafe_config_is_refused_before_ssh(self):
        bad = [{"host": "-oProxyCommand=x"}, {"host": "t2-proxmox; reboot"}, {"host": ""},
               {"host": "t2-proxmox", "storage": "local;rm"}, {"host": "t2-proxmox", "mount": "/var/lib/vz/../.."},
               {"host": "t2-proxmox", "mount": "relative"}, {"host": "t2-proxmox", "watch_vms": ["102; reboot"]},
               {"host": "t2-proxmox", "watch_vms": [True]}, {"host": "t2-proxmox", "watch_vms": "102"},
               {"host": "t2-proxmox", "mount": "/var/lib/vz'x"}]
        for entry in bad:
            with self.subTest(entry=entry):
                self.cfg["proxmox_pools"] = [entry]
                got, _, runner = self.run_check((0, probe()))
                self.assertEqual(runner.calls, [])
                self.assertEqual([a["severity"] for a in got.values()], ["warning"])
                self.assertTrue(list(got)[0].startswith("disk:config:"))

    def test_jump_ssh_config_and_pinned_known_hosts_build_a_strict_command(self):
        # goodqa#15771: the Mac reaches t2-proxmox only through t2-dev, with no edit to ~/.ssh/config (main's ruling).
        self.cfg["proxmox_pools"] = [{"host": "t2-proxmox", "storage": "local", "mount": "/var/lib/vz",
                                      "watch_vms": [102, 103], "jump": "t2-dev",
                                      "ssh_config": "/Users/x/.ssh/config_fleetops",
                                      "known_hosts": "/Users/x/work/t2-proxmox.known_hosts"}]
        got, _, runner = self.run_check((0, probe()))
        (argv, _), = runner.calls
        self.assertEqual(argv[:6], ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"])
        for opt in ("StrictHostKeyChecking=yes", "ControlMaster=no", "ControlPath=none"):
            self.assertIn(opt, argv[:argv.index("--")])
        sep = argv.index("--")
        self.assertEqual(argv[sep - 8:sep], ["-F", "/Users/x/.ssh/config_fleetops", "-J", "t2-dev",
                                             "-o", "UserKnownHostsFile=/Users/x/work/t2-proxmox.known_hosts",
                                             "-o", "StrictHostKeyChecking=yes"])
        self.assertEqual(argv[sep:sep + 2], ["--", "t2-proxmox"])
        # AC-1 key and NEG-4: the alias names the alert, never an address
        self.assertEqual(got["disk:volume:t2-proxmox:/var/lib/vz"]["severity"], "high")

    def test_unsafe_jump_or_paths_are_refused_before_ssh(self):
        base = {"host": "t2-proxmox"}
        bad = [{"jump": "-oProxyCommand=x"}, {"jump": "t2-dev,evil"}, {"jump": "t2 dev"},
               {"ssh_config": "relative/config"}, {"ssh_config": "/a/../etc/passwd"}, {"ssh_config": "/a b"},
               {"known_hosts": "-o"}, {"known_hosts": "/a/../../k"}, {"known_hosts": "/k;reboot"}]
        for extra in bad:
            with self.subTest(extra=extra):
                self.cfg["proxmox_pools"] = [dict(base, **extra)]
                got, _, runner = self.run_check((0, probe()))
                self.assertEqual(runner.calls, [])
                self.assertTrue(list(got)[0].startswith("disk:config:"))

    def test_real_pvesm_header_with_kib_units_parses(self):
        # recorded from t2-proxmox on 2026-11-12 (pve 8): the header names the unit in each size column
        real = ("Name         Type     Status     Total (KiB)      Used (KiB) Available (KiB)        %\n"
                "local         dir     active       916398132       848361792        58698404   92.58%\n")
        self.assertEqual(ow.parse_pool_status(real, "local"),
                         (916398132 * 1024, 848361792 * 1024, 58698404 * 1024))
        got = self.run_check((0, probe(real)))[0]
        self.assertEqual(got["disk:volume:t2-proxmox:/var/lib/vz"]["severity"], "high")
        for header in ("Name Type Status Total (MiB) Used (MiB) Available (MiB) %",
                       "Name Type Status Total (KiB) Used Available (KiB) %"):
            with self.subTest(header=header):
                self.assertIsNone(ow.parse_pool_status(header + "\n" + real.splitlines()[1], "local"))

    def test_disabled_by_default_and_registered(self):
        self.assertEqual(ow.load_config(Path(self.tmp.name), host="h", overrides={})["proxmox_pools"], [])
        self.assertIs(ow.DEFAULT_CHECKS["proxmox_pool"], ow.check_proxmox_pool)
        self.cfg["proxmox_pools"] = []
        self.assertEqual(ow.check_proxmox_pool(self.cfg, {}, Runner((0, "")), NOW), [])


class RedTeamRound2Tests(Base):
    """goodqa#15771 adversarial spec review: any exception in probe or parse is UNKNOWN, never a generic check error."""

    def test_undecodable_output_is_unknown_and_escalates(self):
        boom = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        got, state, _ = self.run_check(boom)
        self.assertEqual(got["disk:unknown:t2-proxmox:/var/lib/vz"]["severity"], "warning")
        self.assertIn("probe or parse error", got["disk:unknown:t2-proxmox:/var/lib/vz"]["message"])
        got = self.run_check(boom, state=state, now=NOW + 1801)[0]
        self.assertEqual(got["disk:unknown:t2-proxmox:/var/lib/vz"]["severity"], "high")

    def test_corrupt_saved_samples_give_unknown_then_recover(self):
        state = {"proxmox_pools": {"t2-proxmox:/var/lib/vz": {"first_try": NOW - 60, "samples": [["x"], None]}}}
        got = self.run_check((0, probe()), state=state)[0]
        self.assertIn("disk:unknown:t2-proxmox:/var/lib/vz", got)
        got = self.run_check((0, probe()), state=state, now=NOW + 60)[0]
        self.assertEqual(got["disk:volume:t2-proxmox:/var/lib/vz"]["severity"], "high")
        self.assertNotIn("disk:unknown:t2-proxmox:/var/lib/vz", got)

    def test_sample_with_good_time_but_bad_values_is_reset_not_stuck(self):
        # delta review d2: a row like [t, "x", {}] must not keep the pool UNKNOWN until it ages out (48 h)
        state = {"proxmox_pools": {"t2-proxmox:/var/lib/vz": {"first_try": NOW - 60,
                                                              "samples": [[NOW - 86400, "x", {}]]}}}
        got = self.run_check((0, probe()), state=state)[0]
        self.assertIn("disk:unknown:t2-proxmox:/var/lib/vz", got)
        got = self.run_check((0, probe()), state=state, now=NOW + 60)[0]
        self.assertNotIn("disk:unknown:t2-proxmox:/var/lib/vz", got)
        self.assertEqual(got["disk:volume:t2-proxmox:/var/lib/vz"]["severity"], "high")

    def test_corrupt_saved_record_restarts(self):
        state = {"proxmox_pools": {"t2-proxmox:/var/lib/vz": "junk"}}
        got = self.run_check((0, probe()), state=state)[0]
        self.assertEqual(got["disk:volume:t2-proxmox:/var/lib/vz"]["severity"], "high")


class RunOnceTests(Base):
    def test_ring_holds_the_high_alert_through_run_once(self):
        home = Path(self.tmp.name)
        runner = Runner((0, probe()))
        rc = ow.run_once(self.cfg, home, runner=runner, checks={"proxmox_pool": ow.check_proxmox_pool}, now=NOW)
        self.assertEqual(rc, 0)
        mine = [e for e in ow.read_ring(ow.ring_path(home)) if e.get("key") == KEY]
        self.assertEqual(mine[-1]["event"], "raise")
        self.assertEqual(mine[-1]["severity"], "high")
        rc = ow.run_once(self.cfg, home, runner=Runner((255, "")), checks={"proxmox_pool": ow.check_proxmox_pool},
                         now=NOW + 600)
        keys = {(e.get("key"), e.get("event")) for e in ow.read_ring(ow.ring_path(home))}
        self.assertIn((UNKNOWN, "raise"), keys)
        self.assertNotIn((KEY, "clear"), keys)


if __name__ == "__main__":
    unittest.main()
