"""ops_watch proxmox_pool check (goodqa#15771): thresholds, growth, overcommit, fail-closed UNKNOWN, read-only command.
Recorded fixture output only; stdlib only; no network."""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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


QM = {
    100: "scsi0: local:100/vm-100-disk-0.qcow2,size=664G\nscsi1: other:100/vm-100-disk-1.raw,size=999G\nname: t2-dev\n",
    102: "scsi0: local:102/vm-102-disk-0.raw,discard=on,size=200G\nname: gq-prod-app\n",
    103: "scsi0: local:103/vm-103-disk-0.raw,discard=on,size=400G\nscsi1: local:103/vm-103-disk-1.raw,size=100G\n",
    105: "scsi0: local:105/vm-105-disk-0.raw,size=16G\n",
    106: "scsi0: local:106/vm-106-disk-0.raw,size=40G\n",
    108: "scsi0: local:108/vm-108-disk-0.qcow2,size=60G\n",
    109: "scsi0: local:109/vm-109-disk-0.raw,size=16G\n",
    15662: "scsi0: local:15662/vm-15662-disk-0.qcow2,size=40G\nide2: none,media=cdrom\n",
}  # local disks sum to 1536G; the 999G disk is on another storage and must not count
DU = {100: 653, 102: 15, 103: 28, 105: 8, 106: 9, 108: 57, 109: 5, 15662: 13}


def probe(pvesm_text=None, qm=None, du=None, end=True, extra=""):
    qm = QM if qm is None else qm
    du = DU if du is None else du
    out = "##PVESM\n" + (pvesm() if pvesm_text is None else pvesm_text) + "##QM\n"
    for vm, cfg in qm.items():
        out += f"##VM {vm}\n{cfg}"
    out += "##DU\n" + "".join(f"{gib_kib(g)}\t/var/lib/vz/images/{vm}\n" for vm, g in du.items())
    return out + extra + ("##END\n" if end else "")


class Runner:
    def __init__(self, result):
        self.result, self.calls = result, []

    def __call__(self, argv, timeout, stdin=None, env=None, cwd=None):
        self.calls.append((list(argv), timeout))
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

    def test_provisioned_counts_only_the_pool_storage(self):
        self.assertEqual(self.pool()[KEY]["detail"]["provisioned_gib"], 1536.0)


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
        qm = {**QM, 102: "scsi0: local:102/vm-102-disk-0.raw,size=garbage\n", 103: ""}
        du = {k: v for k, v in DU.items() if k != 103}
        got = self.run_check((0, probe(qm=qm, du=du)))[0][KEY]
        self.assertEqual(got["severity"], "high")
        self.assertIsNone(got["detail"]["vms"]["102"]["allocated_gib"])
        self.assertIsNone(got["detail"]["vms"]["103"]["actual_gib"])
        self.assertIn("102", got["detail"]["unsized_vms"])

    def test_size_units(self):
        qm = {102: "scsi0: local:102/a.raw,size=2T\nscsi1: local:102/b.raw,size=512M\nscsi2: local:102/c.raw,size=1024K\n"}
        d = self.run_check((0, probe(qm=qm, du={102: 1})))[0][KEY]["detail"]
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
        text = "##PVESM\n" + pvesm(total_g=1000, used_g=500, avail_g=500) + "##QM\n##DU\n##END\n"
        got = self.run_check((0, text))[0]
        self.assertEqual(sorted(k for k in got if k.startswith("disk:vmunknown:")),
                         [f"disk:vmunknown:t2-proxmox:/var/lib/vz:{v}" for v in (102, 103)])
        self.assertTrue(all(a["message"].startswith("UNKNOWN") for k, a in got.items() if "vmunknown" in k))

    def test_a_watched_vm_missing_from_qm_list_is_unknown_even_with_other_vms_present(self):
        qm = {k: v for k, v in QM.items() if k != 103}
        got = self.run_check((0, probe(qm=qm)))[0]
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

    def test_unsized_disk_keeps_sized_siblings_and_cdrom_does_not_count(self):
        qm = {**QM, 103: QM[103] + "scsi2: local:103/vm-103-disk-2.raw\nide2: local:iso/x.iso,media=cdrom,size=4G\n"}
        d = self.run_check((0, probe(qm=qm)))[0][KEY]["detail"]
        self.assertEqual(d["vms"]["103"]["allocated_gib"], 500.0)
        self.assertIn("103", d["unsized_vms"])

    def test_trailing_slash_mount_keeps_one_key_and_state_record(self):
        self.cfg["proxmox_pools"][0]["mount"] = "/var/lib/vz/"
        got, state, _ = self.run_check((0, probe()))
        self.assertIn(KEY, got)
        self.assertEqual(list(state["proxmox_pools"]), ["t2-proxmox:/var/lib/vz"])


class CommandAndConfigTests(Base):
    READ_WORDS = {"echo", "pvesm", "status", "--storage", "qm", "list", "awk", "config", "du", "-sk", "for", "in",
                  "do", "done", "local"}

    def test_the_remote_script_is_one_fixed_read_only_call(self):
        runner = self.run_check((0, probe()))[2]
        (argv, timeout), = runner.calls
        self.assertEqual(argv[:5], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"])
        self.assertEqual(argv[5:7], ["--", "t2-proxmox"])
        self.assertLessEqual(timeout, 30)
        script = argv[-1]
        for verb in ("fstrim", "resize", "destroy", "set", "create", "start", "stop", "shutdown", "migrate", "rm ",
                     "mv ", "delete", "move", "restore", "unlock", "template", "snapshot", "rollback", "reboot",
                     ">", "<", "`", "&", "|", "sudo", "tee"):
            self.assertNotIn(verb, re.sub(r"'##[A-Z ]+'", "", script).replace("$(qm list | awk 'NR>1{print $1}')", ""),
                             verb)
        self.assertIn("pvesm status --storage local", script)
        self.assertIn("qm config", script)
        for cmd in re.split(r";", script):
            first = cmd.strip().split(" ")[0]
            self.assertIn(first, {"echo", "pvesm", "qm", "du", "for", "do", "done", "", "awk"}, cmd)

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
        self.assertEqual(argv[:5], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"])
        self.assertEqual(argv[5:13], ["-F", "/Users/x/.ssh/config_fleetops", "-J", "t2-dev",
                                      "-o", "UserKnownHostsFile=/Users/x/work/t2-proxmox.known_hosts",
                                      "-o", "StrictHostKeyChecking=yes"])
        self.assertEqual(argv[13:15], ["--", "t2-proxmox"])
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
