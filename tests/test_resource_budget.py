import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
os.environ["AH_LOCAL_CONFIG"] = str(Path(__file__).resolve().parent / "data" / "local_fixture.json")  # hermetic hosts
import resource_budget as rb  # noqa: E402

BUDGET = """# Plan

Ticket: GoodQA harness#1

## Resource budget
Host: {host}
Fan-out: agents=2 jobs=1 processes=8 browser_pages=0 test_workers=4
Peak memory: {mem} (method: measured RSS of the previous run x1.5)
CPU: 4 cores (method: nproc of the test runner)
Disk: 2 GB (method: build output size)
Network: 100 MB (method: lockfile size)
Wall time: {wall}
Cap and kill: run_capped.py --max-rss-gb 9 pauses on breach; netwatch kills only as last resort
Checkpoint: {checkpoint}

## Next
"""
GOOD_CP = "durable output under ~/.agent-harness/work/s/t/, steps idempotent, resume by re-running"
# Roughly the real Mac at 16:06Z (8 GB machine under load) and worker-1 (192 cores, 185 GB).
MAC = {"host": "mac", "mem_available_gb": 5.0, "cores": 8, "load1": 3.0, "disk_free_gb": 100, "pressure_free_pct": 40}
DEV2 = {"host": "worker-1", "mem_available_gb": 134.0, "cores": 192, "load1": 4.0, "disk_free_gb": 900, "pressure_free_pct": None}


def packet(host="worker-1", mem="6 GB", wall="25 min", checkpoint=GOOD_CP):
    return BUDGET.format(host=host, mem=mem, wall=wall, checkpoint=checkpoint)


class Budget(unittest.TestCase):
    def test_plan_without_section_is_rejected(self):
        code, text = rb.plan_gate("# Plan\n\nTicket: GoodQA harness#1\n", "enforce", cap=DEV2)
        self.assertEqual(code, 2)
        self.assertIn("no `## Resource budget` section", text)

    def test_same_budget_rejected_on_mac_accepted_on_dev2(self):
        text = packet(host="worker-1", mem="6 GB")
        self.assertEqual(rb.check(text, host="worker-1", cap=DEV2), [])
        problems = rb.check(text, host="mac", cap=MAC)
        self.assertTrue(any("peak memory 6 GB exceeds mac headroom" in p for p in problems), problems)

    def test_cli_rejects_fifo_oversize_and_nonutf8_packets_without_hanging(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp, "fifo.md")
            os.mkfifo(fifo)
            big = Path(tmp, "big.md")
            big.write_bytes(b"x" * (2 * 1024 * 1024))
            bad = Path(tmp, "bad.md")
            bad.write_bytes(b"## Resource budget\n\xff\xfe\n")
            # A fixture capacity keeps the bad.md case (decoded with replacement, then linted) from sshing to worker-1.
            capacity_file = Path(tmp, "worker-1.json")
            capacity_file.write_text(json.dumps(DEV2))
            for packet_path in (fifo, big, bad):
                started = time.time()
                done = subprocess.run([sys.executable, str(HOOKS / "resource_budget.py"), "check", "--host", "worker-1", "--packet",
                                       str(packet_path), "--capacity-json", str(capacity_file)],
                                      capture_output=True, text=True, timeout=20)
                self.assertEqual(done.returncode, 2, packet_path.name + done.stdout)
                self.assertLess(time.time() - started, 10)

    def test_live_dev2_capacity_parses_ssh_output_without_a_real_ssh(self):
        seen = []

        def fake_run(argv, timeout=15):
            seen.append(argv)
            return "134000\n192\n4.00\n943718400\n"
        with unittest.mock.patch.object(rb, "_run", fake_run):
            cap = rb.capacity("worker-1")
        self.assertEqual(seen[0][0], "ssh")
        self.assertEqual((cap["host"], cap["cores"], cap["load1"]), ("worker-1", 192, 4.0))
        self.assertAlmostEqual(cap["mem_available_gb"], 130.86, places=2)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "p.md").write_text(packet())
            Path(tmp, "mac.json").write_text(json.dumps(MAC))
            Path(tmp, "worker-1.json").write_text(json.dumps(DEV2))
            def run(host, cap):
                return subprocess.run([sys.executable, str(HOOKS / "resource_budget.py"), "check", "--host", host, "--packet",
                                       str(Path(tmp, "p.md")), "--capacity-json", str(Path(tmp, cap))],
                                      capture_output=True, text=True)
            self.assertEqual(run("worker-1", "worker-1.json").returncode, 0)
            rejected = run("mac", "mac.json")
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("REJECTED", rejected.stdout)

    def test_missing_fields_and_methods(self):
        text = packet().replace("Network: 100 MB (method: lockfile size)\n", "").replace(" (method: nproc of the test runner)", "")
        problems = rb.check(text, host="worker-1", cap=DEV2)
        self.assertTrue(any("Network" in p for p in problems))
        self.assertTrue(any("Cpu" in p and "method" in p for p in problems))

    def test_pressure_zeroes_headroom(self):
        under_pressure = dict(MAC, pressure_free_pct=10, mem_available_gb=30)
        self.assertTrue(rb.check(packet(mem="1 GB"), host="mac", cap=under_pressure))

    def test_checkpoint_required_for_long_or_big_jobs(self):
        for kwargs in ({"wall": "45 min"}, {"mem": "5 GB", "wall": "5 min"}):
            problems = rb.check(packet(checkpoint="none", **kwargs), host="worker-1", cap=DEV2)
            self.assertTrue(any("Checkpoint" in p for p in problems), (kwargs, problems))
        self.assertTrue(any("not /tmp" in p for p in rb.check(
            packet(wall="45 min", checkpoint="output in /tmp/out, idempotent, resume"), host="worker-1", cap=DEV2)))
        self.assertTrue(any("idempotent" in p for p in rb.check(
            packet(wall="45 min", checkpoint="durable work dir, resume later"), host="worker-1", cap=DEV2)))
        # control: a short small job needs no checkpoint
        self.assertEqual(rb.check(packet(mem="1 GB", wall="5 min", checkpoint="none"), host="worker-1", cap=DEV2), [])

    def test_fanout_ceiling_on_mac(self):
        text = packet(mem="1 GB", wall="5 min").replace("browser_pages=0", "browser_pages=20")
        self.assertTrue(any("browser_pages=20" in p for p in rb.check(text, host="mac", cap=dict(MAC, mem_available_gb=50))))

    def test_warn_mode_does_not_block(self):
        self.assertEqual(rb.plan_gate("no section", "warn", cap=DEV2)[0], 0)
        self.assertEqual(rb.plan_gate("no section", "off", cap=DEV2), (0, ""))


class BudgetParsing(unittest.TestCase):
    MAC10 = dict(MAC, mem_available_gb=10)

    def test_redteam_f8_bogus_numbers_do_not_pass(self):
        base = packet(host="mac", mem="1 GB", wall="5 min", checkpoint="none")
        for bad in ("1,000 GB", "2,048 MB", "unknown (method: last run used 2 GB)", "0 GB", "1e3 GB", "1_000 GB"):
            text = base.replace("Peak memory: 1 GB", "Peak memory: " + bad)
            self.assertTrue(rb.check(text, host="mac", cap=self.MAC10), bad)
        self.assertEqual(rb.check(base, host="mac", cap=self.MAC10), [])  # control

    def test_l5_extra_tokens_after_the_figure_are_rejected(self):
        base = packet(host="mac", mem="1 GB", wall="5 min", checkpoint="none")
        for bad in ("3 GB 900 GB", "3 GB and 900 GB", "3 GB, 900 GB", "3GB 900MB"):
            self.assertTrue(rb.check(base.replace("Peak memory: 1 GB", "Peak memory: " + bad), host="mac", cap=self.MAC10), bad)
        self.assertEqual(rb.check(base.replace("Peak memory: 1 GB", "Peak memory: 3 GB"), host="mac",
                                  cap=dict(self.MAC10, mem_available_gb=20)), [])

    def test_redteam_f8_vm_hosts_are_checked_and_decoys_ignored(self):
        text = packet(host="vm:x", mem="900 GB", wall="5 min", checkpoint="none")
        self.assertTrue(any("Capacity" in p for p in rb.check(text)))
        self.assertTrue(any("exceeds" in p for p in rb.check(text.replace("Host: vm:x", "Host: vm:x\nCapacity: 8 GB memory, 4 cores, 50 GB disk"))))
        self.assertTrue(rb.check(packet(host="vmware", mem="1 GB")))
        fenced = "```\n" + packet(host="worker-1", mem="1 GB", wall="5 min", checkpoint="none") + "```\n" + \
                 packet(host="mac", mem="500 GB", wall="5 min", checkpoint="none")
        self.assertTrue(rb.check(fenced, cap=self.MAC10))
        duplicate = packet(host="worker-1", mem="1 GB", wall="5 min", checkpoint="none").replace("processes=8", "processes=500 processes=1")
        self.assertTrue(rb.check(duplicate, host="worker-1", cap=DEV2))

    def test_redteam_f9_unreachable_host_warns_instead_of_blocking(self):
        original = rb.capacity
        rb.capacity = lambda host: (_ for _ in ()).throw(OSError("ssh down"))
        self.addCleanup(setattr, rb, "capacity", original)
        code, text = rb.plan_gate(packet(host="worker-1", mem="1 GB", wall="5 min", checkpoint="none"), "enforce")
        self.assertEqual(code, 0)
        self.assertIn("WARN", text)


if __name__ == "__main__":
    unittest.main()
