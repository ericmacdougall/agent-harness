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
import agent_gate  # noqa: E402
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
# Roughly the real Mac at 16:06Z (8 GB machine under load) and dev2 (192 cores, 185 GB).
MAC = {"host": "mac", "mem_available_gb": 5.0, "cores": 8, "load1": 3.0, "disk_free_gb": 100, "pressure_free_pct": 40}
DEV2 = {"host": "dev2", "mem_available_gb": 134.0, "cores": 192, "load1": 4.0, "disk_free_gb": 900, "pressure_free_pct": None}


def packet(host="dev2", mem="6 GB", wall="25 min", checkpoint=GOOD_CP):
    return BUDGET.format(host=host, mem=mem, wall=wall, checkpoint=checkpoint)


class Budget(unittest.TestCase):
    def test_plan_without_section_is_rejected(self):
        code, text = rb.plan_gate("# Plan\n\nTicket: GoodQA harness#1\n", "enforce", cap=DEV2)
        self.assertEqual(code, 2)
        self.assertIn("no `## Resource budget` section", text)

    def test_same_budget_rejected_on_mac_accepted_on_dev2(self):
        text = packet(host="dev2", mem="6 GB")
        self.assertEqual(rb.check(text, host="dev2", cap=DEV2), [])
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
            # A fixture capacity keeps the bad.md case (decoded with replacement, then linted) from sshing to dev2.
            capacity_file = Path(tmp, "dev2.json")
            capacity_file.write_text(json.dumps(DEV2))
            for packet_path in (fifo, big, bad):
                started = time.time()
                done = subprocess.run([sys.executable, str(HOOKS / "resource_budget.py"), "check", "--host", "dev2", "--packet",
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
            cap = rb.capacity("dev2")
        self.assertEqual(seen[0][0], "ssh")
        self.assertEqual((cap["host"], cap["cores"], cap["load1"]), ("dev2", 192, 4.0))
        self.assertAlmostEqual(cap["mem_available_gb"], 130.86, places=2)

    def test_limits_config_fifo_keeps_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            hooks = Path(tmp, "hooks")
            hooks.mkdir()
            for name in ("agent_gate.py", "resource_budget.py", "safe_input.py"):
                (hooks / name).write_text((HOOKS / name).read_text())
            os.mkfifo(hooks / "resource_limits.json")
            out = subprocess.run([sys.executable, "-c", "import agent_gate;print(agent_gate.cap())"], cwd=str(hooks),
                                 capture_output=True, text=True, timeout=15,
                                 env=dict(os.environ, PYTHONPATH=str(hooks), AH_HOME=tmp))
            self.assertEqual(out.stdout.strip(), "(16, False)")

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "p.md").write_text(packet())
            Path(tmp, "mac.json").write_text(json.dumps(MAC))
            Path(tmp, "dev2.json").write_text(json.dumps(DEV2))
            def run(host, cap):
                return subprocess.run([sys.executable, str(HOOKS / "resource_budget.py"), "check", "--host", host, "--packet",
                                       str(Path(tmp, "p.md")), "--capacity-json", str(Path(tmp, cap))],
                                      capture_output=True, text=True)
            self.assertEqual(run("dev2", "dev2.json").returncode, 0)
            rejected = run("mac", "mac.json")
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("REJECTED", rejected.stdout)

    def test_missing_fields_and_methods(self):
        text = packet().replace("Network: 100 MB (method: lockfile size)\n", "").replace(" (method: nproc of the test runner)", "")
        problems = rb.check(text, host="dev2", cap=DEV2)
        self.assertTrue(any("Network" in p for p in problems))
        self.assertTrue(any("Cpu" in p and "method" in p for p in problems))

    def test_pressure_zeroes_headroom(self):
        under_pressure = dict(MAC, pressure_free_pct=10, mem_available_gb=30)
        self.assertTrue(rb.check(packet(mem="1 GB"), host="mac", cap=under_pressure))

    def test_checkpoint_required_for_long_or_big_jobs(self):
        for kwargs in ({"wall": "45 min"}, {"mem": "5 GB", "wall": "5 min"}):
            problems = rb.check(packet(checkpoint="none", **kwargs), host="dev2", cap=DEV2)
            self.assertTrue(any("Checkpoint" in p for p in problems), (kwargs, problems))
        self.assertTrue(any("not /tmp" in p for p in rb.check(
            packet(wall="45 min", checkpoint="output in /tmp/out, idempotent, resume"), host="dev2", cap=DEV2)))
        self.assertTrue(any("idempotent" in p for p in rb.check(
            packet(wall="45 min", checkpoint="durable work dir, resume later"), host="dev2", cap=DEV2)))
        # control: a short small job needs no checkpoint
        self.assertEqual(rb.check(packet(mem="1 GB", wall="5 min", checkpoint="none"), host="dev2", cap=DEV2), [])

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
        fenced = "```\n" + packet(host="dev2", mem="1 GB", wall="5 min", checkpoint="none") + "```\n" + \
                 packet(host="mac", mem="500 GB", wall="5 min", checkpoint="none")
        self.assertTrue(rb.check(fenced, cap=self.MAC10))
        duplicate = packet(host="dev2", mem="1 GB", wall="5 min", checkpoint="none").replace("processes=8", "processes=500 processes=1")
        self.assertTrue(rb.check(duplicate, host="dev2", cap=DEV2))

    def test_redteam_f9_unreachable_host_warns_instead_of_blocking(self):
        original = rb.capacity
        rb.capacity = lambda host: (_ for _ in ()).throw(OSError("ssh down"))
        self.addCleanup(setattr, rb, "capacity", original)
        code, text = rb.plan_gate(packet(host="dev2", mem="1 GB", wall="5 min", checkpoint="none"), "enforce")
        self.assertEqual(code, 0)
        self.assertIn("WARN", text)


class AgentGate(unittest.TestCase):
    """The one owner cap (resource_limits.json max_live_owners): owners count, helpers never do; at the cap a short
    advisory unless enforce is set."""

    def wal(self, live, stopped=0, stale=0, now=None, helpers=0):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        now = now or datetime.now(timezone.utc)
        root = Path(tmp.name, "sess")
        root.mkdir()
        main = []
        for i in range(live + stopped + stale + helpers):
            started = now - timedelta(minutes=30 if live + stopped <= i < live + stopped + stale else 2)
            kind = "red-team" if i >= live + stopped + stale else "task-owner"
            main.append({"at": started.isoformat(), "event": "subagent", "agent_id": f"a{i}", "agent_type": kind})
            stale_row = live + stopped <= i < live + stopped + stale
            last = started + (timedelta(seconds=10) if stale_row else timedelta(minutes=1))
            Path(root, f"agent-a{i}.jsonl").write_text(json.dumps({"at": last.isoformat(), "event": "pretool", "agent_id": f"a{i}"}) + "\n")
            if live <= i < live + stopped:
                main.append({"at": last.isoformat(), "event": "subagent_stop", "agent_id": f"a{i}"})
        Path(root, "main.jsonl").write_text("\n".join(json.dumps(r) for r in main) + "\n")
        return tmp.name, now.timestamp()

    def test_at_the_cap_is_an_advisory_naming_the_count_and_enforce_denies(self):
        root, now = self.wal(live=8)
        result = agent_gate.decide("sess", now, root, 8, state_root=root + "/st", enforce=False)
        self.assertEqual((result["action"], result["live"]), ("warn", 8))
        self.assertIn("8 live owners", result["message"])
        self.assertIn("proceeds", result["message"])
        root, now = self.wal(live=8)
        denied = agent_gate.decide("sess", now, root, 8, state_root=root + "/st", enforce=True)
        self.assertEqual((denied["action"], denied["live"]), ("deny", 8))
        root7, now7 = self.wal(live=7)
        self.assertEqual(agent_gate.decide("sess", now7, root7, 8, state_root=root7 + "/st")["action"], "allow")

    def test_helpers_are_never_counted_or_warned_about(self):
        root, now = self.wal(live=7, helpers=12)  # 19 live agents, 7 of them owners
        self.assertEqual(agent_gate.decide("sess", now, root, 8, state_root=root + "/st")["action"], "allow")
        root, now = self.wal(live=8)
        for helper in ("red-team", "click-tester", "reviewer", "fixer", "Explore", "Plan"):
            self.assertEqual(agent_gate.decide("sess", now, root, 8, state_root=root + "/st", enforce=True,
                                               subagent_type=helper)["action"], "allow", helper)
        self.assertTrue(agent_gate.is_helper("z-explore-0123456789abcdef0123"))  # wal.safe_id spelling of Explore

    def test_redteam_f7_burst_of_parallel_owner_spawns_is_limited_when_enforced(self):
        root, now = self.wal(live=0)
        results = [agent_gate.decide("sess", now, root, 8, state_root=root + "/st", enforce=True)["action"]
                   for _ in range(12)]
        self.assertEqual(results.count("allow"), 8)  # slots are reserved even before start records exist
        self.assertEqual(results[8:], ["deny"] * 4)

    def test_stopped_and_stale_agents_do_not_count(self):
        root, now = self.wal(live=3, stopped=6, stale=6)
        result = agent_gate.decide("sess", now, root, 8, state_root=root + "/st")
        self.assertEqual((result["action"], result["live"]), ("allow", 3))

    def test_one_cap_from_resource_limits_json_default_16_no_env_override(self):
        shipped = json.loads((HOOKS / "resource_limits.json").read_text())
        self.assertEqual((shipped["max_live_owners"], shipped["enforce"]), (16, False))
        self.assertNotIn("max_agents", shipped)
        self.assertNotIn("warn_agents", shipped)
        with unittest.mock.patch.dict(os.environ, {"HARNESS_MAX_AGENTS": "3", "AH_HOME": tempfile.mkdtemp()}):
            self.assertEqual(agent_gate.cap(), (16, False))  # the env override is gone
        for live, expected in ((15, "allow"), (16, "warn"), (20, "warn")):
            root, now = self.wal(live=live)
            with unittest.mock.patch.dict(os.environ, {"AH_HOME": root}):
                self.assertEqual(agent_gate.decide("sess", now, root, state_root=root + "/st")["action"], expected, live)

    def test_hook_process_advises_denies_only_when_enforced_and_fails_open(self):
        home = tempfile.mkdtemp()
        wal_dir = Path(home, ".claude", "wals", "sess")
        wal_dir.mkdir(parents=True)
        now = datetime.now(timezone.utc)
        lines = [json.dumps({"at": now.isoformat(), "event": "subagent", "agent_id": f"a{i}", "agent_type": "task-owner"})
                 for i in range(17)]
        wal_dir.joinpath("main.jsonl").write_text("\n".join(lines) + "\n")
        env = dict(os.environ, HOME=home, AH_HOME=home, HARNESS_HEAVY_GUARD_FORCE="1")

        def run(stdin):
            return subprocess.run([sys.executable, str(HOOKS / "agent_gate.py")], input=stdin, capture_output=True, text=True, env=env)
        spawn = json.dumps({"tool_name": "Agent", "session_id": "sess", "tool_input": {"subagent_type": "task-owner"}})
        advised = run(spawn)
        self.assertEqual(advised.returncode, 0)
        self.assertIn("17 live owners", json.loads(advised.stdout)["hookSpecificOutput"]["additionalContext"])
        helper = run(json.dumps({"tool_name": "Agent", "session_id": "sess", "tool_input": {"subagent_type": "red-team"}}))
        self.assertEqual((helper.returncode, helper.stdout.strip()), (0, ""))
        Path(home, ".agent-harness").mkdir(exist_ok=True)
        Path(home, ".agent-harness", "limits.local.json").write_text(json.dumps(
            {"values": {"enforce": {"value": True, "set_by": "user", "reason": "test"}}}))
        denied = run(spawn)
        self.assertEqual(denied.returncode, 2)
        self.assertIn("cap 16, enforced", denied.stderr)
        for raw in ("", "garbage", "[" * 100000, json.dumps({"tool_name": "Agent", "session_id": "../../etc"}),
                    json.dumps({"tool_name": "Bash", "session_id": "sess"})):
            self.assertEqual(run(raw).returncode, 0, raw[:20])


class HeavyJobConcurrency(unittest.TestCase):
    def test_third_heavy_job_on_the_mac_is_queued(self):
        home = tempfile.mkdtemp()
        state = Path(home, ".agent-harness", "state", "run_capped")
        state.mkdir(parents=True)
        sleepers = [subprocess.Popen(["sleep", "30"]) for _ in range(2)]
        self.addCleanup(lambda: [p.kill() for p in sleepers])
        for p in sleepers:
            state.joinpath(f"{p.pid}.json").write_text("{}")
        env = dict(os.environ, HOME=home, HARNESS_HEAVY_GUARD_FORCE="1")
        command = "HARNESS_LOCAL_OK='xcode needs the mac' npm run build"
        done = subprocess.run([sys.executable, str(HOOKS / "heavy_job_guard.py")], capture_output=True, text=True, env=env,
                              input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "s"}))
        self.assertEqual(done.returncode, 2)
        self.assertIn("already running on the Mac", done.stderr)
        sleepers[0].kill()
        sleepers[0].wait()
        again = subprocess.run([sys.executable, str(HOOKS / "heavy_job_guard.py")], capture_output=True, text=True, env=env,
                               input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "s"}))
        self.assertEqual(again.returncode, 0, again.stderr)  # one slot freed


if __name__ == "__main__":
    unittest.main()
