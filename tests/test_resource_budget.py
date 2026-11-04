import json
import os
import subprocess
import sys
import tempfile
import unittest
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


class AgentGate(unittest.TestCase):
    def wal(self, live, stopped=0, stale=0, now=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        now = now or datetime.now(timezone.utc)
        root = Path(tmp.name, "sess")
        root.mkdir()
        main = []
        for i in range(live + stopped + stale):
            started = now - timedelta(minutes=30 if i >= live + stopped else 2)
            main.append({"at": started.isoformat(), "event": "subagent", "agent_id": f"a{i}"})
            last = started + (timedelta(seconds=10) if i >= live + stopped else timedelta(minutes=1))
            Path(root, f"agent-a{i}.jsonl").write_text(json.dumps({"at": last.isoformat(), "event": "pretool", "agent_id": f"a{i}"}) + "\n")
            if live <= i < live + stopped:
                main.append({"at": last.isoformat(), "event": "subagent_stop", "agent_id": f"a{i}"})
        Path(root, "main.jsonl").write_text("\n".join(json.dumps(r) for r in main) + "\n")
        return tmp.name, now.timestamp()

    def test_ninth_concurrent_agent_is_denied(self):
        root, now = self.wal(live=8)
        result = agent_gate.decide("sess", now, root, 8)
        self.assertEqual((result["action"], result["live"]), ("deny", 8))
        self.assertIn("dev2", result["message"])
        root7, now7 = self.wal(live=7)
        self.assertEqual(agent_gate.decide("sess", now7, root7, 8)["action"], "allow")  # 8th spawn is fine

    def test_stopped_and_stale_agents_do_not_count(self):
        root, now = self.wal(live=3, stopped=6, stale=6)
        result = agent_gate.decide("sess", now, root, 8)
        self.assertEqual((result["action"], result["live"]), ("allow", 3))

    def test_hook_process_denies_and_fails_open(self):
        home = tempfile.mkdtemp()
        wal_dir = Path(home, ".claude", "wals", "sess")
        wal_dir.mkdir(parents=True)
        now = datetime.now(timezone.utc)
        lines = []
        for i in range(9):
            lines.append(json.dumps({"at": now.isoformat(), "event": "subagent", "agent_id": f"a{i}"}))
        wal_dir.joinpath("main.jsonl").write_text("\n".join(lines) + "\n")
        env = dict(os.environ, HOME=home, HARNESS_HEAVY_GUARD_FORCE="1")

        def run(stdin):
            return subprocess.run([sys.executable, str(HOOKS / "agent_gate.py")], input=stdin, capture_output=True, text=True, env=env)
        denied = run(json.dumps({"tool_name": "Agent", "session_id": "sess", "tool_input": {}}))
        self.assertEqual(denied.returncode, 2)
        self.assertIn("limit 8", denied.stderr)
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
