"""P12 (goodqa#14817): large-copy classification, hatch rate limit, per-owner disk budget block.

Sparse files keep these cheap: st_blocks is faked by patching path_size where a "big" tree is needed, and one test
writes a real 1.1 GiB-apparent sparse file to prove the real walker agrees. Run on dev2/T2 with the other suites.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import heavy_job_guard as guard  # noqa: E402

GIB = 1024 ** 3
MODES = dict(guard.DEFAULT_MODES)


def decide(command, cwd="/Users/eric"):
    return guard.decide(command, cwd, MODES)


def fake_size(table):
    def size(path, cap=None, seconds=1.0):
        for prefix, value in table.items():
            if path.startswith(prefix):
                return value, True
        return 10, True
    return size


class CopyClassification(unittest.TestCase):
    def test_big_local_copies_are_denied_and_routed(self):
        big = {"/bigsrc": 3 * GIB}
        with mock.patch.object(guard, "path_size", fake_size(big)):
            for command in ("cp -r /bigsrc /Users/eric/x", "cp -a /bigsrc/ ~/y", "rsync -a /bigsrc/ /Users/eric/z/",
                            "tar cf /Users/eric/a.tar /bigsrc", "ditto /bigsrc /Users/eric/d",
                            "cd /tmp && cp -r /bigsrc ."):
                with self.subTest(command=command):
                    result = decide(command)
                    self.assertEqual((result["action"], result["rule"]), ("deny", "copy"), result)
                    self.assertIn("dev2", result["message"])

    def test_small_and_offbox_copies_are_allowed(self):
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB})):
            for command in ("cp -r /smallsrc /Users/eric/x", "rsync -a /bigsrc/ dev2:work/", "scp -r /bigsrc dev2:work/",
                            "ssh dev2 'cp -r /bigsrc /x'", "tar czf - /bigsrc | ssh dev2 'tar xzf -'",
                            "rsync -an /bigsrc/ /Users/eric/z/", "rsync --dry-run -a /bigsrc/ /Users/eric/z/",
                            "git status", "ls -la", "cp a.txt b.txt"):
                with self.subTest(command=command):
                    self.assertEqual(decide(command)["action"], "allow", command)

    def test_unmeasurable_source_counts_as_heavy(self):
        with mock.patch.object(guard, "path_size", lambda p, cap=None, seconds=1.0: (10, False)):
            result = decide("cp -r /hugetree /Users/eric/x")
        self.assertEqual((result["action"], result["rule"]), ("deny", "copy"))

    def test_real_walker_counts_disk_usage_and_stops_at_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                Path(tmp, f"f{i}").write_bytes(os.urandom(1 << 20))
            size, complete = guard.path_size(tmp)
            self.assertTrue(complete)
            self.assertGreaterEqual(size, 3 << 20)
            capped, _ = guard.path_size(tmp, cap=1 << 20)
            self.assertLess(capped, size + 1)
            os.symlink("/", os.path.join(tmp, "loop"))  # never followed
            self.assertLess(guard.path_size(tmp)[0], 1 << 30)

    def test_tar_extract_uses_archive_size_times_compression(self):
        with mock.patch.object(guard, "path_size", fake_size({"/arch": 400 * 1024 * 1024})):
            self.assertEqual(decide("tar xzf /arch.tgz -C /Users/eric/o")["rule"], "copy")  # 400 MB * 4
            self.assertEqual(decide("tar xf /arch.tar -C /Users/eric/o")["action"], "allow")  # 400 MB * 1

    def test_clone_uses_github_size(self):
        with mock.patch.object(guard, "github_repo_bytes", lambda o, r: 3 * GIB):
            result = decide("git clone https://github.com/acme/release.git /Users/eric/r")
            self.assertEqual((result["action"], result["rule"]), ("deny", "copy"))
            self.assertEqual(decide("gh repo clone acme/release")["rule"], "copy")
            self.assertEqual(decide("git clone --depth 1 git@github.com:acme/release.git")["rule"], "copy")  # 1.5 GiB
        with mock.patch.object(guard, "github_repo_bytes", lambda o, r: 50 * 1024 * 1024):
            self.assertEqual(decide("git clone https://github.com/acme/small.git")["action"], "allow")

    def test_unknown_full_clone_is_heavy_but_unknown_shallow_is_not(self):
        with mock.patch.object(guard, "github_repo_bytes", lambda o, r: None):
            self.assertEqual(decide("git clone https://github.com/acme/x.git")["rule"], "copy")
            self.assertEqual(decide("git clone --depth 1 https://github.com/acme/x.git")["action"], "allow")

    def test_worktree_add_uses_tracked_tree_size(self):
        with mock.patch.object(guard, "tracked_tree_bytes", lambda d: 2 * GIB):
            self.assertEqual(decide("git worktree add ../review")["rule"], "copy")
            self.assertEqual(decide("git -C /somewhere worktree add ../review main")["rule"], "copy")
        with mock.patch.object(guard, "tracked_tree_bytes", lambda d: 5 * 1024 * 1024):
            self.assertEqual(decide("git worktree add ../review")["action"], "allow")
        self.assertEqual(decide("git worktree list")["action"], "allow")

    def test_threshold_env_override(self):
        with mock.patch.object(guard, "path_size", fake_size({"/mid": 300 * 1024 * 1024})), \
                mock.patch.dict(os.environ, {"HARNESS_COPY_GIB": "0.1"}):
            self.assertEqual(decide("cp -r /mid /Users/eric/m")["rule"], "copy")

    def test_a_sizing_bug_fails_open(self):
        with mock.patch.object(guard, "path_size", side_effect=RuntimeError("boom")):
            self.assertEqual(decide("cp -r /bigsrc /Users/eric/x")["action"], "allow")


class ReviewFindings(unittest.TestCase):
    """goodqa#14817 review: each row failed against the first implementation."""

    def test_flags_that_take_no_value_do_not_hide_the_source(self):
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB})):
            for command in ("cp -i /bigsrc /Users/eric/x", "cp -R -P /bigsrc /Users/eric/x", "ditto -X /bigsrc /Users/eric/d",
                            "cp -c -R /bigsrc /Users/eric/x", "tar -C /Users/eric/d -czf /Users/eric/o.tgz /bigsrc",
                            "tar --exclude=.git -czf /Users/eric/o.tgz /bigsrc", "tar czf /Users/eric/o.tgz /bigsrc"):
                with self.subTest(command=command):
                    self.assertEqual(decide(command).get("rule"), "copy", command)
        with mock.patch.object(guard, "path_size", fake_size({"/arch": 5 * GIB})):
            self.assertEqual(decide("tar -C /Users/eric/d -xzf /arch.tgz")["rule"], "copy")
            self.assertEqual(decide("tar -xf /arch.tar -C /Users/eric/d")["rule"], "copy")

    def test_other_hosts_clones_are_unknown_and_heavy_unless_shallow(self):
        for url in ("https://gitlab.com/acme/x.git", "git@gitlab.com:acme/x.git", "ssh://git@bitbucket.org/acme/x.git"):
            self.assertEqual(decide(f"git clone {url}")["rule"], "copy", url)
            self.assertEqual(decide(f"git clone --depth 1 {url}")["action"], "allow", url)

    def test_unmeasurable_worktree_is_heavy(self):
        with mock.patch.object(guard, "tracked_tree_bytes", lambda d: None):
            self.assertEqual(decide("git worktree add ../r")["rule"], "copy")

    def test_the_hook_only_ever_connects_to_fleet_hosts(self):
        import subprocess
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("must not connect")):
            for command in ("cp notes:2026.txt /Users/eric/x", "rsync evil.example:x /Users/eric/y",
                            "scp eve@evil.example:/etc /Users/eric/z", "rsync -e 'ssh -o ProxyCommand=x' attacker:/a ."):
                with self.subTest(command=command):
                    decide(command)
        with mock.patch.object(guard, "remote_path_size", lambda spec: 4 * GIB):
            self.assertEqual(decide("rsync -a dev2:repo /Users/eric/r")["rule"], "copy")
            self.assertEqual(decide("scp -r eric@t2:repo /Users/eric/r")["rule"], "copy")
        with mock.patch.object(guard, "remote_path_size", lambda spec: None):
            self.assertEqual(decide("rsync -a dev2:repo /Users/eric/r")["rule"], "copy")  # unknown fleet size is heavy

    def test_external_volumes_are_not_the_macs_disk(self):
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB})):
            self.assertEqual(decide("cp -R /bigsrc /Volumes/Backup/x")["action"], "allow")

    def test_dereferenced_symlink_is_measured_where_it_points(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "link")
            os.symlink("/bigsrc", link)
            with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB})):
                self.assertEqual(decide(f"cp -RL {link} /Users/eric/x").get("rule"), "copy")
                self.assertEqual(decide(f"cp -R {link} /Users/eric/x")["action"], "allow")  # control: the link itself

    def test_sizing_has_an_overall_time_bound(self):
        sources = " ".join(f"/src{i}" for i in range(50))
        calls = []

        def slow(path, cap=None, seconds=1.0):
            calls.append(path)
            time.sleep(0.2)
            return 1, True
        with mock.patch.object(guard, "path_size", slow):
            start = time.monotonic()
            result = decide(f"cp -r {sources} /Users/eric/x")
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(result["rule"], "copy")
        self.assertLess(len(calls), 50)


class RunGates(unittest.TestCase):
    """The side-effecting front door: hatch limit, 85% disk refusal, over-budget block, ring and WAL audit."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        env = mock.patch.dict(os.environ, {"HOME": self.home.name, "HARNESS_HEAVY_GUARD_FORCE": "1"})
        env.start()
        self.addCleanup(env.stop)
        for patch in (mock.patch.object(guard, "LOG_PATH", os.path.join(self.home.name, "log.jsonl")),
                      mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB})),
                      mock.patch.object(guard, "disk_used_pct", lambda: 40.0),
                      mock.patch.object(guard, "live_heavy_jobs", lambda: 0)):
            patch.start()
            self.addCleanup(patch.stop)

    def call(self, command, agent="agentA", cwd="/Users/eric", session="s1"):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd, "session_id": session,
                   "agent_id": agent}
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            code = guard.run(json.dumps(payload).encode())
        return code, err.getvalue()

    def ring(self):
        import ops_watch
        return [e for e in ops_watch.read_ring(ops_watch.ring_path(Path(self.home.name))) if e.get("source") == "heavy-guard"]

    def test_refusal_emits_one_ring_event_without_command_or_path(self):
        code, err = self.call("cp -r /bigsrc /Users/eric/secret-dest")
        self.assertEqual(code, 2)
        events = self.ring()
        self.assertEqual([e["key"] for e in events], ["heavy:copy:agentA"])
        detail = events[0]["detail"]
        self.assertEqual(detail["agent"], "agentA")
        self.assertEqual(detail["route"], "dev2")
        self.assertNotIn("secret-dest", json.dumps(events))
        self.assertNotIn("/bigsrc", json.dumps(events))

    def test_second_hatch_use_in_an_hour_is_refused_and_first_is_audited(self):
        cmd = "HARNESS_LOCAL_OK='one local step' cp -r /bigsrc /Users/eric/x"
        self.assertEqual(self.call(cmd)[0], 0)
        code, err = self.call(cmd)
        self.assertEqual(code, 2, err)
        self.assertIn("already used", err)
        keys = [(e["key"], e["severity"]) for e in self.ring()]
        self.assertIn(("heavy:hatch:agentA", "warning"), keys)
        self.assertEqual(self.call(cmd, agent="agentB")[0], 0)  # another owner has its own allowance

    def test_hatch_window_slides(self):
        now = time.time()
        self.assertEqual(guard.record_hatch_use("o", 1, now)[0], True)
        self.assertEqual(guard.record_hatch_use("o", 1, now + 10)[0], False)
        self.assertEqual(guard.record_hatch_use("o", 1, now + 3601)[0], True)

    def test_limit_is_configurable_and_applies_to_every_rule(self):
        with mock.patch.dict(os.environ, {"HARNESS_HATCH_PER_HOUR": "3"}):
            for _ in range(3):
                self.assertEqual(self.call("HARNESS_LOCAL_OK='needs the mac' npm run build")[0], 0)
            self.assertEqual(self.call("HARNESS_LOCAL_OK='needs the mac' npm run build")[0], 2)

    def test_hatch_refused_for_copy_above_85_percent_disk(self):
        with mock.patch.object(guard, "disk_used_pct", lambda: 94.0):
            code, err = self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc /Users/eric/x")
        self.assertEqual(code, 2)
        self.assertIn("85%", err)
        with mock.patch.object(guard, "disk_used_pct", lambda: 94.0):  # other rules keep the plain hatch
            self.assertEqual(self.call("HARNESS_LOCAL_OK='needs the mac' npm run build")[0], 0)

    def budget_record(self, key, over=True, age=0):
        d = Path(self.home.name, ".agent-harness", "state", "disk-budget")
        d.mkdir(parents=True, exist_ok=True)
        d.joinpath("x.json").write_text(json.dumps({
            "agent": "agentA", "path_key": key, "budget_bytes": 5 * GIB, "used_bytes": 9 * GIB,
            "measured_at": "2026-11-05T15:00Z", "measured_at_epoch": time.time() - age,
            "over_since": "2026-11-05T14:00Z" if over else None}))

    def work_cwd(self):
        path = Path(self.home.name, ".agent-harness", "work", "sess", "agent-A")
        path.mkdir(parents=True)
        return str(path)

    def test_over_budget_owner_cannot_start_a_heavy_copy_even_with_the_hatch(self):
        cwd = self.work_cwd()
        self.budget_record("sess/agent-A")
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            code, err = self.call("cp -r /bigsrc ./clone", cwd=cwd)
            self.assertEqual(code, 2)
            self.assertIn("over its", err)
            self.assertEqual(self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c", cwd=cwd)[0], 2)
            self.assertEqual(self.call("ls", cwd=cwd)[0], 0)  # light commands are never blocked
            self.assertEqual(self.call("cp -r /smallsrc ./c", cwd=cwd)[0], 0)

    def test_freeing_space_unblocks_at_once_and_stale_records_never_block(self):
        cwd = self.work_cwd()
        self.budget_record("sess/agent-A")
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: GIB, os.path.realpath(cwd): GIB})):
            self.assertEqual(self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c", cwd=cwd)[0], 0)  # only the hatch
        self.budget_record("sess/agent-A", age=4 * 3600)
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            self.assertEqual(self.call("cp -r /smallsrc ./c", cwd=cwd)[0], 0)

    def test_other_owner_is_not_blocked_by_someone_elses_budget(self):
        self.work_cwd()
        self.budget_record("sess/agent-A")
        other = Path(self.home.name, ".agent-harness", "work", "sess", "agent-B")
        other.mkdir(parents=True)
        code, _ = self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c", cwd=str(other))
        self.assertEqual(code, 0)

    def test_contract_shaped_record_without_path_key_or_epoch_still_blocks(self):
        cwd = self.work_cwd()
        d = Path(self.home.name, ".agent-harness", "state", "disk-budget")
        d.mkdir(parents=True)
        from datetime import datetime, timezone
        d.joinpath("A.json").write_text(json.dumps({
            "agent": "A", "budget_bytes": 5 * GIB, "used_bytes": 9 * GIB,
            "measured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ"), "over_since": "2026-11-05T14:00Z"}))
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            self.assertEqual(self.call("cp -r /bigsrc ./c", cwd=cwd)[0], 2)

    def test_a_live_walk_that_times_out_does_not_clear_the_block(self):
        cwd = self.work_cwd()
        self.budget_record("sess/agent-A")

        def partial(path, cap=None, seconds=1.0):
            return (2 * GIB, False) if os.path.realpath(path).startswith(os.path.dirname(os.path.realpath(cwd))) else (3 * GIB, True)
        with mock.patch.object(guard, "path_size", partial):
            self.assertEqual(self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c", cwd=cwd)[0], 2)

    def test_a_refused_command_does_not_spend_the_hourly_hatch_use(self):
        cmd = "HARNESS_LOCAL_OK='one local step' cp -r /bigsrc /Users/eric/x"
        with mock.patch.object(guard, "live_heavy_jobs", lambda: 99):
            self.assertEqual(self.call(cmd, agent="agentC")[0], 2)
        self.assertEqual(self.call(cmd, agent="agentC")[0], 0)

    def test_stale_record_really_is_ignored(self):
        cwd = self.work_cwd()
        self.budget_record("sess/agent-A", age=4 * 3600)
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            self.assertEqual(self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c", cwd=cwd)[0], 0)
        self.budget_record("sess/agent-A", age=2 * 3600)
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            self.assertEqual(self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c2", cwd=cwd, agent="agentD")[0], 2)

    def test_codex_payload_shapes_are_guarded(self):
        for tool_input in ({"cmd": "cp -r /bigsrc /Users/eric/x"}, {"command": ["bash", "-lc", "cp -r /bigsrc /Users/eric/x"]},
                           {"command": "cp -r /bigsrc /Users/eric/x", "workdir": "/Users/eric"}):
            for tool in ("exec_command", "shell", "local_shell", "Bash"):
                payload = {"tool_name": tool, "tool_input": tool_input, "session_id": "s"}
                with mock.patch.object(sys, "stderr", io.StringIO()):
                    self.assertEqual(guard.run(json.dumps(payload).encode()), 2, (tool, tool_input))
        with mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(guard.run(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/x"}}).encode()), 0)


if __name__ == "__main__":
    unittest.main()
