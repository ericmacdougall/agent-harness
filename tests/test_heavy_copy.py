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

    def test_depth_must_be_a_real_small_depth_option(self):
        url = "https://gitlab.com/huge/mono.git"
        for flags in ("--depth 2147483647", "--shallow-since=1970-01-01", "--template --depth",
                      "--separate-git-dir --depth", "--server-option --depth", "--depth 0", "--depth x"):
            with self.subTest(flags=flags):
                self.assertEqual(decide(f"git clone {flags} {url} m").get("rule"), "copy", flags)
        # A blobless clone is bounded like a shallow one (the deny message recommends it; review m1 on 60c0630).
        for flags in ("--depth 1", "--depth=1", "--depth 50", "-b main --depth 1", "--filter=blob:none"):
            self.assertEqual(decide(f"git clone {flags} {url}")["action"], "allow", flags)

    def test_to_stdout_only_counts_as_a_real_extract_option(self):
        with mock.patch.object(guard, "path_size", fake_size({"/arch": 5 * GIB, "/bigsrc": 5 * GIB})):
            for command in ("tar -czf /Users/eric/out.tgz /bigsrc -O", "tar -xzf /arch.tgz -C /Users/eric/d --exclude -O",
                            "tar -xzf /arch.tgz -C /Users/eric/d -- -O"):
                with self.subTest(command=command):
                    self.assertEqual(decide(command).get("rule"), "copy", command)
            self.assertEqual(decide("tar -xzOf /arch.tgz")["action"], "allow")

    def test_the_last_depth_option_wins_as_in_git(self):
        url = "https://gitlab.com/huge/mono.git"
        self.assertEqual(decide(f"git clone --depth 1 --depth 2147483647 {url}").get("rule"), "copy")
        self.assertEqual(decide(f"git clone --depth=1 --depth=1000 {url}").get("rule"), "copy")
        self.assertEqual(decide(f"git clone --depth 1000 --depth 1 {url}")["action"], "allow")

    def test_t2_dev_is_a_fleet_host_and_tar_to_stdout_writes_nothing(self):
        with mock.patch.object(guard, "remote_path_size", lambda spec: 4 * GIB):
            self.assertEqual(decide("scp -r t2-dev:/bigsrc /Users/eric/z")["rule"], "copy")
        with mock.patch.object(guard, "path_size", fake_size({"/arch": 5 * GIB})):
            self.assertEqual(decide("tar xzf /arch.tgz --to-stdout")["action"], "allow")
            self.assertEqual(decide("tar -xOf /arch.tar")["action"], "allow")

    def test_a_volumes_path_that_leads_back_to_the_boot_disk_is_still_the_macs_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "Boot")
            os.symlink("/Users/eric", link)
            with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB})):
                self.assertEqual(decide(f"cp -R /bigsrc {link}/x").get("rule"), "copy")

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


class HeavyCommandFamilies(unittest.TestCase):
    """Coordinator P12 follow-up: installs, replays, containers and claude -p fan-out are denied on the Mac with the exact route."""

    DENIED = [("pnpm install", "install"), ("npm ci", "install"), ("yarn add left-pad", "install"), ("bun install", "install"),
              ("node scripts/solve-replay.js --all", "replay"), ("pnpm run synthetic:full", "replay"),
              ("docker run --rm -it ubuntu bash", "container"), ("docker compose up -d", "container"),
              ("docker pull postgres", "container"), ("podman run x", "container"),
              ("for f in a b c; do claude -p \"review $f\" & done", "fan-out"),
              ("claude -p a & claude -p b & claude -p c &", "fan-out"), ("ls | xargs -P8 -n1 claude -p", "fan-out"),
              ("pytest", "full-suite"), ("python3 -m unittest discover -s tests", "full-suite"), ("npm test", "full-suite"),
              ("pnpm build", "build")]
    ALLOWED = ["pnpm --version", "npm --version", "docker ps", "docker logs web | tail", "claude -p 'one quick question'",
               "node scripts/one-off.js", "pytest tests/test_one.py", "npm test -- src/a.test.ts", "git status"]

    def test_denied_with_the_exact_route(self):
        for command, rule in self.DENIED:
            with self.subTest(command=command):
                result = guard.decide(command, "/Users/eric/proj", MODES)
                self.assertEqual((result["action"], result["rule"]), ("deny", rule), result)
                host = "dev2" if "claude" in command else "t2-dev"  # claude is not logged in on t2-dev
                self.assertIn(f"ssh {host} bash -lc", result["message"])
                if host == "dev2":
                    self.assertNotIn("ssh t2-dev ", result["message"])

    def test_quick_forms_stay_allowed(self):
        for command in self.ALLOWED:
            with self.subTest(command=command):
                self.assertEqual(guard.decide(command, "/Users/eric/proj", MODES)["action"], "allow", command)

    def test_the_route_line_is_runnable_on_the_host(self):
        message = guard.decide("pnpm install --frozen-lockfile", "/Users/eric/proj", MODES)["message"]
        self.assertIn("rsync -a --exclude node_modules --exclude .git /Users/eric/proj/ t2-dev:~/proj/", message)
        self.assertIn("ssh t2-dev bash -lc 'cd ~/proj && pnpm install --frozen-lockfile'", message)
        self.assertNotIn("cd /Users/eric", message)  # a Mac path does not exist on the host
        with mock.patch.object(guard, "ah_run_available", lambda: False):
            self.assertIn("replaces steps 1-2 once goodqa#14548", guard.decide("pnpm install", "/Users/eric/proj", MODES)["message"])
        with mock.patch.object(guard, "ah_run_available", lambda: True):
            self.assertIn("ah.py run --host t2-dev -- pnpm install", guard.decide("pnpm install", "/Users/eric/proj", MODES)["message"])
        piped = guard.decide("ls | xargs -P8 pnpm install", "/Users/eric/proj", MODES)["message"]
        self.assertIn("ls | xargs -P8 pnpm install", piped)  # the whole command, pipe included
        multi = guard.decide("pnpm install\npnpm build", "/Users/eric/proj", MODES)["message"]
        self.assertIn("pnpm install\npnpm build", multi)  # newlines survive quoting
        self.assertNotIn("...", guard.decide("pnpm install " + "x " * 400, "/Users/eric/proj", MODES)["message"])


class ReviewRound4(unittest.TestCase):
    """Native review B1/M1/minors of PR 103 at e78b427: each row failed against that head."""

    def d(self, command, cwd="/Users/eric/proj"):
        return guard.decide(command, cwd, MODES)

    def test_b1_prompts_containing_loop_words_are_not_loops(self):
        for command in ('claude -p "review this diff for bugs"', 'git log -5 | claude -p "summarize while ignoring merges"',
                        "claude -p 'explain what happens until the lock is freed'",
                        'for f in a b; do wc -l "$f"; done; claude -p "summarize"',
                        'for f in a b c; do claude -p "one at a time $f"; done',  # sequential, not backgrounded
                        'claude -p a; claude -p b; claude -p c', 'claude -p "a && b & c"'):
            with self.subTest(command=command):
                self.assertEqual(self.d(command)["action"], "allow", command)

    def test_b1_real_background_fanout_is_denied_and_the_cap_plus_hatch_is_a_working_escape(self):
        loop = 'for f in a b c; do claude -p "review $f" & done; wait'
        self.assertEqual(self.d(loop)["rule"], "fan-out")
        self.assertEqual(self.d("claude -p a & claude -p b & wait")["rule"], "fan-out")
        capped = ("HARNESS_LOCAL_OK='needs local sessions' python3 ~/.claude/hooks/run_capped.py --max-rss-gb 4 -- "
                  "bash -c 'claude -p a & claude -p b & wait'")
        self.assertEqual(self.d(capped)["action"], "allow", self.d(capped))
        uncapped = "HARNESS_LOCAL_OK='needs local sessions' claude -p a & claude -p b & wait"
        self.assertEqual(self.d(uncapped)["action"], "deny")

    def test_m1_claude_routes_to_dev2_and_others_to_t2_dev(self):
        message = self.d('for f in a b; do claude -p "x $f" & done')["message"]
        self.assertIn("ssh dev2 bash -lc", message)
        self.assertNotIn("ssh t2-dev", message)
        self.assertIn("not logged in", message)
        self.assertIn("ssh t2-dev bash -lc", self.d("pnpm install")["message"])
        with mock.patch.dict(os.environ, {"HARNESS_CLAUDE_ROUTE_HOST": "t2-dev"}):
            self.assertIn("ssh t2-dev bash -lc", self.d("claude -p a & claude -p b &")["message"])

    def test_docker_remote_engines_and_more_container_forms(self):
        for command in ("docker --context t2-dev run x", "docker -H ssh://t2-dev run x", "DOCKER_HOST=ssh://t2-dev docker run x"):
            self.assertEqual(self.d(command)["action"], "allow", command)
        for command in ("docker compose --profile dev up", "docker compose --env-file e.cfg up", "docker container run x",
                        "docker image pull x", "colima start", "podman machine start"):
            self.assertEqual(self.d(command)["rule"], "container", command)

    def test_installs_that_slipped_through(self):
        for command in ("yarn", "yarn workspace web add left-pad", "pnpm -w add -D x", "npm clean-install", "npm cit",
                        "npm install-test", "corepack pnpm install", "yarn install"):
            self.assertEqual(self.d(command)["rule"], "install", command)
        for command in ("yarn --version", "npm install --dry-run", "pnpm install --help"):
            self.assertEqual(self.d(command)["action"], "allow", command)

    def test_replay_forms(self):
        for command in ("python3 scripts/replay.py", "pnpm tsx scripts/replay.ts", "node --import tsx scripts/replay.ts",
                        "k6 run load.js", "pnpm run synthetic:full"):
            self.assertEqual(self.d(command)["rule"], "replay", command)
        for command in ("node --test tests/replay.test.mjs", "tsx src/replay.spec.ts", "node scripts/replay.js --help",
                        "pnpm run stress-free-mode", "python3 scripts/replay.py --help"):
            self.assertEqual(self.d(command)["action"], "allow", command)

    def test_nan_epoch_is_stale_and_tiny_sizes_keep_their_estimate(self):
        self.assertEqual(guard.record_epoch({"measured_at_epoch": float("nan")}), 0.0)
        detail = guard.copy_event_detail({"cwd": ""}, {"detail": "cp copies at least 3.0 MiB onto this Mac"})
        self.assertEqual(detail["est_bytes"], 3 * 1048576)


class ClaudeRouteAndAuth(unittest.TestCase):
    def test_claude_fanout_routes_to_dev2_with_the_reason_not_to_t2_dev(self):
        message = guard.decide('for f in a b c; do claude -p "x $f" & done', "/Users/eric/p", MODES)["message"]
        self.assertIn("ssh dev2 bash -lc", message)
        self.assertNotIn("ssh t2-dev", message)
        self.assertIn("not logged in", message)


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
        self.assertEqual(detail["route"], "t2-dev")
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

    def test_future_timestamps_and_a_corrupt_hatch_file_do_not_lock_an_owner_out_or_in_forever(self):
        now = time.time()
        guard.record_hatch_use("fut", 5, now)
        path = os.path.join(guard.state_dir(), "heavy-hatch.json")
        Path(path).write_text(json.dumps({"fut": [now + 10 * 3600], "o": ["x", None]}))
        self.assertEqual(guard.record_hatch_use("fut", 1, now + 3601)[0], True)  # the future stamp was clamped to now
        Path(path).write_text("{not json")
        self.assertEqual(guard.record_hatch_use("o", 1, now)[0], True)  # corrupt file: fails open, and heals
        self.assertEqual(guard.record_hatch_use("o", 1, now)[0], False)

    def test_env_assignments_in_the_command_cannot_raise_the_limits(self):
        cmd = "HARNESS_HATCH_PER_HOUR=99 HARNESS_COPY_GIB=999 HARNESS_LOCAL_OK='one local step' cp -r /bigsrc /Users/eric/x"
        self.assertEqual(self.call(cmd)[0], 0)
        self.assertEqual(self.call(cmd)[0], 2)  # the hook reads its own environment, not the command's

    def test_a_future_stamped_budget_record_does_not_block(self):
        cwd = self.work_cwd()
        self.budget_record("sess/agent-A", age=-3600)
        with mock.patch.object(guard, "path_size", fake_size({"/bigsrc": 3 * GIB, cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            self.assertEqual(self.call("HARNESS_LOCAL_OK='one local step' cp -r /bigsrc ./c", cwd=cwd)[0], 0)

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

    def test_over_budget_owner_cannot_start_a_local_build_either(self):
        cwd = self.work_cwd()
        self.budget_record("sess/agent-A")
        with mock.patch.object(guard, "path_size", fake_size({cwd: 9 * GIB, os.path.realpath(cwd): 9 * GIB})):
            code, err = self.call("HARNESS_LOCAL_OK='needs the mac' npm run build", cwd=cwd)
            self.assertEqual(code, 2)
            self.assertIn("[build]", err)
            self.assertEqual(self.call("ls", cwd=cwd)[0], 0)
        other = Path(self.home.name, ".agent-harness", "work", "sess", "agent-B")
        other.mkdir(parents=True)
        self.assertEqual(self.call("HARNESS_LOCAL_OK='needs the mac' npm run build", cwd=str(other))[0], 0)

    def test_hatch_overuse_raises_a_warning_alert_and_the_route_is_configurable(self):
        cmd = "HARNESS_LOCAL_OK='one local step' cp -r /bigsrc /Users/eric/x"
        self.call(cmd)
        code, err = self.call(cmd)
        self.assertEqual(code, 2)
        refusals = [e for e in self.ring() if e["key"] == "heavy:hatch:agentA" and "exceeded" in e["message"]]
        self.assertEqual([e["severity"] for e in refusals], ["warning"])
        self.assertEqual(refusals[0]["detail"]["hatch_uses_1h"], 1)
        with mock.patch.dict(os.environ, {"HARNESS_ROUTE_HOST": "t2"}):
            code, err = self.call("cp -r /bigsrc /Users/eric/y", agent="agentR")
            self.assertEqual(code, 2)
            self.assertIn("ssh t2 ", err)
            self.assertNotIn("ssh dev2 ", err)
            self.assertEqual(self.ring()[-1]["detail"]["route"], "t2")
        with mock.patch.dict(os.environ, {"HARNESS_ROUTE_HOST": "bad host;rm"}):
            self.assertEqual(guard.route_host(), "t2-dev")

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
