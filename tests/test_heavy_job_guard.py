"""Heavy-job guard, run_capped and run_probe.

Run on dev2, not the Mac: the process tests allocate ~1.5 GB on purpose.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import heavy_job_guard as guard  # noqa: E402

MODES = dict(guard.DEFAULT_MODES)
CAP = "python3 ~/.claude/hooks/run_capped.py --max-rss-gb 4 -- "

# Condensed from the real 2026-11-04T16:06:32Z red-team command (agent ad1514a): a heredoc writes a probe that
# points a hook at /dev/zero and a FIFO, then runs it under a perl alarm/exec timeout wrapper.
IO_COMMAND = """cd /private/tmp/claude-501/x/scratchpad/rt && cat > io.py <<'EOF'
from run import *
import os
fifo=home+"/fifo"
os.mkfifo(fifo)
print("dev zero", hook("stop-lint",{"session_id":SID,"transcript_path":"/dev/zero"},timeout=20))
EOF
perl -e 'alarm 150; exec @ARGV' python3 io.py"""

# Real calibration sample: ordinary commands seen in the session that must never be touched.
NORMAL = [
    "git status --short", "git log --oneline -5", "git diff --stat origin/main", "gh pr view 47 --json state",
    "curl -s https://example.com/health | head", "ls -la ~/.claude/hooks", "cat README.md | head -50",
    "python3 ~/.claude/hooks/wal_note.py --wal ~/.claude/wals/x/main.jsonl --event status --note 'pytest later'",
    "git commit -m 'test: run pytest and npm test in CI'", "grep -rn 'playwright' docs/ | head",
    "python3 -m unittest tests.test_wal -v", "python3 -m pytest tests/test_wal.py -x -q",
    "pytest tests/test_wal.py::TestWal::test_append", "python3 tests/test_wal.py", "npm test -- src/foo.test.ts",
    "npx vitest run src/foo.test.ts", "go test ./pkg/foo -run TestBar", "echo 'next build' > note.txt",
    "ssh dev2 'cd repo && pytest'", "ssh eric@100.86.166.93 'npm run build'", "rsync -a src/ dev2:src/",
    "sed -n 1,40p heavy.py", "python3 -m json.tool < x.json", "node --version", "npm install --no-audit",
    "docker ps", "docker logs web | tail", "cargo --version", "ffmpeg -version", "ffprobe -v error clip.mp4",
    "xargs -n1 echo < list.txt", "git ls-files -z | xargs -0 -P 6 grep -l foo", "ls | xargs -P2 echo", "playwright install chromium", "open -a 'Google Chrome' http://x",
    "tail -f server.log", "find . -name '*.py' | wc -l", "bash -c 'echo hi'", "env FOO=1 ls",
    "python3 -c 'print(1)'", "python3 -c \"import playwright;print(playwright.__version__)\"",
    "python3 -m unittest discover -s tests -p test_commit_policy.py 2>&1 | tail -5", "perl -e 'alarm 60; exec @ARGV' python3 tests/test_wal.py", "git worktree list", "python3 ~/.claude/hooks/peer_review.py plan --repo . --packet p.md",
]


def decide(command, cwd=None, modes=None):
    return guard.decide(command, cwd, modes or MODES)


class Classification(unittest.TestCase):
    def test_ac1_io_probe_is_routed_but_never_blocked(self):
        result = decide(IO_COMMAND)
        self.assertEqual(result["action"], "warn", result)
        self.assertEqual(result["rule"], "adversarial")
        self.assertIn("dev2", result["message"])
        self.assertIn("run_capped.py", result["message"])

    def test_ac1_io_probe_on_dev2_or_group_cleanup_is_plain_allow(self):
        self.assertEqual(decide("ssh dev2 'cd repo/rt && perl -e \"alarm 150; exec @ARGV\" python3 io.py'"), {"action": "allow"})
        wrapped = IO_COMMAND.replace("perl -e 'alarm 150; exec @ARGV' python3 io.py", CAP + "python3 io.py")
        self.assertEqual(decide(wrapped), {"action": "allow"})

    def test_adversarial_cannot_be_forced_to_enforce(self):
        with unittest.mock.patch.dict(os.environ, {"HARNESS_HEAVY_GUARD": "enforce"}):
            self.assertEqual(guard.load_modes()["adversarial"], "warn")

    def sweep_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        Path(tmp.name, "site_sweep.py").write_text("import sys\nfrom playwright.sync_api import sync_playwright\n")
        return tmp.name

    def test_ac1b_site_sweep_relaunch_denied(self):
        d = self.sweep_dir()
        command = (f"cd {d} && SWEEP_USER=eric SWEEP_PASSWORD=preview-only ./venv/bin/python site_sweep.py "
                   "https://127.0.0.1:8791 --ignore-https-errors --out s.json > s.log 2>&1; tail -70 s.log | cut -c1-220")
        result = decide(command)
        self.assertEqual((result["action"], result["rule"]), ("deny", "browser"), result)
        self.assertIn("ssh dev2", result["message"])
        relaunch = ("pkill -f site_sweep.py; cd " + d + " && python3 - <<'E'\ns=open('site_sweep.py').read()\nE\n"
                    "(./venv/bin/python site_sweep.py https://x --public > o.log 2>&1 &) ; ./venv/bin/python site_sweep.py https://y")
        self.assertEqual(decide(relaunch)["action"], "deny")

    def test_ac2_ssh_prefix_allows(self):
        d = self.sweep_dir()
        self.assertEqual(decide(f"ssh dev2 'cd {d} && ./venv/bin/python site_sweep.py https://x'"), {"action": "allow"})
        self.assertEqual(decide("ssh eric@100.86.166.93 pytest"), {"action": "allow"})

    def test_hatch_needs_reason_and_cap_for_browser(self):
        d = self.sweep_dir()
        run = f"cd {d} && ./venv/bin/python site_sweep.py https://x"
        self.assertEqual(decide("HARNESS_LOCAL_OK=1 " + run)["action"], "deny")  # not a reason
        uncapped = decide("HARNESS_LOCAL_OK='local page check' " + run)
        self.assertEqual(uncapped["action"], "deny")
        self.assertIn("ALSO", uncapped["message"])
        capped = decide(f"cd {d} && HARNESS_LOCAL_OK='local page check' {CAP}./venv/bin/python site_sweep.py https://x")
        self.assertEqual((capped["action"], capped["hatch_reason"]), ("allow", "local page check"))

    def test_suites_and_builds_denied_and_hatch_alone_allows(self):
        for command, rule in [("pytest", "full-suite"), ("python3 -m pytest tests/", "full-suite"),
                              ("python3 -m unittest discover -s tests", "full-suite"), ("npm test", "full-suite"),
                              ("pnpm run test:unit", "full-suite"), ("npx vitest run", "full-suite"),
                              ("go test ./...", "full-suite"), ("next build", "build"), ("npm run build", "build"),
                              ("pnpm build", "build"), ("docker build -t x .", "build"), ("cargo build --release", "build"),
                              ("dotnet test", "full-suite"), ("cd x && npx next build", "build"),
                              ("bash -c 'npm run build'", "build"), ("uv run pytest", "full-suite"),
                              ("time nohup pytest -q", "full-suite"), ("npx playwright test", "browser"),
                              ("chromium --headless --screenshot x", "browser")]:
            with self.subTest(command=command):
                result = decide(command, cwd=str(HOOKS.parents[1]))
                self.assertEqual((result["action"], result["rule"]), ("deny", rule), result)
        for command in ("pytest", "npm run build"):
            self.assertEqual(decide("HARNESS_LOCAL_OK='xcode needs the mac' " + command)["action"], "allow")

    def test_media_and_fanout_warn_only(self):
        for command, rule in [("ffmpeg -i a.mov b.mp4", "media"), ("whisper a.wav", "media"),
                              ("ls | xargs -P8 -n1 curl", "fan-out"), ("parallel echo ::: a b", "fan-out")]:
            result = decide(command)
            self.assertEqual((result["action"], result["rule"]), ("warn", rule))

    def test_neg1_normal_commands_not_flagged(self):
        flagged = [c for c in NORMAL if decide(c, cwd=str(HOOKS.parents[1]))["action"] != "allow"]
        self.assertEqual(flagged, [])
        self.assertGreater(len(NORMAL), 35)  # not vacuous

    def test_fifo_and_device_script_paths_do_not_hang(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = os.path.join(tmp, "p.py")
            os.mkfifo(fifo)
            start = time.time()
            for command in (f"python3 {fifo}", "python3 /dev/zero", "python3 /dev/stdin", f"node {fifo[:-3]}.js"):
                self.assertEqual(decide(command), {"action": "allow"})
            self.assertLess(time.time() - start, 5)

    def test_deny_message_names_the_hatch_and_dev2_for_every_enforced_rule(self):
        for command in ("pytest", "npm run build", "npx playwright test"):
            result = decide(command)
            self.assertEqual(result["action"], "deny", command)
            self.assertIn("HARNESS_LOCAL_OK", result["message"], command)
            self.assertIn("ssh dev2", result["message"], command)
            self.assertIn("dev2", result["message"])

    def test_guard_is_a_noop_off_the_mac_and_ssh_dev2_is_allowed_on_it(self):
        import io
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "session_id": "s"})
        with unittest.mock.patch.object(sys, "platform", "linux"), unittest.mock.patch.dict(
                os.environ, {"HARNESS_HEAVY_GUARD_FORCE": ""}), unittest.mock.patch.object(sys, "stdin", io.StringIO(payload)):
            self.assertEqual(guard.main(), 0)  # dev2/Linux: nothing is ever denied
        with unittest.mock.patch.object(sys, "platform", "darwin"), unittest.mock.patch.object(sys, "stdin", io.StringIO(payload)), \
                unittest.mock.patch.object(guard, "log_event"), unittest.mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(guard.main(), 2)  # the same command on the Mac is denied
        ssh = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ssh dev2 'cd repo && pytest && npm run build'"}, "session_id": "s"})
        with unittest.mock.patch.object(sys, "platform", "darwin"), unittest.mock.patch.object(sys, "stdin", io.StringIO(ssh)):
            self.assertEqual(guard.main(), 0)

    def test_redteam_f1_most_severe_finding_wins(self):
        self.assertEqual(decide("ffmpeg -i a b; npx playwright test")["action"], "deny")
        self.assertEqual(decide("xargs -P 9 python3 x; pytest")["action"], "deny")
        self.assertEqual(decide("HARNESS_LOCAL_OK=reasonxx npm run build; npx playwright test")["rule"], "browser")
        self.assertEqual(decide("HARNESS_LOCAL_OK=reasonxx npm run build; npx playwright test")["action"], "deny")

    def test_redteam_f2_compound_forms_and_wrappers(self):
        for command in ("for f in a b; do pytest $f; done", "if true; then npx playwright test; fi", "while :; do pytest; done",
                        "{ pytest; }", "! pytest", "eval 'pytest'", "sudo -u eric npm run build", "env -u X pytest",
                        "xargs pytest", "ls | xargs npx playwright test", "yarn playwright test", "pnpm playwright test",
                        "uv run --with x pytest", "python3 -mpytest", "coverage run -m pytest", "tox",
                        "node -e \"require('playwright').chromium.launch()\"", "podman build .", "nuxt build", "astro build"):
            with self.subTest(command=command):
                self.assertEqual(decide(command)["action"], "deny", command)

    def test_redteam_f4_fail_open_triggers_do_not_hide_a_denied_command(self):
        self.assertEqual(decide("xargs -P \u00b2 python3 x; pytest")["action"], "deny")
        self.assertEqual(decide(": '" + "x" * 150000 + "'; pytest")["action"], "deny")
        start = time.time()
        decide("cat <<A\n" * 30000 + "pytest")
        self.assertLess(time.time() - start, 3)

    def test_redteam_f5_adversarial_hatch_never_denied_by_concurrency_and_stale_sidecars_ignored(self):
        home = tempfile.mkdtemp()
        state = Path(home, ".agent-harness", "state", "run_capped")
        state.mkdir(parents=True)
        for pid in (1, 2, 999999):  # pid 1 is alive but not ours; the others are gone
            state.joinpath(f"{pid}.json").write_text("{}")
        env = dict(os.environ, HOME=home, HARNESS_HEAVY_GUARD_FORCE="1")
        for command in ("HARNESS_LOCAL_OK='redteam probe' python3 -c \"open('/dev/zero','rb').read(1)\"",
                        "HARNESS_LOCAL_OK='xcode needs mac' npm run build"):
            done = subprocess.run([sys.executable, str(HOOKS / "heavy_job_guard.py")], capture_output=True, text=True, env=env,
                                  input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "s"}))
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_redteam_f10_log_never_holds_the_command_text(self):
        home = tempfile.mkdtemp()
        env = dict(os.environ, HOME=home, HARNESS_HEAVY_GUARD_FORCE="1")
        subprocess.run([sys.executable, str(HOOKS / "heavy_job_guard.py")], capture_output=True, text=True, env=env,
                       input=json.dumps({"tool_name": "Bash", "session_id": "s",
                                         "tool_input": {"command": "OPENAI_API_KEY=sk-abcdefghijklmnop1234 npm run build"}}))
        log = Path(home, ".agent-harness", "logs", "heavy-job-guard.jsonl").read_text()
        self.assertIn("build", log)
        self.assertNotIn("sk-abcdef", log)

    def test_off_mode(self):
        self.assertEqual(guard.decide("pytest", None, dict(MODES, **{"full-suite": "off"})), {"action": "allow"})


class HookProcess(unittest.TestCase):
    def run_hook(self, stdin, home=None, extra=None):
        env = dict(os.environ, HARNESS_HEAVY_GUARD_FORCE="1", HOME=home or tempfile.mkdtemp())
        env.update(extra or {})
        return subprocess.run([sys.executable, str(HOOKS / "heavy_job_guard.py")], input=stdin, capture_output=True,
                              text=True, env=env, timeout=30)

    def payload(self, command, **extra):
        return json.dumps(dict({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "sess-1"}, **extra))

    def test_deny_exit_2_with_rule_named(self):
        done = self.run_hook(self.payload("pytest"))
        self.assertEqual(done.returncode, 2)
        self.assertIn("[full-suite]", done.stderr)
        self.assertIn("ssh dev2", done.stderr)

    def test_normal_and_non_bash_pass(self):
        self.assertEqual(self.run_hook(self.payload("git status")).returncode, 0)
        self.assertEqual(self.run_hook(json.dumps({"tool_name": "Write", "tool_input": {"command": "pytest"}})).returncode, 0)

    def test_neg2_malformed_payloads_fail_open(self):
        for raw in ("", "not json", "{", "[]", "null", '{"tool_name":"Bash","tool_input":5}',
                    '{"tool_name":"Bash","tool_input":{"command":["pytest"]}}',
                    "[" * 200000 + "]" * 200000, '{"a":' * 5000 + "1" + "}" * 5000, "x" * (5 * 1024 * 1024)):
            with self.subTest(raw=raw[:30]):
                done = self.run_hook(raw)
                self.assertEqual(done.returncode, 0, done.stderr[-300:])
        self.assertIn("failing open", self.run_hook("[" * 200000).stderr)

    def test_internal_error_fails_open(self):
        done = self.run_hook(self.payload("pytest"), extra={"HARNESS_HEAVY_GUARD": "enforce"})
        self.assertEqual(done.returncode, 2)  # control: the same payload does deny
        broken = tempfile.mkdtemp()
        Path(broken, "heavy_job_guard.json").write_text("{bad")  # unreadable config must not matter
        self.assertEqual(guard.load_modes()["build"], "enforce")

    def test_hatch_is_logged_to_the_wal(self):
        home = tempfile.mkdtemp()
        wal_dir = Path(home, ".claude", "wals", "sess-1")
        wal_dir.mkdir(parents=True)
        done = self.run_hook(self.payload("HARNESS_LOCAL_OK='needs keychain' npm run build"), home=home)
        self.assertEqual(done.returncode, 0, done.stderr)
        text = (wal_dir / "main.jsonl").read_text()
        self.assertIn("HARNESS_LOCAL_OK used: rule=build", text)
        self.assertIn("needs keychain", text)

    def test_startup_budget(self):
        start = time.time()
        for _ in range(5):
            self.run_hook(self.payload("git status"))
        per_call = (time.time() - start) / 5
        print("hook wall time per call: %.1f ms" % (per_call * 1000))
        self.assertLess(per_call, 0.25)  # generous: shared CI; the real number is printed above


def hog_script(gb):
    return ("import time\nb=bytearray(%d)\nfor i in range(0,len(b),4096): b[i]=1\nprint('allocated',flush=True)\n"
            "time.sleep(60)\n" % int(gb * 1024 ** 3))


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def wait_dead(pid, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if os.waitpid(pid, os.WNOHANG) != (0, 0):
                return True
        except ChildProcessError:
            pass
        if not alive(pid):
            return True
        time.sleep(0.1)
    return False


def state(pid):
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return out


class RunCapped(unittest.TestCase):
    def spawn_tree(self, tmp, extra=None):
        """A parent that spawns a child that spawns a grandchild; pids written to files."""
        script = Path(tmp, "tree.py")
        script.write_text(
            "import os,subprocess,sys,time\n"
            "gc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])\n"
            "open(sys.argv[1],'w').write(str(gc.pid))\n" + (extra or "") + "time.sleep(120)\n")
        return script

    def test_ac3_kill_mode_kills_hog_and_children(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "hog.py").write_text(
                "import subprocess,sys\nsubprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])\n"
                + hog_script(1.5))
            started = time.time()
            done = subprocess.run([sys.executable, str(HOOKS / "run_capped.py"), "--max-rss-gb", "1", "--on-breach", "kill",
                                   "--", sys.executable, str(Path(tmp, "hog.py"))], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 137, done.stderr)
            self.assertIn("exceeded the 1 GB cap", done.stderr)
            self.assertLess(time.time() - started, 30)
            left = subprocess.run(["pgrep", "-f", str(Path(tmp, "hog.py"))], capture_output=True, text=True).stdout.split()
            self.assertEqual(left, [])

    def test_breach_pauses_instead_of_killing_then_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "work.py").write_text(
                "import time,sys\nb=bytearray(%d)\nfor i in range(0,len(b),4096): b[i]=1\n"
                "open(sys.argv[1],'w').write('allocated')\ntime.sleep(3)\nopen(sys.argv[2],'w').write('finished')\n" % int(1.3 * 1024 ** 3))
            marker, finished = str(Path(tmp, "m")), str(Path(tmp, "f"))
            proc = subprocess.Popen([sys.executable, str(HOOKS / "run_capped.py"), "--max-rss-gb", "1", "--",
                                     sys.executable, str(Path(tmp, "work.py")), marker, finished],
                                    stderr=subprocess.PIPE, text=True)
            deadline = time.time() + 40
            sidecar = Path.home() / ".agent-harness" / "state" / "run_capped" / f"{proc.pid}.json"
            status = None
            while time.time() < deadline:
                try:
                    status = json.loads(sidecar.read_text())["status"]
                except (OSError, ValueError, KeyError):
                    status = None
                if status == "paused":
                    break
                time.sleep(0.2)
            self.assertEqual(status, "paused")
            self.assertIsNone(proc.poll())  # alive: nothing was killed
            self.assertFalse(Path(finished).exists())
            os.kill(proc.pid, signal.SIGUSR1)
            self.assertEqual(proc.wait(timeout=30), 0)  # resumed and completed: the work was not lost
            self.assertTrue(Path(finished).exists())

    def test_ac4_sigterm_to_wrapper_leaves_no_children(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = str(Path(tmp, "gc.pid"))
            proc = subprocess.Popen([sys.executable, str(HOOKS / "run_capped.py"), "--max-rss-gb", "8", "--",
                                     sys.executable, str(self.spawn_tree(tmp)), pidfile])
            for _ in range(100):
                if Path(pidfile).exists() and Path(pidfile).read_text():
                    break
                time.sleep(0.1)
            grandchild = int(Path(pidfile).read_text())
            self.assertTrue(alive(grandchild))
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(timeout=15), 128 + signal.SIGTERM)
            self.assertTrue(wait_dead(grandchild), "grandchild survived the wrapper SIGTERM")

    def test_ac4_sigkill_of_wrapper_is_reaped_by_guardian(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = str(Path(tmp, "gc.pid"))
            proc = subprocess.Popen([sys.executable, str(HOOKS / "run_capped.py"), "--max-rss-gb", "8", "--",
                                     sys.executable, str(self.spawn_tree(tmp)), pidfile])
            for _ in range(100):
                if Path(pidfile).exists() and Path(pidfile).read_text():
                    break
                time.sleep(0.1)
            grandchild = int(Path(pidfile).read_text())
            proc.kill()
            proc.wait()
            self.assertTrue(wait_dead(grandchild, 15), "guardian did not reap the orphaned tree")

    def test_timeout_does_not_count_time_spent_stopped(self):
        """netwatch pauses with SIGSTOP; a job resumed after a long pause must not die on the wall-clock timeout."""
        with tempfile.TemporaryDirectory() as tmp:
            work, done_file = Path(tmp, "w.py"), Path(tmp, "done")
            work.write_text("import time,sys\nopen(sys.argv[1]+'.started','w').write('1')\n"
                            "end=time.time()+1.5\nwhile time.time()<end: time.sleep(0.05)\n"
                            "open(sys.argv[1],'w').write('finished')\n")
            proc = subprocess.Popen([sys.executable, str(HOOKS / "run_capped.py"), "--max-rss-gb", "8", "--timeout-s", "4",
                                     "--on-breach", "kill", "--poll-s", "0.1", "--", sys.executable, str(work), str(done_file)],
                                    stderr=subprocess.PIPE, text=True)
            for _ in range(100):
                if Path(str(done_file) + ".started").exists():
                    break
                time.sleep(0.05)
            time.sleep(0.4)
            pgid = os.getpgid(proc.pid)  # wrapper's group; the job is in its own session group
            rows = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True).stdout.split("\n")
            kids = [int(r.split()[0]) for r in rows if r.split() and int(r.split()[1]) == proc.pid]
            self.assertTrue(kids)
            os.killpg(os.getpgid(kids[0]), signal.SIGSTOP)  # what netwatch does
            time.sleep(6)  # longer than the whole timeout
            self.assertIsNone(proc.poll(), "wrapper gave up while the job was stopped: " + str(proc.stderr))
            os.killpg(os.getpgid(kids[0]), signal.SIGCONT)
            self.assertEqual(proc.wait(timeout=30), 0)
            self.assertTrue(done_file.exists())

    def test_normal_command_exit_code_passes_through(self):
        done = subprocess.run([sys.executable, str(HOOKS / "run_capped.py"), "--max-rss-gb", "1", "--", sys.executable,
                               "-c", "raise SystemExit(7)"], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 7)

    def test_refuses_missing_cap(self):
        done = subprocess.run([sys.executable, str(HOOKS / "run_capped.py"), "--", "true"], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)


class RunProbe(unittest.TestCase):
    def probe(self, flags, code, timeout=60):
        with tempfile.TemporaryDirectory() as tmp:
            report = str(Path(tmp, "r.json"))
            done = subprocess.run([sys.executable, str(HOOKS / "run_probe.py")] + flags + ["--report", report, "--",
                                   sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout)
            data = json.loads(Path(report).read_text()) if Path(report).exists() else None
            return done, data

    def test_refused_without_declaration(self):
        for flags in ([], ["--class", "memory", "--max-rss-gb", "1", "--timeout-s", "5"],  # no worst case
                      ["--worst-case", "reads /dev/zero", "--class", "memory", "--timeout-s", "5"],  # no memory bound
                      ["--worst-case", "reads /dev/zero", "--class", "memory", "--max-rss-gb", "1"]):  # no time bound
            done, data = self.probe(flags, "print('ran')")
            self.assertEqual(done.returncode, 2, flags)
            self.assertIn("REFUSED", done.stderr)
            self.assertNotIn("ran", done.stdout)

    def test_memory_bound_finding_for_dev_zero_style_probe(self):
        code = "import time\nb=bytearray(1)\nwhile True:\n    b+=bytes(64*1024*1024)\n    time.sleep(0.02)\n"
        done, data = self.probe(["--class", "memory", "--worst-case", "reads /dev/zero: unbounded memory growth",
                                 "--max-rss-gb", "0.5", "--timeout-s", "30"], code)
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertEqual(data["outcome"], "bound-hit:memory")
        self.assertIn("memory bound hit", data["finding"])
        self.assertEqual(data["survivors"], 0)
        self.assertLess(data["observed"]["peak_rss_gb"], 3)

    def test_dev_zero_read_ends_as_a_memory_bound_finding(self):
        """The real 2026-11-04 failure shape: a consumer that slurps /dev/zero with no bound."""
        code = "f=open('/dev/zero','rb')\nb=bytearray()\nwhile True: b+=f.read(1<<26)\n"
        started = time.time()
        done, data = self.probe(["--class", "memory", "--worst-case", "transcript_path=/dev/zero: unbounded memory growth",
                                 "--max-rss-gb", "1", "--timeout-s", "20"], code)
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertEqual(data["outcome"], "bound-hit:memory")
        self.assertLess(time.time() - started, 20)
        self.assertLess(data["observed"]["peak_rss_gb"], 3)  # stopped near its 1 GB bound, not at 66 GB
        self.assertEqual(data["survivors"], 0)

    def test_redteam_f6_every_class_gets_a_memory_bound(self):
        code = "b=bytearray(1)\nimport time\nwhile True:\n    b+=bytes(64<<20); time.sleep(0.02)\n"
        with unittest.mock.patch.dict(os.environ, {"HARNESS_PROBE_RSS_FRACTION": "0.004"}):
            done, data = self.probe(["--class", "hang", "--worst-case", "spins and grows", "--timeout-s", "40"], code, timeout=90)
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertEqual(data["outcome"], "bound-hit:memory")  # not "time": the default ceiling caught it
        self.assertTrue(data["rss_bound_defaulted"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "subreaper accounting is Linux-only")
    def test_redteam_f6_daemonized_escapee_is_counted_and_killed(self):
        code = ("import os,sys,time\nif os.fork()==0:\n    os.setsid()\n    if os.fork()==0:\n"
                "        b=bytearray(int(0.9*2**30))\n        for i in range(0,len(b),4096): b[i]=1\n        time.sleep(60)\n"
                "    os._exit(0)\nos.wait()\ntime.sleep(30)\n")
        done, data = self.probe(["--class", "memory", "--worst-case", "daemon holds memory outside the group",
                                 "--max-rss-gb", "0.5", "--timeout-s", "30"], code)
        self.assertEqual(done.returncode, 3, done.stdout)
        self.assertEqual(data["outcome"], "bound-hit:memory")
        self.assertEqual(data["survivors"], 0)

    def test_time_bound(self):
        done, data = self.probe(["--class", "hang", "--worst-case", "blocks forever on a FIFO", "--timeout-s", "1"],
                                "import time\ntime.sleep(60)")
        self.assertEqual((done.returncode, data["outcome"]), (3, "bound-hit:time"))

    def test_file_size_bound(self):
        code = "import os\nf=open(os.environ['TMPDIR']+'/big','wb')\nwhile True:\n    f.write(bytes(1<<20)); f.flush()\n"
        done, data = self.probe(["--class", "disk", "--worst-case", "writes until the disk fills", "--max-file-mb", "20",
                                 "--timeout-s", "30"], code)
        self.assertEqual(done.returncode, 3, done.stdout)
        self.assertEqual(data["outcome"], "bound-hit:disk")

    def test_process_count_bound(self):
        code = ("import subprocess,sys,time\nfor _ in range(40):\n"
                "    subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\ntime.sleep(30)\n")
        done, data = self.probe(["--class", "process", "--worst-case", "fork fan-out", "--max-procs", "10",
                                 "--timeout-s", "30"], code)
        self.assertEqual((done.returncode, data["outcome"]), (3, "bound-hit:process"))
        self.assertEqual(data["survivors"], 0)

    def test_well_behaved_probe_completes(self):
        done, data = self.probe(["--class", "memory", "--worst-case", "small allocation only", "--max-rss-gb", "1",
                                 "--timeout-s", "20"], "print('fine')")
        self.assertEqual(done.returncode, 0)
        self.assertEqual((data["outcome"], data["child_rc"]), ("completed", 0))

    def test_sandbox_home_and_tmp(self):
        done, data = self.probe(["--class", "sandbox-escape", "--worst-case", "writes outside sandbox", "--timeout-s", "10"],
                                "import os,sys\nassert os.environ['HOME']==os.environ['TMPDIR']!=os.path.expanduser('~x') ; "
                                "assert 'run-probe-' in os.environ['HOME']")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


import unittest.mock  # noqa: E402  (used above via unittest.mock.patch)

if __name__ == "__main__":
    unittest.main()
