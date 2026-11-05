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
        import safe_input
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "session_id": "s"}).encode()
        ssh = json.dumps({"tool_name": "Bash", "session_id": "s",
                          "tool_input": {"command": "ssh dev2 'cd repo && pytest && npm run build'"}}).encode()

        def run_main(platform, data):
            with unittest.mock.patch.object(sys, "platform", platform), \
                    unittest.mock.patch.dict(os.environ, {"HARNESS_HEAVY_GUARD_FORCE": ""}), \
                    unittest.mock.patch.object(safe_input, "read_stdin_bounded", return_value=data), \
                    unittest.mock.patch.object(guard, "log_event"), unittest.mock.patch.object(sys, "stderr", io.StringIO()):
                return guard.main()
        self.assertEqual(run_main("linux", payload), 0)   # dev2/Linux: nothing is ever denied
        self.assertEqual(run_main("darwin", payload), 2)  # the same command on the Mac is denied
        self.assertEqual(run_main("darwin", ssh), 0)      # ...but not when it is sent to dev2

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

    def test_m2_wrapper_flags_never_swallow_the_command(self):
        for command in ("env -i pytest", "sudo -n pytest", "sudo -S pytest", "sudo -i pytest", "time -p pytest",
                        "env FOO=1 pytest", "sudo -u root pytest", "nice -n 5 pytest", "time pytest", "nice pytest",
                        "env -u FOO pytest", "sudo -E -H npm run build", "nohup nice -n 10 time -p pytest", "env -i FOO=1 npm test",
                        "caffeinate -i pytest", "stdbuf -oL pytest", "arch -arm64 pytest", "exec pytest", "command pytest"):
            with self.subTest(command=command):
                self.assertEqual(decide(command)["action"], "deny", command)
        self.assertEqual(decide("sudo -u root ls")["action"], "allow")  # control: wrappers around light commands stay allowed

    def test_m2b_unparseable_wrapper_forms_scan_for_the_heavy_command(self):
        for command in ("env -S 'pytest -x'", "env -S pytest", "env --split-string=pytest", "/usr/bin/env -S pytest",
                        "sudo -iu root pytest", "sudo -nu root pytest", "sudo -Eu root pytest", "env -iu V pytest",
                        "time -ao o pytest", "arch -arch arm64 pytest", "env -P /usr/bin pytest", "doas pytest",
                        "doas -u root npm run build", "su -c pytest", "su -l eric -c 'npm test'", "taskpolicy -b pytest",
                        "watch -n 5 pytest", "watch 'pytest -x'", "unbuffer pytest", "nohup sudo -iu root npx playwright test",
                        "stdbuf -oL pytest", "caffeinate -dimsu pytest"):
            with self.subTest(command=command):
                self.assertEqual(decide(command)["action"], "deny", command)
        for command in ("sudo -u root ls", "time ls", "env FOO=1 ls", "git status", "ssh dev2 pytest", "command -v pytest",
                        "command -V pytest", "time grep -rn pytest .", "env FOO=1 grep pytest notes.txt", "sudo ls pytest",
                        "nice -n 5 tail -f pytest.log", "watch -n 5 ls", "su -c 'ls -la'", "doas ls", "env -i HOME=/tmp ls"):
            with self.subTest(allowed=command):
                self.assertEqual(decide(command, cwd="/nonexistent")["action"], "allow", command)

    def test_m2c_command_valued_flags_in_every_spelling_and_deep_nesting(self):
        for command in ("env -Spytest", "env --split-string pytest", "env --split-string 'npm test'", "sudo env -Spytest",
                        "sudo -u root env --split-string pytest", "env --split-string=pytest", "env -S'npm run build'",
                        "su --command pytest", "su --command 'npm test'", "su -s /bin/sh --command pytest", "su -lc pytest",
                        "su -cpytest", "su --command=pytest", "env - pytest", "env - FOO=1 pytest",
                        "nohup nohup nohup nohup nohup pytest", "nice nice nice nice nice pytest",
                        "nohup nohup nohup nohup nohup nohup nohup nohup nohup nohup nohup nohup nohup nohup pytest",
                        "watch $'pytest\t-x'", "watch $'pytest\n-x'", "watch 'pytest\t-x'"):
            with self.subTest(command=command):
                self.assertEqual(decide(command)["action"], "deny", command)
        for command in ("env -S 'ls -la'", "su --command 'ls -la'", "su -c ls", "env - ls", "nohup nohup nohup ls",
                        "watch $'ls\t-la'", "env --split-string=ls"):
            with self.subTest(allowed=command):
                self.assertEqual(decide(command, cwd="/nonexistent")["action"], "allow", command)

    def test_off_mode(self):
        self.assertEqual(guard.decide("pytest", None, dict(MODES, **{"full-suite": "off"})), {"action": "allow"})


class BuildTools(unittest.TestCase):
    """goodqa#14459 B1/L1: make/gradle/mvn/bazel/xcodebuild and the wrapper-depth limit.

    decide() only: these strings are classified, never executed."""

    DENY_FULL = [
        "make test", "make check", "make tests", "make test-unit", "make -j8 check", "make -C sub test", "gmake test",
        "make CC=clang test", "make -f build/Makefile check", "gradle test", "gradle check", "./gradlew test",
        "./gradlew :app:test", "gradlew testDebugUnitTest", "gradle clean test", "gradle test --tests FooTest",
        "gradle connectedAndroidTest", "gradlew.bat check", "mvn test", "mvn verify", "./mvnw test", "mvn clean verify",
        "mvn -q -pl core test", "mvn integration-test", "mvnd test", "bazel test //...", "bazel test //pkg:foo_test",
        "bazelisk test //...", "bazel coverage //...", "xcodebuild test -scheme App",
        "xcodebuild -scheme App -destination 'platform=iOS Simulator,name=iPhone' test",
        "xcodebuild test-without-building -scheme App",
    ]
    DENY_BUILD = [
        "make", "make all", "make build", "make -j8", "make -j 8 all", "make install", "gmake all",
        "gradle build", "./gradlew build", "gradle assemble", "./gradlew assembleRelease", "gradle clean build",
        "gradle -x test build", "./gradlew bundleRelease", "gradle :app:build", "mvn package", "mvn install",
        "mvn clean install", "./mvnw -DskipTests package", "mvn compile", "bazel build //...", "bazel build //app:app",
        "xcodebuild build -scheme App", "xcodebuild -scheme App archive", "xcodebuild", "xcodebuild -project A.xcodeproj",
    ]
    WRAPPED = ["make test", "gradle build", "mvn verify", "bazel test //...", "xcodebuild test"]
    ALLOW = [
        "make help", "make clean", "make --version", "make -v", "make -n test", "make --dry-run all", "make -kn build",
        "make distclean", "make -C sub clean", "make lint", "git commit -m \"make test\"", "git commit -m 'gradle build'",
        "grep -rn \"gradle build\" .", "grep -rn 'mvn test' docs", "ls Makefile", "cat build.gradle", "cat pom.xml",
        "echo make test", "ls gradlew mvnw", "gradle --version", "gradle tasks", "gradle clean", "gradle help",
        "gradle dependencies", "./gradlew --version", "./gradlew -v", "gradle --dry-run build", "gradle -m build",
        "mvn --version", "mvn -v", "mvn clean", "mvn help:effective-pom", "mvn dependency:tree", "./mvnw -v",
        "bazel version", "bazel info", "bazel query //...", "bazel clean", "xcodebuild -version", "xcodebuild -list",
        "xcodebuild -showBuildSettings", "xcodebuild -showsdks", "xcodebuild -scheme test -list",
        "ssh dev2 'make test'", "ssh dev2 'cd repo && ./gradlew build'", "ssh eric@100.86.166.93 'mvn verify'",
        "rsync -a Makefile dev2:repo/", "cd /nonexistent && ls Makefile", "which make gradle mvn",
    ]

    def wrap(self, command):
        return [
            "env FOO=1 " + command, "sudo " + command, "sudo -u root " + command, "nohup " + command, "time " + command,
            "nice -n 5 " + command, "bash -lc '" + command + "'", "sh -c \"" + command + "\"",
            "su -c '" + command + "'", "sudo nohup env A=1 " + command, "nohup bash -c '" + command + "'",
            "bash -c 'nohup env X=1 " + command + "'", "bash -c \"sudo bash -lc '" + command + "'\"",
            "env -S '" + command + "'", "watch -n 5 '" + command + "'", "cd /nonexistent && " + command,
        ]

    def test_corpus_not_vacuous(self):
        for corpus in (self.DENY_FULL, self.DENY_BUILD, self.WRAPPED, self.ALLOW):
            self.assertGreater(len(corpus), 4)

    def test_b1_test_targets_are_full_suite(self):
        for command in self.DENY_FULL:
            with self.subTest(command=command):
                result = decide(command, cwd="/nonexistent")
                self.assertEqual(result["action"], "deny", command)
                self.assertEqual(result["rule"], "full-suite", command)
                self.assertIn("HARNESS_LOCAL_OK", result["message"])
                self.assertIn("dev2", result["message"])

    def test_b1_build_targets_are_build(self):
        for command in self.DENY_BUILD:
            with self.subTest(command=command):
                result = decide(command, cwd="/nonexistent")
                self.assertEqual(result["action"], "deny", command)
                self.assertEqual(result["rule"], "build", command)

    def test_b1_denied_through_every_wrapper_and_nesting(self):
        seen = 0
        for command in self.WRAPPED:
            for wrapped in self.wrap(command):
                seen += 1
                with self.subTest(command=wrapped):
                    self.assertEqual(decide(wrapped, cwd="/nonexistent")["action"], "deny", wrapped)
        self.assertGreater(seen, 40)

    def test_b1_hatch_alone_allows_build_tools_and_modes_apply(self):
        self.assertEqual(decide("HARNESS_LOCAL_OK=needs-mac-keychain make test", cwd="/nonexistent")["action"], "allow")
        self.assertEqual(decide("HARNESS_LOCAL_OK=needs-xcode xcodebuild test", cwd="/nonexistent")["action"], "allow")
        self.assertEqual(guard.decide("make test", "/nonexistent", dict(MODES, **{"full-suite": "off"})), {"action": "allow"})
        self.assertEqual(guard.decide("mvn package", "/nonexistent", dict(MODES, **{"build": "off"})), {"action": "allow"})

    def test_b1_light_forms_never_denied(self):
        for command in self.ALLOW:
            with self.subTest(command=command):
                self.assertEqual(decide(command, cwd="/nonexistent")["action"], "allow", command)
        for command in ("make help", "make clean", "make --version", "gradle tasks", "mvn -v", "xcodebuild -version"):
            for wrapped in self.wrap(command):
                with self.subTest(command=wrapped):
                    self.assertEqual(decide(wrapped, cwd="/nonexistent")["action"], "allow", wrapped)

    def test_b1_make_dry_run_is_allowed_by_design(self):
        # -n/--dry-run/--just-print prints the recipe without running it; a nested $(MAKE) line can still execute in
        # GNU make, which is accepted for a careless-agent threat model and documented in the module docstring.
        for command in ("make -n test", "make --dry-run test", "make --just-print build", "make -n", "make -nj4 check"):
            with self.subTest(command=command):
                self.assertEqual(decide(command, cwd="/nonexistent")["action"], "allow", command)
        self.assertEqual(decide("make test -n", cwd="/nonexistent")["action"], "allow")

    def test_redteam_delta_false_allows_are_closed(self):
        full = ["mvn -V verify", "bash ./gradlew test", "sh ./mvnw verify", "make e2e", "make ci", "make coverage",
                "bazel --output_base x test //...", "bazel --bazelrc f test //...", "xcrun xcodebuild test -scheme A",
                "xcrun --sdk iphoneos xcodebuild test", "xcrun make test", "script -q /dev/null make test",
                "gradle jacocoTestReport", "mvn pre-integration-test"]
        build = ["mvn -V clean install", "bash gradlew build", "sh gradlew build", "gradle shadowJar", "./gradlew bootJar",
                 "gradle classes", "mvn prepare-package", "make compile", "bazel run //app:app", "bazel --batch build //...",
                 "xcrun xcodebuild build", "script -q /dev/null gradle build", "script -c 'make all' /dev/null"]
        for rule, commands in (("full-suite", full), ("build", build)):
            self.assertGreater(len(commands), 10)
            for command in commands:
                with self.subTest(command=command):
                    result = decide(command, cwd="/nonexistent")
                    self.assertEqual((result["action"], result.get("rule")), ("deny", rule), command)

    def test_redteam_delta_light_forms_stay_allowed(self):
        light = ["gradle help --task test", "gradle help --task build", "gradle dependencyInsight --dependency test",
                 "xcodebuild -exportArchive -archivePath a -exportPath b", "xcodebuild -resolvePackageDependencies",
                 "xcodebuild -scheme test -list", "mvn -v", "mvn --version", "xcrun --find clang", "xcrun simctl list",
                 "bash ./deploy.sh", "sh script.sh make", "script -q /dev/null ls", "bazel --output_base x info",
                 "bazel --output_base x version", "bash -c 'ls gradlew'"]
        self.assertGreater(len(light), 10)
        for command in light:
            with self.subTest(command=command):
                self.assertEqual(decide(command, cwd="/nonexistent")["action"], "allow", command)

    def test_redteam_delta_wrapper_forms_report_the_rule(self):
        seen = 0
        for command, rule in (("make test", "full-suite"), ("gradle build", "build"), ("mvn verify", "full-suite"),
                              ("xcodebuild test", "full-suite"), ("bazel build //...", "build")):
            for wrapped in self.wrap(command):
                seen += 1
                with self.subTest(command=wrapped):
                    self.assertEqual(decide(wrapped, cwd="/nonexistent").get("rule"), rule, wrapped)
        self.assertGreater(seen, 60)

    def chain(self, depth, tail="ls"):
        return "nohup " * depth + tail

    def test_l1_deep_wrapper_chain_is_denied_with_the_too_deep_reason(self):
        for depth in (13, 14, 20):
            result = decide(self.chain(depth), cwd="/nonexistent")
            self.assertEqual(result["action"], "deny", depth)
            self.assertIn("too deep", result["message"], depth)
        mixed = decide("nohup env A=1 sudo nice time " * 4 + "ls", cwd="/nonexistent")
        self.assertEqual(mixed["action"], "deny")
        self.assertIn("too deep", mixed["message"])

    def test_l1_chain_at_the_limit_is_allowed(self):
        self.assertEqual(guard.MAX_WRAPPER_DEPTH, 12)
        for depth in (1, 11, 12):
            self.assertEqual(decide(self.chain(depth), cwd="/nonexistent")["action"], "allow", depth)
        self.assertEqual(decide(self.chain(12, "pytest"), cwd="/nonexistent")["action"], "deny")

    def test_l1_limit_is_tight_not_merely_present(self):
        # fails if MAX_WRAPPER_DEPTH is raised (12 -> 40 mutation): 14 wrappers must still be refused
        self.assertEqual(decide(self.chain(14), cwd="/nonexistent")["action"], "deny")
        self.assertLessEqual(guard.MAX_WRAPPER_DEPTH, 13)


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

    def test_safe_input_oversize_nonutf8_and_fifo_inputs_fail_open_quickly(self):
        env = dict(os.environ, HARNESS_HEAVY_GUARD_FORCE="1", HOME=tempfile.mkdtemp())
        hook = [sys.executable, str(HOOKS / "heavy_job_guard.py")]
        for label, data in (("oversize", b'{"tool_name":"Bash","tool_input":{"command":"' + b"a" * (9 * 1024 * 1024) + b'"}}'),
                            ("non-utf8", b'{"tool_name":"Bash","tool_input":{"command":"pytest \xff\xfe"}}'),
                            ("nul-and-garbage", b"\x00\x01\x02" * 1000)):
            started = time.time()
            done = subprocess.run(hook, input=data, capture_output=True, env=env, timeout=30)
            self.assertLess(time.time() - started, 10, label)
            self.assertIn(done.returncode, (0, 2), label)
            if label != "non-utf8":
                self.assertEqual(done.returncode, 0, label)
        with tempfile.TemporaryDirectory() as tmp:  # a FIFO where the config file should be: defaults, no hang
            fifo = Path(tmp, "resource_limits.json")
            os.mkfifo(fifo)
            self.assertEqual(guard.load_modes()["build"], "enforce")
            started = time.time()
            self.assertEqual(guard.read_script(str(fifo), tmp), None)
            self.assertLess(time.time() - started, 3)

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


class PathologicalInput(unittest.TestCase):
    """GoodQA #14505: shlex is quadratic in CPython 3.9, so a 1 MB token hung every hook for 100 s+, and review
    found more superlinear paths (heredoc terminators, per-invocation rescans, wrapper argv slicing).

    Each case builds its string inside a child process with a hard timeout, so a regression fails the test
    instead of hanging the suite. The strings are only ever passed to decide(); nothing executes them. The
    child uses DEFAULT_MODES and a throwaway HOME, so the developer's guard mode and log are never involved."""

    def timed(self, expression, limit=5, cwd="/tmp"):
        code = ("import sys,time; sys.path.insert(0, %r); import heavy_job_guard as g\n"
                "cmd = %s\nt = time.time(); r = g.decide(cmd, %r, g.DEFAULT_MODES); "
                "print(round(time.time() - t, 3), r['action'], r.get('rule'))" % (str(HOOKS), expression, cwd))
        with tempfile.TemporaryDirectory() as home:
            env = {k: v for k, v in os.environ.items() if not k.startswith("HARNESS_")}
            env["HOME"] = home
            try:
                done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=limit,
                                      env=env)
            except subprocess.TimeoutExpired:
                self.fail("no decision within %ss for %s" % (limit, expression))
        self.assertEqual(done.returncode, 0, done.stderr)
        elapsed, action, rule = done.stdout.split()
        return float(elapsed), action, rule

    def fast(self, expression, action, rule="oversize", **kwargs):
        elapsed, got_action, got_rule = self.timed(expression, **kwargs)
        self.assertLess(elapsed, 1.0, expression)
        self.assertEqual(got_action, action, expression)
        if action == "deny" and rule:
            self.assertEqual(got_rule, rule, expression)

    def test_ac1_one_megabyte_token_decides_in_under_a_second(self):
        for expression in ("'echo ' + 'a' * 1000000", "'echo \"' + 'a' * 1000000 + '\"'",
                           "\"echo $'\" + 'a' * 1000000 + \"'\"", "'echo ' + 'a\\\\' * 500000"):
            self.fast(expression, "deny")

    def test_ac1_million_character_command_of_many_segments_decides_in_under_a_second(self):
        self.fast("'ls; ' * 250000", "deny")

    def test_ac1_large_token_under_the_cap_is_scanned_linearly_and_allowed(self):
        self.fast("'echo ' + 'a' * 250000", "allow")

    def test_scan_cap_boundary_is_exact(self):
        self.fast("'ls; ' * 65536", "allow")  # exactly 262144 characters
        self.fast("'ls; ' * 65536 + 'x'", "deny")  # one more

    def test_word_cap_boundary_is_exact(self):
        self.fast("'echo ' + 'a ' * 2047", "allow")  # 2048 words
        self.fast("'echo ' + 'a ' * 2048", "deny")

    def test_neg1_heavy_invocation_past_the_cap_is_not_silently_allowed_even_with_the_hatch(self):
        self.fast("'echo ' + 'a' * 300000 + '; pytest'", "deny")
        # The tail may hold a browser/media/fan-out job that needs the resource cap, so the hatch cannot waive it.
        self.fast("'HARNESS_LOCAL_OK=needs-the-mac echo ' + 'a' * 300000 + '; chromium --headless'", "deny")
        self.fast("'HARNESS_LOCAL_OK=needs-the-mac echo ' + 'a ' * 3000", "deny")

    def test_neg1_long_heredoc_body_does_not_count_toward_the_cap(self):
        self.fast("'cat > big.txt <<EOF\\n' + 'x' * 400000 + '\\nEOF\\nls'", "allow")

    def test_neg2_nested_wrappers_with_long_tokens_stay_bounded(self):
        self.fast("'bash -c ' + repr('sudo ' * 50 + 'x' * 1000000)", "deny")
        self.fast("'bash -c ' + repr('env ' * 200 + 'x' * 200000)", "deny", rule=None)  # depth limit, not size

    def test_many_distinct_unterminated_heredoc_markers_stay_linear(self):
        self.fast("' '.join('<<T%d' % i for i in range(1000)) + '\\n' * 50000", "allow")

    def test_repeated_python_invocations_do_not_rescan_a_large_heredoc_body(self):
        self.fast("'cat <<EOF\\n' + 'x' * 700000 + '\\nEOF\\n' + 'python3 y\\n' * 2000", "allow")

    def test_repeated_script_invocations_do_not_reread_a_large_file(self):
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "big.py").write_text("x = 1\n" * 300000)
            self.fast("'python3 big.py\\n' * 3000", "allow", cwd=cwd)

    def test_wrapper_argv_slicing_paths_are_bounded(self):
        for expression in ("'env -Z ' + 'a ' * 80000", "'do ' * 80000 + 'ls'", "'xcrun ' + '-v ' * 80000 + 'ls'",
                           "'timeout ' + '-x ' * 80000 + '1 ls'"):
            self.fast(expression, "deny")

    def test_ac2_linear_split_matches_shlex_on_seeded_random_input(self):
        import random
        import shlex
        rng, alphabet, cases = random.Random(14505), "ab '\"\\\t\n\r$#;\x0b\x0c\0\u00a0\u2028\u00e9", 0
        for _ in range(20000):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            try:
                want = shlex.split(text)
            except ValueError:
                want = "ValueError"
            try:
                got = guard.posix_split(text)
            except ValueError:
                got = "ValueError"
            self.assertEqual(got, want, "seed 14505, input %r" % text)
            cases += 1
        self.assertEqual(cases, 20000)

    def test_ac2_heredoc_extraction_matches_the_reference_scan(self):
        import random
        rng = random.Random(14505)
        parts = ["cat <<EOF", "cat <<-EOF", "x <<A <<B", "EOF", "\tEOF", "A", "B", "echo hi", "<<<EOF",
                 "cat <<'EOF'", "  EOF", "ls", "<<EOF <<EOF2", "EOF2"]

        def reference(text):  # the pre-#14505 implementation: rescan the remaining lines for each new terminator
            lines, out, bodies, i, missing = text.split("\n"), [], [], 0, set()
            while i < len(lines):
                line = lines[i]
                out.append(line)
                i += 1
                for match in guard.HEREDOC.finditer(line):
                    if line[max(0, match.start() - 1):match.start()] == "<":
                        continue
                    strip_tabs, term = match.group(1) == "-", match.group(3)
                    if term in missing:
                        continue
                    j = i
                    while j < len(lines) and (lines[j].strip() if strip_tabs else lines[j]) != term:
                        j += 1
                    if j < len(lines):
                        bodies.append("\n".join(lines[i:j]))
                        i = j + 1
                    else:
                        missing.add(term)
            return "\n".join(out), bodies

        cases = 0
        for _ in range(20000):
            text = "\n".join(rng.choice(parts) for _ in range(rng.randint(0, 9)))
            self.assertEqual(guard.extract_heredocs(text), reference(text), "seed 14505, input %r" % text)
            cases += 1
        self.assertEqual(cases, 20000)


class BoundValidation(unittest.TestCase):
    def run_script(self, script, flags):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp, "ran")
            done = subprocess.run([sys.executable, str(HOOKS / script)] + flags + ["--", sys.executable, "-c",
                                  "open(%r,'w').write('x')" % str(marker)], capture_output=True, text=True, timeout=30)
            return done, marker.exists()

    def test_m1_nan_inf_and_nonpositive_bounds_are_refused_and_nothing_runs(self):
        for bad in ("nan", "inf", "-inf", "-1", "0", "NaN", "infinity"):
            done, ran = self.run_script("run_capped.py", ["--max-rss-gb", bad])
            self.assertEqual(done.returncode, 2, ("capped rss", bad, done.stderr))
            self.assertFalse(ran, ("capped rss ran", bad))
        for flag in ("--timeout-s", "--poll-s"):
            for bad in ("nan", "inf", "-1"):
                done, ran = self.run_script("run_capped.py", ["--max-rss-gb", "1", flag, bad])
                self.assertEqual(done.returncode, 2, (flag, bad, done.stderr))
                self.assertFalse(ran, (flag, bad))
        base = ["--class", "memory", "--worst-case", "reads /dev/zero: unbounded"]
        for flag in ("--timeout-s", "--max-rss-gb", "--max-file-mb", "--poll-s"):
            for bad in ("nan", "inf", "-1"):
                flags = base + ["--max-rss-gb", "1", "--timeout-s", "5"]
                flags = [f for i, f in enumerate(flags) if not (flags[i - 1] == flag or f == flag)] + [flag, bad]
                done, ran = self.run_script("run_probe.py", flags)
                self.assertEqual(done.returncode, 2, (flag, bad, done.stdout + done.stderr))
                self.assertFalse(ran, ("probe ran", flag, bad))
        done, ran = self.run_script("run_probe.py", base + ["--max-rss-gb", "1", "--timeout-s", "5"])  # control: valid runs
        self.assertEqual((done.returncode, ran), (0, True), done.stdout + done.stderr)


class AbsurdBounds(unittest.TestCase):
    def test_finite_but_absurd_caps_are_refused(self):
        for script, flags in (("run_capped.py", ["--max-rss-gb", "1e300"]), ("run_capped.py", ["--max-rss-gb", "1025"]),
                              ("run_capped.py", ["--max-rss-gb", "1", "--timeout-s", "1e12"]),
                              ("run_probe.py", ["--class", "memory", "--worst-case", "reads /dev/zero: unbounded",
                                                "--max-rss-gb", "1e300", "--timeout-s", "5"]),
                              ("run_probe.py", ["--class", "memory", "--worst-case", "reads /dev/zero: unbounded",
                                                "--max-rss-gb", "1", "--timeout-s", "1e12"])):
            done = subprocess.run([sys.executable, str(HOOKS / script)] + flags + ["--", "true"], capture_output=True, text=True,
                                  timeout=20)
            self.assertEqual(done.returncode, 2, (script, flags, done.stdout + done.stderr))

    def test_max_heavy_mac_env_is_ascii_digits_only(self):
        for value, expected in (("\u00b2", 2), ("\u0662", 2), ("1e3", 2), ("-3", 2), ("5", 5)):
            with unittest.mock.patch.dict(os.environ, {"HARNESS_MAX_HEAVY_MAC": value}):
                self.assertEqual(guard.max_heavy_jobs(), expected, value)


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
