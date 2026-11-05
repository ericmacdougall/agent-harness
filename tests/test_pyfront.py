"""The Python front door resolves exactly like internal/impl (shared parity/switchfile/cases.json)."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "compat" / "pyfront"))
import frontdoor  # noqa: E402

CASES = json.loads((ROOT / "parity" / "switchfile" / "cases.json").read_text(encoding="utf-8"))["cases"]


@unittest.skipIf(os.name == "nt", "permission rules are POSIX-only; Windows has no Python front door")
class SharedCases(unittest.TestCase):
    def test_case_table_is_meaningful(self):
        self.assertGreaterEqual(len(CASES), 38)
        self.assertGreater(len({c.get("host", "claude") for c in CASES}), 2)
        self.assertEqual({c["want"] for c in CASES}, {"go", "python", "refuse"})

    def test_every_case(self):
        for case in CASES:
            with self.subTest(case["name"]):
                self.run_case(case)

    def run_case(self, case):
        root = Path(tempfile.mkdtemp(prefix="pyfront-"))
        self.addCleanup(shutil.rmtree, root, True)
        binary, other = root / "launcher" / "harness", root / "other" / "harness"
        link = case.get("launcher_link")
        if link:
            # dir/launcher is a symlink (layouts in the cases.json comment); shared is 0777, not sticky.
            shared = root / "shared"
            if link in ("shared", "two_hop_shared"):
                shared.mkdir(mode=0o700)
                shared.chmod(0o777)
                self.addCleanup(shared.chmod, 0o700)
            real = shared / "x" if link == "shared" else root / "real"
            real.mkdir(mode=0o700)
            if link == "two_hop_shared":
                (shared / "lnk").symlink_to(real)
                binary.parent.symlink_to(shared / "lnk")
            elif link == "relative_safe":
                binary.parent.symlink_to("real")
            else:
                binary.parent.symlink_to(real)
        else:
            binary.parent.mkdir(mode=0o700)
        if "launcher_dir_mode" in case:
            binary.parent.chmod(case["launcher_dir_mode"])
            self.addCleanup(binary.parent.chmod, 0o700)
        other.parent.mkdir(mode=0o700)
        content = b"#!fake harness binary\n"
        sha = hashlib.sha256(content).hexdigest()
        other.write_bytes(content)
        other.chmod(0o700)
        if case.get("bin_symlink"):
            binary.symlink_to(other)
        elif not case.get("bin_missing"):
            binary.write_bytes(content)
            binary.chmod(case.get("bin_mode", 0o700))

        def fill(text):
            return (text.replace("$BIN", str(binary)).replace("$OTHER", str(other))
                    .replace("$SHA_UPPER", sha.upper()).replace("$SHA", sha))

        path = root / "impl.json"
        if "raw" in case:
            body = case["raw"]
        elif "raw_template" in case:
            body = fill(case["raw_template"])
        elif case.get("impl") is not None:
            body = fill(json.dumps(case["impl"]))
        else:
            body = None
        if body is not None:
            target = root / "impl.json.real" if case.get("file_symlink") else path
            data = body.encode("utf-8")
            if case.get("bad_byte"):
                data = data.replace(b"@BAD@", b"\xff")
            target.write_bytes(data)
            target.chmod(case.get("file_mode", 0o600))
            if case.get("file_symlink"):
                path.symlink_to(target)
        environ = {k: v.replace("$SHA", sha) for k, v in case.get("env", {}).items()}
        impl, reason, _, _ = frontdoor.resolve(case.get("group", "wal"), case.get("host", "claude"), str(binary),
                                               str(path), environ)
        self.assertEqual((impl, reason), (case["want"], case.get("reason", "")))


@unittest.skipIf(os.name == "nt", "execve front door is POSIX-only")
class Dispatch(unittest.TestCase):
    """dispatch() execs the Go binary with the canonical grammar, or exits on refusal."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="pyfront-dispatch-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / "home"
        (self.home / ".agent-harness").mkdir(parents=True)
        self.binary = self.root / "bin" / "harness"
        self.binary.parent.mkdir(mode=0o700)  # an umask-002 default (0775) fails the ancestor check
        self.binary.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"; echo \"marker=$AGENT_HARNESS_DISPATCHED\"\n")
        self.binary.chmod(0o700)
        self.helper = self.root / "hooks" / "wal.py"
        self.helper.parent.mkdir(mode=0o700)
        self.helper.write_text(
            "import sys\nsys.path.insert(0, sys.argv[1])\nimport frontdoor\n"
            "frontdoor.dispatch('wal', 'claude', sys.argv[2], __file__, 'hook', sys.argv[3:], hook=True)\n"
            "print('ran python')\n")

    def write_switch(self, group_value):
        sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        path = self.home / ".agent-harness" / "impl.json"
        path.write_text(json.dumps({"schema": 1, "groups": {"wal": group_value},
                                    "hosts": {"claude": {"binary": str(self.binary), "sha256": sha}}}))
        path.chmod(0o600)

    def run_helper(self, *argv, extra_env=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_HARNESS")}
        env.update(HOME=str(self.home), **(extra_env or {}))
        return subprocess.run([sys.executable, str(self.helper), str(ROOT / "compat" / "pyfront"),
                               str(self.binary), *argv], env=env, capture_output=True, text=True, timeout=60)

    def test_go_group_execs_canonical_argv(self):
        self.write_switch("go")
        result = self.run_helper("pre_tool_use")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "--host", "claude", "--config-dir", str(self.helper.parent),
            "--entry", "py:" + str(self.helper), "hook", "pre_tool_use", "marker=py->go"])

    def test_python_group_runs_python(self):
        self.write_switch("python")
        self.assertEqual(self.run_helper("x").stdout, "ran python\n")

    def test_failed_exec_refuses_hook_with_exit_2(self):
        # Passes every check (owner, 0700, sha) but is not executable code: execve raises OSError.
        self.binary.write_bytes(b"\x00\x01 not an executable format\n")
        self.binary.chmod(0o700)
        self.write_switch("go")
        result = self.run_helper("x")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("fail-closed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("ran python", result.stdout)

    def test_loop_refuses_hook_with_exit_2(self):
        self.write_switch("go")
        result = self.run_helper("x", extra_env={"AGENT_HARNESS_DISPATCHED": "go->py"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("harness dispatch loop", result.stderr)
        self.assertNotIn("ran python", result.stdout)


GATES = json.loads((ROOT / "cmd" / "harness" / "gates.json").read_text(encoding="utf-8"))["gates"]
SUBCOMMAND = {"wal.py": "wal", "commit_policy.py": "commit-policy", "spec_flow.py": "spec-flow",
              "command_guard_hook.py": "command-guard", "merge_gate.py": "merge-gate"}


class GateTable(unittest.TestCase):
    """Every hook an installer registers as blocking is a fail-closed gate in the Go binary (gates.json)."""

    def assert_gate(self, argv):
        script, args = Path(argv[0]).name, argv[1:]
        self.assertIn(script, SUBCOMMAND, f"unmapped hook script {script}")
        verbs = GATES.get(SUBCOMMAND[script], [])
        self.assertTrue(any(a in verbs for a in args), f"{script} {args} is not a gate in gates.json")

    def test_claude_blocking_hooks_are_gates(self):
        sys.path.insert(0, str(ROOT))
        import install
        checked = 0
        for groups in install.managed_hooks(Path("/home/u/.claude")).values():
            for group in groups:
                for hook in group["hooks"]:
                    if hook.get("onFailure") == "block":
                        self.assert_gate(hook["args"])
                        checked += 1
        self.assertGreaterEqual(checked, 3)

    def test_codex_hooks_are_gates(self):
        sys.path.insert(0, str(ROOT))
        try:
            import install_codex
        except (ImportError, SyntaxError, TypeError) as error:  # needs Python 3.11 (tomllib)
            self.skipTest(f"install_codex not importable here: {error}")
        merged = install_codex.merge_hooks({}, Path("/home/u/.codex"))
        checked = 0
        for event, groups in merged["hooks"].items():
            if event not in ("PreToolUse", "UserPromptSubmit"):
                continue  # Codex only blocks on these events
            for group in groups:
                for hook in group["hooks"]:
                    self.assert_gate(shlex.split(hook["command"])[1:])
                    checked += 1
        self.assertGreaterEqual(checked, 3)


if __name__ == "__main__":
    unittest.main()
