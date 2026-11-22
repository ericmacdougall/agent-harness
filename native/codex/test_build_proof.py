"""Exercise the build driver's source gates with isolated command stand-ins."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


DRIVER = Path(__file__).with_name("build-proof.sh").resolve()
SOURCE = {
    "upstreamRepository": "https://github.com/openai/codex.git",
    "upstreamTag": "rust-v0.169.0",
    "upstreamCommit": "d32063f96c2dff1dc96af839b3952abb6acfeda4",
    "patchSha256": "90141e64b41ec86c31c5a320535c4cb9300aab29894117544a44a746386d9c1f",
    "toolchain": "1.95.0",
    "target": "x86_64-unknown-linux-gnu",
    "receiptProtocol": "codex-response-model-observation-v1",
}

GIT_STAND_IN = """
import os
from pathlib import Path
import sys

flag, directory, *args = sys.argv[1:]
assert flag == "-C"
checkout = Path(directory).name
case = os.environ["PROOF_DRIVER_FIXTURE"]
if args == ["rev-parse", "--verify", "HEAD"]:
    if checkout == "codex-upstream":
        print("d32063f96c2dff1dc96af839b3952abb6acfeda4")
        sys.exit(43 if case == "upstream-rev-parse-failed" else 0)
    elif checkout == "codex-receipt-capsule":
        print("8d688c1c9a548f14de0a1c4b9475ef42e607684b")
    elif checkout == "harness":
        print("g" * 40 if case == "malformed-commit" else "a" * 40)
        sys.exit(42 if case == "rev-parse-failed" else 0)
    else:
        sys.exit(96)
elif args == ["write-tree"] and checkout == "codex-upstream":
    print("b" * 39 if case == "malformed-tree" else "b" * 40)
    sys.exit(41 if case == "write-tree-failed" else 0)
elif args == ["status", "--porcelain=v1"] and checkout in ("codex-upstream", "codex-receipt-capsule"):
    sys.exit(44 if case == "status-failed" else 0)
elif args in (["apply", "--check", "--index", "--whitespace=error", os.environ["PROOF_FIXTURE_PATCH"]],
              ["apply", "--index", "--whitespace=error", os.environ["PROOF_FIXTURE_PATCH"]]):
    assert checkout == "codex-upstream"
else:
    sys.exit(96)
"""


class BuildProofTests(unittest.TestCase):
    def run_driver(self, case):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        work = root / "harness"
        run_temp = root / "runner-temp"
        tools = root / "bin"
        capsule = work / "codex-receipt-capsule/native/codex"
        for directory in (work / "codex-upstream", capsule, run_temp, tools):
            directory.mkdir(parents=True)
        source = capsule / "model-receipt.patch"
        source.write_text("Synthetic prefix fixture\n")
        (capsule / "source.json").write_text(json.dumps(SOURCE))
        sentinel = root / "rustup-entered"
        self.stand_in(tools / "git", GIT_STAND_IN)
        self.stand_in(tools / "uname", 'import sys\nassert sys.argv[1:] == ["-m"]\nprint("x86_64")\n')
        self.stand_in(tools / "python3", f'import os,sys\nos.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n')
        self.stand_in(tools / "sha256sum", f'''
import sys
assert sys.argv[1:] == ["--check", "--strict", "-"]
assert sys.stdin.read().strip() == {SOURCE["patchSha256"] + "  " + str(source)!r}
''')
        self.stand_in(tools / "rustup", f'''
from pathlib import Path
import sys
assert sys.argv[1:] == ["toolchain", "install", "1.95.0", "--profile", "minimal", "--target", "x86_64-unknown-linux-gnu"]
Path({str(sentinel)!r}).write_text("entered the build step")
sys.exit(79)
''')
        environment = {"PATH": f"{tools}:/usr/bin:/bin", "LC_ALL": "C",
                       "PROOF_DRIVER_FIXTURE": case, "PROOF_FIXTURE_PATCH": str(source)}
        result = subprocess.run(["/bin/bash", str(DRIVER), str(run_temp)], cwd=work, env=environment,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(list((run_temp / "codex-receipt-output").glob("*")), [])
        return result, sentinel

    def stand_in(self, path, source):
        path.write_text(f"#!{sys.executable}\n{source}")
        path.chmod(0o700)

    def test_valid_source_prefix_reaches_only_the_rustup_sentinel(self):
        result, sentinel = self.run_driver("valid")
        self.assertEqual(result.returncode, 79, result.stderr)
        self.assertEqual(sentinel.read_text(), "entered the build step")

    def test_provenance_command_errors_refuse_even_with_valid_looking_output(self):
        for case, code in (("write-tree-failed", 41), ("rev-parse-failed", 42)):
            with self.subTest(case=case):
                result, sentinel = self.run_driver(case)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(sentinel.exists())

    def test_malformed_tree_or_commit_id_refuses_before_rustup(self):
        for case in ("malformed-tree", "malformed-commit"):
            with self.subTest(case=case):
                result, sentinel = self.run_driver(case)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(sentinel.exists())

    def test_source_checkout_and_status_errors_refuse_before_rustup(self):
        for case, code in (("upstream-rev-parse-failed", 43), ("status-failed", 44)):
            with self.subTest(case=case):
                result, sentinel = self.run_driver(case)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
