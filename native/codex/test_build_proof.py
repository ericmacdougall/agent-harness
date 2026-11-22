"""Exercise the build driver's source gates with isolated command stand-ins."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


DRIVER = Path(__file__).with_name("build-proof.sh").resolve()
TEST_HOME_PATCH = DRIVER.with_name("test-arg0-home.patch")
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
elif args == ["add", "--", "codex-rs/Cargo.lock"] and checkout == "codex-upstream":
    assert (Path(directory) / "codex-rs/Cargo.lock").read_text() == "normalized fixture lock"
    (Path(directory) / "lock-staged").touch()
elif args == ["write-tree"] and checkout == "codex-upstream":
    assert (Path(directory) / "lock-staged").is_file()
    assert (Path(directory) / "test-home-patch-applied").is_file()
    print("b" * 39 if case == "malformed-tree" else "b" * 40)
    sys.exit(41 if case == "write-tree-failed" else 0)
elif args == ["status", "--porcelain=v1"] and checkout in ("codex-upstream", "codex-receipt-capsule"):
    sys.exit(44 if case == "status-failed" else 0)
elif args in (["apply", "--check", "--index", "--whitespace=error", os.environ["PROOF_FIXTURE_PATCH"]],
              ["apply", "--index", "--whitespace=error", os.environ["PROOF_FIXTURE_PATCH"]]):
    assert checkout == "codex-upstream"
    if "--check" not in args:
        (Path(directory) / "receipt-patch-applied").touch()
elif (args[:1] == ["apply"] and
      Path(args[-1]).name == "test-arg0-home.patch" and checkout == "codex-upstream"):
    assert (Path(directory) / "receipt-patch-applied").is_file()
    assert args[1:-1] == (["--check", "--index", "--whitespace=error"] if "--check" in args
                          else ["--index", "--whitespace=error"])
    if "--check" in args:
        sys.exit(46 if case == "test-home-patch-drift" else 0)
    (Path(directory) / "test-home-patch-applied").touch()
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
        system_temp = root / "system-temp"
        tools = root / "bin"
        capsule = work / "codex-receipt-capsule/native/codex"
        for directory in (work / "codex-upstream/codex-rs", capsule, run_temp, system_temp,
                          work / "native/codex", tools):
            directory.mkdir(parents=True)
        source = capsule / "model-receipt.patch"
        source.write_text("Synthetic prefix fixture\n")
        (capsule / "source.json").write_text(json.dumps(SOURCE))
        fixture_patch = work / "native/codex/test-arg0-home.patch"
        fixture_patch.write_bytes(TEST_HOME_PATCH.read_bytes())
        if case == "test-home-patch-digest":
            with fixture_patch.open("ab") as output:
                output.write(b"Unexpected bytes\n")
        sentinel = root / "rustup-entered"
        self.stand_in(tools / "git", GIT_STAND_IN)
        self.stand_in(tools / "uname", 'import sys\nassert sys.argv[1:] == ["-m"]\nprint("x86_64")\n')
        self.stand_in(tools / "python3", f"""
import os
from pathlib import Path
import sys
if Path(sys.argv[1]).name == "normalize-lock.py":
    upstream = Path({str(work / 'codex-upstream/codex-rs')!r})
    assert sys.argv[1:] == [{str(work / 'native/codex/normalize-lock.py')!r}, str(upstream)]
    if os.environ["PROOF_DRIVER_FIXTURE"] == "lock-unverified":
        sys.exit(45)
    (upstream / "Cargo.lock").write_text("normalized fixture lock")
else:
    os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])
""")
        self.stand_in(tools / "sha256sum", f'''
import hashlib
from pathlib import Path
import sys
assert sys.argv[1:] == ["--check", "--strict", "-"]
digest, path = sys.stdin.read().strip().split("  ", 1)
if path == {str(fixture_patch)!r}:
    sys.exit(47 if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest else 0)
assert (digest, path) == ({SOURCE["patchSha256"]!r}, {str(source)!r})
''')
        self.stand_in(tools / "rustup", f'''
import os
from pathlib import Path
import sys

stage = Path({str(sentinel)!r})
assert os.environ["HOME"] == {str(root / 'fresh-home')!r}
assert os.environ["CARGO_HOME"] == {str(root / 'fresh-home/.cargo')!r}
assert os.environ["RUSTUP_HOME"] == {str(root / 'fresh-home/.rustup')!r}
assert "CI" not in os.environ
assert "CODEX_TEST_ARG0_HOME_BASE" not in os.environ
fixture_base = Path({str(run_temp / 'codex-receipt-work/fixture-homes')!r})
assert fixture_base.resolve() == fixture_base and fixture_base.stat().st_mode & 0o777 == 0o700
assert not fixture_base.is_relative_to(Path(os.environ["TMPDIR"]))
if sys.argv[1:3] == ["toolchain", "install"]:
    assert sys.argv[3:] == ["1.95.0", "--profile", "minimal", "--target",
                           "x86_64-unknown-linux-gnu", "--no-self-update"]
    stage.write_text("exact toolchain install invoked")
    sys.exit(78 if os.environ["PROOF_DRIVER_FIXTURE"] == "rustup-install-failed" else 0)
assert sys.argv[1:] == ["run", "1.95.0", "rustc", "--version", "--verbose"]
assert stage.read_text() == "exact toolchain install invoked"
stage.write_text("rustc probe invoked after install success")
sys.exit(79)
''')
        home = root / "fresh-home"
        home.mkdir()
        environment = {"PATH": f"{tools}:/usr/bin:/bin", "LC_ALL": "C", "HOME": str(home),
                       "CARGO_HOME": str(home / ".cargo"), "RUSTUP_HOME": str(home / ".rustup"),
                       "TMPDIR": str(run_temp if case == "test-home-under-system-temp" else system_temp),
                       "CODEX_TEST_ARG0_HOME_BASE": str(system_temp),
                       "PROOF_DRIVER_FIXTURE": case, "PROOF_FIXTURE_PATCH": str(source)}
        result = subprocess.run(["/bin/bash", str(DRIVER), str(run_temp)], cwd=work, env=environment,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(list((run_temp / "codex-receipt-output").glob("*")), [])
        return result, sentinel

    def stand_in(self, path, source):
        path.write_text(f"#!{sys.executable}\n{source}")
        path.chmod(0o700)

    def test_valid_source_installs_without_self_update_then_probes_rustc(self):
        result, sentinel = self.run_driver("valid")
        self.assertEqual(result.returncode, 79, result.stderr)
        self.assertEqual(sentinel.read_text(), "rustc probe invoked after install success")

    def test_failed_toolchain_install_refuses_before_rustc_probe(self):
        result, sentinel = self.run_driver("rustup-install-failed")
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertEqual(sentinel.read_text(), "exact toolchain install invoked")

    def test_provenance_command_errors_refuse_even_with_valid_looking_output(self):
        for case, code in (("write-tree-failed", 41), ("rev-parse-failed", 42)):
            with self.subTest(case=case):
                result, sentinel = self.run_driver(case)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(sentinel.exists())

    def test_unverified_lock_refuses_before_rustup(self):
        result, sentinel = self.run_driver("lock-unverified")
        self.assertEqual(result.returncode, 45, result.stderr)
        self.assertFalse(sentinel.exists())

    def test_invalid_fixture_patch_refuses_before_rustup(self):
        for case, code in (("test-home-patch-digest", 47), ("test-home-patch-drift", 46)):
            with self.subTest(case=case):
                result, sentinel = self.run_driver(case)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(sentinel.exists())

    def test_fixture_base_under_system_temp_refuses_before_rustup(self):
        result, sentinel = self.run_driver("test-home-under-system-temp")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("outside the system temp root", result.stderr)
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
