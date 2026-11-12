"""goodqa#15759 failing-first evidence: the tests must fail against the code WITHOUT the fix (origin/main) and against each broken variant.

Run: python3 -B tests/mutants_scp_dest.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_command_guard_scp_dest"
GUARD = "command_guard.py"

MUTANTS = {
    "scp not dispatched": ("'rsync', 'scp', 'rclone'", "'rsync', 'rclone'"),
    "scp branch does nothing": ("elif name == 'scp':\n            self.remote_copy_dest(name, nd)", "elif name == 'scp':\n            pass"),
    "rsync not checked": ("elif name == 'rsync':\n            self.remote_copy_dest(name, nd)\n", "elif name == 'rsync':\n"),
    "relative remote path not read as home": ("if not path.startswith(('/', '~')):\n            path = '~/' + path", "if False:\n            path = '~/' + path"),
    "directory destination ignores the sources": ("if base and not self._remote_spec(source.text):", "if False:"),
    "scp url not read": ("if text.startswith('scp://'):", "if False:"),
}


def run(tmp, label):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print("%-42s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_command_guard_scp_dest.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(["git", "-C", str(ROOT), "show", "origin/main:harness/hooks/" + GUARD], capture_output=True, check=True).stdout
        (tmp / "harness" / "hooks" / GUARD).write_bytes(base)
        bad += 0 if run(tmp, "origin/main (no fix)") else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / GUARD
            text = path.read_text()
            if old not in text:
                print("MUTANT NOT APPLIED:", name)
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
