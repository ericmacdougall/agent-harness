"""goodqa#15827 follow-up failing-first evidence: the capabilities tests must fail against ops_watch.py WITHOUT the subcommand
(the parent commit) and against each controlled broken variant.

Run: python3 -B tests/mutants_ops_capabilities.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_ops_watch_capabilities"
TARGET = "ops_watch.py"

MUTANTS = {
    "capability not listed": ('        caps.append("forward-foreign-critical")', '        pass'),
    "listed without checking the code": ('    if callable(globals().get("forward_foreign")) and callable(globals().get("queue_events")):',
                                         '    if True:'),
    "decorated line": ('        caps.append("forward-foreign-critical")', '        caps.append("forward-foreign-critical v1")'),
    "subcommand exits non-zero": ('        print("\\n".join(capabilities()))\n        return 0', '        print("\\n".join(capabilities()))\n        return 1'),
    "probe loads config and state": ('    if cmd == "capabilities":  # no config, no state, no ring: a pure probe\n',
                                     '    if cmd == "capabilities":  # no config, no state, no ring: a pure probe\n        save_state(home, {})\n'),
    "duplicate line": ('    caps = ["emit"]', '    caps = ["emit", "emit"]'),
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
    shutil.copy(ROOT / "tests" / "test_ops_watch_capabilities.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(["git", "-C", str(ROOT), "show", "a810795d:harness/hooks/" + TARGET], capture_output=True, check=True).stdout
        (tmp / "harness" / "hooks" / TARGET).write_bytes(base)
        bad += 0 if run(tmp, "a810795d (no subcommand)") else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / TARGET
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
