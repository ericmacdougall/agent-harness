"""goodqa#15870 failing-first evidence: tests.test_worktree_inuse must fail against command_guard.py WITHOUT the change
(origin/main) and against each controlled broken variant.

Run: python3 -B tests/mutants_worktree_inuse.py   (copies the hooks and the tests into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_worktree_inuse"
GUARD = "command_guard.py"

MUTANTS = {
    "an unreadable process always blocks": ("if int(entry) in ancestors or unreadable_verdict(entry, status['name'], path, created) is None:", "if False:"),
    "the scanner's ancestors are not excluded": ("if int(entry) in ancestors or unreadable_verdict(", "if unreadable_verdict("),
    "known helpers are not exempt": ("            return None  # a known long-lived helper: skipped whatever its start time", "            pass"),
    "known helpers matched by name only": ("if base == helper and marker in (' ' + args + ' ' if marker.startswith(' ') else args):", "if base == helper:"),
    "an unreadable process is always skipped": ("    base = (name or '').strip().lower()\n    args = _proc_args(pid)", "    return None\n    base = (name or '').strip().lower()\n    args = _proc_args(pid)"),
    "the command line is ignored": ("if path in args or os.path.realpath(path) in args:", "if False:"),
    "shells and wrappers are skipped": ("    if base in UNREADABLE_ALWAYS_REFUSES:", "    if False:"),
    "the start time is ignored": ("if started is None or created is None or started >= created:", "if False:"),
    "unknown times are skipped": ("if started is None or created is None or started >= created:", "if started is not None and created is not None and started >= created:"),
    "skipped processes are not reported": ("report['skipped_processes'] = ['pid", "report['skipped_processes'] = [] and ['pid"),
    "a readable cwd inside the worktree is ignored": ("if cwd == path or cwd.startswith(path + os.sep):", "if False:"),
    "the ignored-file refusal does not list the paths": ("% (', '.join(shown) or '?', ", "% ('?', "),
    "creation time unreadable": ("return os.lstat(os.path.join(path, '.git')).st_mtime", "return None"),
}


def run(tmp, label):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print("%-48s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    for name in ("test_worktree_inuse.py", "test_ah_worktree_remove.py"):
        shutil.copy(ROOT / "tests" / name, tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(["git", "-C", str(ROOT), "show", "origin/main:harness/hooks/" + GUARD], capture_output=True, check=True).stdout
        (tmp / "harness" / "hooks" / GUARD).write_bytes(base)
        bad += 0 if run(tmp, "origin/main (no change)") else 1
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
