"""goodqa#15876 failing-first evidence: tests.test_guard_selftest must fail against origin/main (no module) and against each controlled
broken variant of guard_selftest.py.

Run: python3 -B tests/mutants_guard_selftest.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_guard_selftest"
TARGET = "guard_selftest.py"

MUTANTS = {
    "the installed-copy check is removed": ("            if cli and module_dir != installed_dir(home):", "            if False:"),
    "print-manifest skips the installed-copy check": ("            if module_dir != installed_dir(user_home()):", "            if False:"),
    "the manifest check is removed": ("            if digest != expect_manifest:", "            if False:"),
    "the policy check is removed": ("            if policy != expect_policy:", "            if False:"),
    "an unknown mode is guessed": ("        if modes[rule] not in (\"warn\", \"enforce\"):\n            raise Refused", "        if False:\n            raise Refused"),
    "the identity check before removal is removed": ("    if (now.st_dev, now.st_ino) != ident or (under.st_dev, under.st_ino) != ident or not stat.S_ISDIR(under.st_mode):",
                                                   "    if False:"),
    "a symlink inside is followed": ("        st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)", "        st = os.stat(entry.name, dir_fd=fd, follow_symlinks=True)"),
    "the private parent is not checked": ("    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:", "    if False:"),
    "abbreviations are accepted": ("allow_abbrev=False", "allow_abbrev=True"),
    "the hook environment is inherited": ("def hook_env(git, home):\n    return {", "def hook_env(git, home):\n    return dict(os.environ) or {"),
    "the table is not compared": ("    if got[\"timed_out\"] or got[\"exit\"] is None:\n        return False\n    if kind == \"quiet\":",
                                  "    return True\n    if kind == \"quiet\":"),
    "a timeout counts as a pass": ("    if got[\"timed_out\"] or got[\"exit\"] is None:\n        return False\n    if kind == \"quiet\":",
                                   "    if got[\"timed_out\"] or got[\"exit\"] is None:\n        return True\n    if kind == \"quiet\":"),
    "stderr is ignored in a quiet case": ("        return got[\"exit\"] == 0 and got[\"stdout\"].strip() == \"\" and got[\"stderr\"].strip() == \"\"",
                                          "        return got[\"exit\"] == 0 and got[\"stdout\"].strip() == \"\""),
    "a warn case ignores stderr": ("    if got[\"exit\"] != 0 or got[\"stderr\"].strip():\n        return False  # any stderr note",
                                   "    if got[\"exit\"] != 0:\n        return False  # any stderr note"),
    "enforce expectations are not mode aware": ("    if mode == \"enforce\":\n        return got[\"exit\"] == 2", "    if False:\n        return got[\"exit\"] == 2"),
    "the audit values are not bounded": ("def _bound(value):\n    return re.sub(r\"[^\\x20-\\x7e]\", \"?\", str(value))[:80]", "def _bound(value):\n    return str(value)"),
    "the child is started with a shell": ("    argv = [sys.executable, \"-I\", str(Path(hooks_dir) / LAUNCHER), \"hook\"]",
                                          "    argv = [sys.executable, str(Path(hooks_dir) / LAUNCHER), \"hook\"]"),
    "this tool is not pinned": ('PINNED = ("command_guard.py", "command_guard_hook.py", "guard_selftest.py", "redact.py", "safe_input.py")',
                                'PINNED = ("command_guard.py", "command_guard_hook.py", "redact.py", "safe_input.py")'),
    "a policy symlink reads as absent": ("    if not stat.S_ISREG(st.st_mode):\n        raise Refused(\"the policy file is not a regular file\")", "    pass"),
    "an OS error escapes as a traceback": ("        except OSError as error:\n            result.update(ok=False, exit_code=4", "        except KeyError as error:\n            result.update(ok=False, exit_code=4"),
    "the cleanup is skipped on an error": ("            if created.get(\"dir_fd\") is not None:\n                try:\n                    remove_own_directory",
                                           "            if False:\n                try:\n                    remove_own_directory"),
}


def run(tmp, label):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print("%-52s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_guard_selftest.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        (tmp / "harness" / "hooks" / TARGET).unlink()  # origin/main has no module
        bad += 0 if run(tmp, "origin/main (no module)") else 1
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
