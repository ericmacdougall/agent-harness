"""Mutation controls for tests/test_checkout_inventory.py (goodqa#16947). Each mutant removes one safety control of
scripts/checkout_inventory.py, and the named test must FAIL against it. Run from the repository root:

    python3 tests/mutants_checkout_inventory.py

Each mutant runs in a temporary copy of scripts/ and tests/; the real files are never edited. A baseline over every
named test runs first. Exit 1 if the baseline fails, or any mutant survives or no longer applies.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join("scripts", "checkout_inventory.py")
T = "tests.test_checkout_inventory."
MUTANTS = [
    ("the checkout's fsmonitor and hooks may run",
     'GIT_FLAGS = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false"]',
     'GIT_FLAGS = []',
     T + "Safety.test_repo_config_never_starts_a_program"),
    ("git status may rewrite the index",
     'GIT_ENV.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", LC_ALL="C")',
     'GIT_ENV.update(GIT_TERMINAL_PROMPT="0", LC_ALL="C")',
     T + "Safety.test_status_does_not_rewrite_the_index"),
    ("a redirecting GIT_DIR reaches git",
     'GIT_ENV = {k: v for k, v in os.environ.items() if k not in _REDIRECT and not k.startswith("GIT_CONFIG_")}',
     'GIT_ENV = dict(os.environ)',
     T + "Safety.test_a_redirecting_environment_does_not_change_which_repo_is_read"),
    ("credentials in the origin URL are printed",
     '            note.append("origin=" + (redact_url(out.strip()) if rc == 0 else "none"))',
     '            note.append("origin=" + (out.strip() if rc == 0 else "none"))',
     T + "Safety.test_credentials_in_the_origin_url_are_never_printed"),
    ("unpushed commits are counted from HEAD only on a whole clone",
     '"rev-list", "--count", "--branches", "--tags", "--not", "--remotes"',
     '"rev-list", "--count", "HEAD", "--not", "--remotes"',
     T + "Rows.test_unpushed_commits_on_other_local_branches_are_counted_on_the_main_row"),
    ("a missing worktree is skipped",
     '        exists = os.path.isdir(path)',
     '        exists = os.path.isdir(path)\n        if not exists:\n            continue',
     T + "Rows.test_a_missing_worktree_folder_is_reported_not_skipped"),
    ("a linked worktree is listed again on its own",
     '            if common in seen:\n                continue',
     '            if False:\n                continue',
     T + "Rows.test_main_and_linked_worktree_rows"),
]


def copy(tmp):
    shutil.copytree(os.path.join(ROOT, "scripts"), os.path.join(tmp, "scripts"))
    shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"))


def run(tmp, tests):
    return subprocess.run([sys.executable, "-m", "unittest", *tests], cwd=tmp, capture_output=True, text=True,
                          timeout=900)


def main() -> int:
    src = open(os.path.join(ROOT, TARGET)).read()
    tmp = tempfile.mkdtemp(prefix="checkout-inventory-baseline-")
    try:
        copy(tmp)
        base = run(tmp, sorted({m[3] for m in MUTANTS}))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("baseline (unmutated copy, every named test): %s" % ("PASS" if base.returncode == 0 else "FAIL"))
    if base.returncode or "skipped" in base.stderr:
        print(base.stderr[-2000:])
        print("a named test fails or skips without any mutant, so KILLED would mean nothing")
        return 1
    bad = 0
    for name, old, new, test in MUTANTS:
        if src.count(old) != 1:
            print("STALE    %s" % name)
            bad += 1
            continue
        tmp = tempfile.mkdtemp(prefix="checkout-inventory-mutant-")
        try:
            copy(tmp)
            with open(os.path.join(tmp, TARGET), "w") as fh:
                fh.write(src.replace(old, new))
            r = run(tmp, [test])
            bad += r.returncode == 0
            print("%s %s (%s)" % ("KILLED  " if r.returncode else "SURVIVED", name, test.rsplit(".", 1)[-1]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("%d of %d mutants survived or were stale" % (bad, len(MUTANTS)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
