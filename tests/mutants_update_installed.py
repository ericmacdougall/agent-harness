"""Mutation controls for tests/test_update_installed.py (goodqa#16947): each mutant breaks one refusal or derivation
of scripts/update_installed.py and the named test must FAIL against it. Run from the repository root:

    python3 tests/mutants_update_installed.py

Each mutant runs in a temporary copy (the real file is never edited). Exit 1 if any survives or no longer applies.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join("scripts", "update_installed.py")
T = "tests.test_update_installed."
MUTANTS = [
    ("a commit off origin/main is accepted",
     '        raise Stop("%s is not on origin/main; nothing was changed" % commit)',
     '        pass',
     T + "Refusals.test_commit_not_on_main_is_refused"),
    ("a dirty clone is accepted",
     '        raise Stop("%s has local changes or untracked files; nothing was changed" % repo)',
     '        pass',
     T + "Refusals.test_dirty_clone_is_refused"),
    ("preview goes on to install",
     '            print("Preview only: nothing was installed.")\n            return 0',
     '            print("Preview only: nothing was installed.")',
     T + "Preview.test_preview_writes_nothing"),
    ("installed files are never compared",
     '            if file_sha(Path(home) / ".claude" / rel) != blob_sha(repo, commit, "harness/" + rel):',
     '            if False:',
     T + "FileList.test_file_list_is_derived_from_the_installed_files"),
    ("a symlinked install counts as current",
     '    if p.is_symlink() or not p.is_file():',
     '    if not p.is_file():',
     T + "FileList.test_file_list_is_derived_from_the_installed_files"),
    ("every remote hook is sent, changed or not",
     '    return [n for n in hooks if (plan[n] or {}).get("action") != "already_current"]',
     '    return list(hooks)',
     T + "FileList.test_file_list_is_derived_from_the_installed_files"),
    ("the remote is not re-checked after the install",
     '            left = remote_changes(a.home, h, commit, lists["hooks"], runner)',
     '            left = []',
     T + "RealRun.test_a_remote_file_still_different_after_the_install_stops"),
]


def main() -> int:
    src = open(os.path.join(ROOT, TARGET)).read()
    bad = 0
    for name, old, new, test in MUTANTS:
        if src.count(old) != 1:
            print("STALE    %s" % name)
            bad += 1
            continue
        tmp = tempfile.mkdtemp(prefix="update-installed-mutant-")
        try:
            shutil.copytree(os.path.join(ROOT, "scripts"), os.path.join(tmp, "scripts"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"))
            with open(os.path.join(tmp, TARGET), "w") as fh:
                fh.write(src.replace(old, new))
            r = subprocess.run([sys.executable, "-m", "unittest", test], cwd=tmp, capture_output=True, text=True,
                               timeout=900)
            bad += r.returncode == 0
            print("%s %s (%s)" % ("KILLED  " if r.returncode else "SURVIVED", name, test.rsplit(".", 1)[-1]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("%d of %d mutants survived or were stale" % (bad, len(MUTANTS)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
