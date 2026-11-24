"""Shared runner for the hook mutant scripts (tests/mutants_*.py): copy the hooks and the whole tests directory into a
temporary tree, apply one controlled break at a time, and run one test module there.

The rule every run follows (goodqa#17059, after a run whose every "kill" was an import error):
1. The unmutated copy runs first as a control and must pass; otherwise the run stops and reports the tree as broken.
2. A mutant counts as killed only when the same number of tests ran as in the control and at least one test reported
   FAIL or ERROR. An import error, a missing fixture or a crash is reported as a broken tree, never as a kill.
3. A mutant whose text is not found in the file is reported as not applied and fails the run.

Changes nothing outside the temporary trees."""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def tree():
    tmp = Path(tempfile.mkdtemp(prefix='mutant-'))
    shutil.copytree(ROOT / 'harness' / 'hooks', tmp / 'harness' / 'hooks', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(ROOT / 'tests', tmp / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
    return tmp


def unittest_run(tmp, module):
    done = subprocess.run([sys.executable, '-B', '-m', 'unittest', module], cwd=str(tmp), capture_output=True, text=True)
    ran = re.search(r'^Ran (\d+) test', done.stderr, re.M)
    failed = [ln for ln in done.stderr.splitlines() if ln.startswith(('FAIL:', 'ERROR:'))]
    return done.returncode, int(ran.group(1)) if ran else 0, failed


def judge(tmp, module, label, expect_ran):
    rc, ran, failed = unittest_run(tmp, module)
    killed = rc != 0 and ran == expect_ran and bool(failed)
    verdict = 'FAILS (good)' if killed else 'PASSES (test is vacuous)' if rc == 0 else 'BROKEN TREE (ran %d)' % ran
    print('%-60s %s' % (label, verdict))
    for line in failed:
        print('    ' + line)
    return killed


def run(module, hook, mutants, base=None):
    """Run `module` against the control, the hook file at commit `base` (when given) and each mutant of `hook`
    (a file name in harness/hooks). `mutants` maps a label to a list of (old, new) text replacements. Returns the exit
    status for the script: 0 only when the control passes and every case is killed."""
    tmp = tree()
    try:
        rc, expect_ran, failed = unittest_run(tmp, module)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%-60s %s' % ('control: unmutated copy', 'PASSES, %d tests' % expect_ran if rc == 0 else 'FAILS'))
    if rc != 0 or expect_ran == 0:
        for line in failed:
            print('    ' + line)
        return 1
    bad = 0
    if base:
        tmp = tree()
        try:
            text = subprocess.run(['git', '-C', str(ROOT), 'show', '%s:harness/hooks/%s' % (base, hook)],
                                  capture_output=True, check=True).stdout
            (tmp / 'harness' / 'hooks' / hook).write_bytes(text)
            bad += 0 if judge(tmp, module, 'base %s' % base, expect_ran) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    for label, edits in mutants.items():
        tmp = tree()
        try:
            path = tmp / 'harness' / 'hooks' / hook
            text = path.read_text()
            if any(old not in text for old, _ in edits):
                print('MUTANT NOT APPLIED:', label)
                bad += 1
                continue
            for old, new in edits:
                text = text.replace(old, new, 1)
            path.write_text(text)
            bad += 0 if judge(tmp, module, label, expect_ran) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print('mutants not killed or not applied:', bad)
    return 1 if bad else 0
