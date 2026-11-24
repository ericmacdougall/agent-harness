"""Mutation controls for the stream D janitor tests (goodqa#16947): each mutant breaks one safety rule of
workspace_janitor.py and the named test must FAIL against it. Run from the repository root:

    python3 tests/mutants_workspace_janitor_ownership.py

Copies the tree into a temporary folder per mutant (the real file is never edited), applies one text substitution,
runs one test and reports KILLED (the test failed, good) or SURVIVED (the test passed: the test is vacuous). Exit 1 if any
mutant survives or a substitution no longer applies.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join("harness", "hooks", "workspace_janitor.py")
T = "tests.test_workspace_janitor."
MUTANTS = [
    ("build output outside a checkout counts as regenerable",
     'if d == "node_modules" and regular(os.path.join(dp, "package.json")):',
     'if d in ("node_modules", "build", "dist", "out", "target", ".cache", "__pycache__"):',
     T + "Regenerable.test_build_output_outside_a_checkout_is_kept"),
    ("node_modules needs no package.json",
     'if d == "node_modules" and regular(os.path.join(dp, "package.json")):',
     'if d == "node_modules":',
     T + "Regenerable.test_node_modules_without_a_package_json_and_venv_without_pyvenv_cfg_are_kept"),
    ("venv needs no pyvenv.cfg",
     'if d in (".venv", "venv") and regular(os.path.join(full, "pyvenv.cfg")):',
     'if d in (".venv", "venv"):',
     T + "Regenerable.test_node_modules_without_a_package_json_and_venv_without_pyvenv_cfg_are_kept"),
    ("symlinked folders are candidates",
     'if (full + "/").startswith(inside) or d == ".git" or os.path.islink(full):',
     'if (full + "/").startswith(inside) or d == ".git":',
     T + "Regenerable.test_symlinked_node_modules_is_not_followed"),
    ("a nested repository inside node_modules is ignored",
     'if d == "node_modules" and regular(os.path.join(dp, "package.json")):\n                if not S._has_nested_repo(full):',
     'if d == "node_modules" and regular(os.path.join(dp, "package.json")):\n                if True:',
     T + "Regenerable.test_node_modules_holding_a_repository_is_kept"),
    ("regenerable removal runs without the caller's ownership flag",
     "    if regenerable and S.within_allowed(path)",
     "    if S.within_allowed(path)",
     T + "Regenerable.test_without_the_regenerable_flag_nothing_outside_checkouts_is_touched"),
    ("report-only removes regenerable folders",
     '            if deleting:\n                done, err = C.safe_remove(d, "tree", cfg)',
     '            if True:\n                done, err = C.safe_remove(d, "tree", cfg)',
     T + "Regenerable.test_report_only_lists_and_removes_nothing"),
    ("Codex WALs are not read",
     '"codex": os.path.join(S.home(), ".agent-harness", "codex-wals", sid)}',
     '"codex": os.path.join(S.home(), ".agent-harness", "no-such-codex-wals", sid)}',
     T + "Ownership.test_codex_session_with_a_fresh_codex_wal_is_kept"),
    ("transcripts are not read",
     "        for t in _transcripts(sid):",
     "        for t in []:",
     T + "Ownership.test_fresh_transcript_keeps_a_session_whose_wal_is_old"),
    ("only the file time of a WAL counts",
     "            if stamp is not None:\n                out.append(stamp)",
     "            if False:\n                out.append(stamp)",
     T + "Ownership.test_backdated_wal_with_a_fresh_row_stamp_is_kept"),
    ("open asks are ignored",
     '            elif asks:\n                reasons.append("open_work")',
     '            elif False:\n                reasons.append("open_work")',
     T + "Ownership.test_open_ask_keeps_and_a_resolved_ask_does_not"),
    ("an unreadable task ledger means no tasks",
     '    if tasks is None:\n        reasons.append("tasks_unreadable")',
     '    if False:\n        reasons.append("tasks_unreadable")',
     T + "Ownership.test_open_task_keeps_and_an_unreadable_task_ledger_keeps_everything"),
    ("two WAL flavors are accepted",
     '    if len(flavors) > 1:\n        reasons.append("ambiguous_session")',
     '    if False:\n        reasons.append("ambiguous_session")',
     T + "Ownership.test_session_in_both_wal_flavors_is_ambiguous_and_kept"),
    ("live bg jobs are ignored",
     "    if _bg_jobs_live(sid, blob):",
     "    if False:",
     T + "Ownership.test_live_bg_job_keeps"),
    ("the release CLI skips the verdict",
     "        if sid and not own:",
     "        if False:",
     T + "Ownership.test_release_cli_refuses_a_session_that_is_not_retired_and_session_end_may_release_its_own"),
    ("no process list means retired",
     '    if blob is None:\n        return ["no_process_list"]',
     '    if blob is None:\n        return []',
     T + "Ownership.test_no_process_list_keeps_every_session"),
]


def main() -> int:
    src = open(os.path.join(ROOT, TARGET)).read()
    bad = 0
    for name, old, new, test in MUTANTS:
        if src.count(old) != 1:
            print("STALE    %s: the substitution no longer applies exactly once" % name)
            bad += 1
            continue
        tmp = tempfile.mkdtemp(prefix="janitor-mutant-")
        try:
            shutil.copytree(os.path.join(ROOT, "harness"), os.path.join(tmp, "harness"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"))
            with open(os.path.join(tmp, TARGET), "w") as fh:
                fh.write(src.replace(old, new))
            r = subprocess.run([sys.executable, "-m", "unittest", test], cwd=tmp, capture_output=True, text=True,
                               timeout=600)
            verdict = "KILLED  " if r.returncode != 0 else "SURVIVED"
            bad += r.returncode == 0
            print("%s %s (%s)" % (verdict, name, test.rsplit(".", 1)[-1]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("%d of %d mutants survived or were stale" % (bad, len(MUTANTS)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
