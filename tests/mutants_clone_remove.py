"""Controlled broken variants of clone_remove.py (goodqa#15743): each one must make a named test fail.

Run: python3 -B tests/mutants_clone_remove.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# name -> (old text, new text, tests that must fail)
MUTANTS = {
    "no protocol denial": ("'-c', 'protocol.allow=never', '-C', repo]", "'-C', repo]",
                           ["FullAndPartialClone.test_partial_clone_is_removable_and_every_git_call_denies_the_network",
                            "FullAndPartialClone.test_the_runner_never_contacts_the_remote_for_a_missing_object"]),
    "lazy fetch left on": ("env['GIT_NO_LAZY_FETCH'] = '1'", "env['GIT_NO_LAZY_FETCH'] = '0'",
                           ["FullAndPartialClone.test_partial_clone_is_removable_and_every_git_call_denies_the_network"]),
    "symlink followed": ("info = os.lstat(name, dir_fd=frame['fd'])", "info = os.stat(name, dir_fd=frame['fd'])",
                         ["Walk.test_a_symlink_is_removed_as_a_link_and_its_target_survives"]),
    "no cutoff": ("info.st_ctime_ns) > cutoff_ns:", "info.st_ctime_ns) > 2 ** 62:",
                  ["Walk.test_an_entry_newer_than_the_cutoff_is_kept_and_a_newer_directory_is_kept_whole",
                   "Removal.test_a_file_written_after_verification_survives_even_through_resume"]),
    "device crossed": ("if info.st_dev != dev:", "if False:", ["Walk.test_a_second_device_is_not_crossed"]),
    "intent row not required": ("raise CloneError('refused', 'the audit row could not be written (%s); nothing was changed' % type(error).__name__)",
                                "pass", ["Removal.test_the_intent_row_must_be_written_before_anything_moves"]),
    "no refs re-read in quarantine": ("if again != verdict['snapshot']:", "if False:",
                                      ["Removal.test_refs_that_differ_inside_the_quarantine_rename_it_back_without_a_marker"]),
    "resume ignores the marker": ("    if minfo.st_ino != markers[0].get('marker_ino') or content.get('audit_id') != audit_id \\\n            or content.get('snapshot_sha256') != intent.get('snapshot_sha256'):",
                                  "    if False:", ["Removal.test_resume_refuses_a_forged_or_mismatched_quarantine"]),
    "resume ignores the inode": (["if (info.st_dev, info.st_ino) != (intent['dev'], intent['ino']) or (parent.st_dev, parent.st_ino) != (intent['parent_dev'], intent['parent_ino']):",
                                  "if _fd_ident(qfd) != (ident['dev'], ident['ino']):"],
                                 ["if False:", "if False:"], ["Removal.test_resume_refuses_when_the_recorded_inode_is_not_the_quarantine"]),
    "pull merge refs accepted": ("re.fullmatch(r'refs/pull/\\d+/head', ref)", "re.fullmatch(r'refs/pull/\\d+/(head|merge)', ref)",
                                 ["UnsafeStates.test_a_commit_known_only_through_a_pull_head_counts_but_a_pull_merge_ref_does_not"]),
    "reflog ignored": ("shas = _reflog_shas(path) | {head}", "shas = {head}",
                       ["UnsafeStates.test_each_unsafe_state_refuses_and_a_clean_clone_does_not"]),
    "alternates scan off": ("alternates_scan(os.path.join(work_root(home), session), path)", "pass",
                            ["Scope.test_a_repository_borrowing_objects_from_the_target_refuses"]),
    "ignored by local exclude accepted": ("code, out = run_git(path, ['check-ignore', '-v', '--no-index', '--', name.rstrip('/')], 10.0, check=False)",
                                          "code, out = 0, '.gitignore:1:x\\ty'",
                                          ["UnsafeStates.test_each_unsafe_state_refuses_and_a_clean_clone_does_not"]),
    "foreign session accepted": ("if parent != receipts or not name.startswith('wt-')", "if not name.startswith('wt-')",
                                 ["Scope.test_paths_outside_the_scope_refuse_before_anything_is_touched"]),
    "byte-for-byte check off": ("if part not in names:", "if False:", ["Scope.test_a_case_variant_spelling_refuses_when_the_filesystem_folds_case"]),
    "credential url accepted": ("if CREDENTIAL_URL.search(url):", "if False:", ["UnsafeStates.test_a_remote_url_with_a_credential_refuses_and_leaks_nowhere"]),
}


def main():
    failures = 0
    for name, (old, new, tests) in MUTANTS.items():
        with tempfile.TemporaryDirectory(prefix="mutant-") as tmp:
            tmp = Path(tmp)
            shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
            (tmp / "tests").mkdir()
            shutil.copy(ROOT / "tests" / "test_ah_clone_remove.py", tmp / "tests")
            for extra in ("install.py", "install_codex.py"):
                shutil.copy(ROOT / extra, tmp / extra)
            target = tmp / "harness" / "hooks" / "clone_remove.py"
            text = target.read_text()
            olds, news = (old, new) if isinstance(old, list) else ([old], [new])
            if any(o not in text for o in olds):
                print("MUTANT NOT APPLIED:", name)
                failures += 1
                continue
            for o, n in zip(olds, news):
                text = text.replace(o, n, 1)
            target.write_text(text)
            done = subprocess.run([sys.executable, "-B", "-m", "unittest"] + ["tests.test_ah_clone_remove." + t for t in tests],
                                  cwd=str(tmp), capture_output=True, text=True)
            killed = done.returncode != 0
            print("%-36s %s" % (name, "KILLED" if killed else "SURVIVED (test is vacuous)"))
            failures += 0 if killed else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
