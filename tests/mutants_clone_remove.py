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
    "no cutoff": ("elif info.st_ctime_ns > cutoff_ns:", "elif False:",
                  ["review:VerifiedTree.test_a_touched_but_verified_directory_is_still_emptied_and_a_new_file_in_it_is_kept",
                   "Removal.test_a_file_written_after_verification_survives_even_through_resume"]),
    "verified directory set ignored": ("if (info.st_dev, info.st_ino) not in allowed_dirs:", "if False:",
                                       ["review:VerifiedTree.test_a_directory_outside_the_verified_set_is_kept_whole_on_any_walk",
                                        "review:Rollback.test_resume_never_deletes_what_the_first_run_kept"]),
    "directory set not checked on resume": (["if hashlib.sha256(raw).hexdigest() != sha256:", "if len(pairs) != count:"], ["if False:", "if False:"],
                                            ["review:Rollback.test_a_missing_or_altered_directory_set_refuses_resume"]),
    "directories judged by ctime again": ("if (info.st_dev, info.st_ino) not in allowed_dirs:", "if info.st_ctime_ns > cutoff_ns:",
                                          ["Removal.test_an_interrupted_walk_is_finished_by_resume"]),
    "hook-form accepts a partial clone": ("if not allow_partial_clone and ((section == 'remote'", "if False and ((section == 'remote'",
                                          ["review:Rollback.test_the_hook_form_exemption_refuses_a_partial_clone_by_its_keys_without_the_network"]),
    "directory set taken at the end of verification": (["        verified_dirs = dir_inodes(path)\n", "dirs=verified_dirs)"], ["        verified_dirs = None\n", "dirs=dir_inodes(path))"],
                                                       ["review:Rollback.test_a_directory_moved_in_while_verification_runs_is_kept"]),
    "hook-form promisor value 2 accepted": ("value.strip().lower() not in _FALSE_WORDS))", "value.strip().lower() in _TRUE_WORDS))",
                                            ["review:Rollback.test_any_promisor_value_git_reads_as_true_refuses_in_the_hook_form"]),
    "hook-form linked route accepts a partial clone": ("bad = _config_refusal(shared, allow_worktree_config=True)", "bad = _config_refusal(shared, allow_worktree_config=True, allow_partial_clone=True)",
                                                       ["review:Rollback.test_a_linked_worktree_of_a_partial_clone_is_refused_by_the_reclaim_route"]),
    "remote-auth passes no credential helper": ("    if authenticated is True:\n        gh = shutil.which", "    if False:\n        gh = shutil.which",
                                                ["review:RemoteAuth.test_the_authenticated_listing_names_one_host_scoped_helper_and_the_anonymous_one_none"]),
    "credential helper not scoped to the host": ("'credential.https://github.com.helper=!%s auth git-credential' % gh", "'credential.helper=!%s auth git-credential' % gh",
                                                 ["review:RemoteAuth.test_the_authenticated_listing_names_one_host_scoped_helper_and_the_anonymous_one_none"]),
    "session gate always refuses": ("def require_session(session, home):\n", "def require_session(session, home):\n    refuse('always')\n",
                                    ["review:Identity.test_the_command_gets_past_the_session_gate_for_a_real_session"]),
    "session gate never refuses": ("        if os.path.islink(path) or not os.path.isdir(path):\n            refuse('the session has no", "        if False:\n            refuse('the session has no",
                                   ["review:Identity.test_a_session_without_its_wal_or_work_directory_is_refused",
                                    "review:ParentEnvironment.test_the_real_ah_refuses_a_missing_or_unknown_session_in_a_real_process"]),
    "duplicate session variable accepted": ("if len(values) != 1 or not values[0]:", "if not values or not values[0]:",
                                            ["review:ParentEnvironment.test_a_missing_process_and_a_duplicate_variable_read_as_none"]),
    "arguments parsed as environment": ("for item in parts[argc:]:", "for item in parts[1:]:",
                                        ["review:ParentEnvironment.test_the_buffer_parser_separates_arguments_from_the_environment",
                                         "review:ParentEnvironment.test_the_command_line_is_never_read_only_the_environment"]),
    "missing directory set crashes": ("if not isinstance(sha256, str) or not isinstance(count, int):", "if False:",
                                      ["review:IntentFields.test_an_intent_row_without_a_directory_set_refuses_with_a_clone_error"]),
    "directory set file kept": ("                os.unlink(dirs_path(home, audit_id))  # the directory set has done its job once the removal is recorded", "                pass",
                                ["review:IntentFields.test_the_directory_set_file_is_deleted_once_the_removal_is_recorded_and_kept_until_then"]),
    "unwritable marker not restored": ("            _restore(parent, qname, intent, ident)\n            _result_row(", "            raise\n            _result_row(",
                                       ["review:Rollback.test_an_unwritable_marker_puts_the_clone_back_and_records_it"]),
    "relative alternates mis-resolved": ("os.path.join(os.path.dirname(os.path.dirname(candidate)), line))", "os.path.join(os.path.dirname(candidate), line))",
                                         ["review:Rollback.test_a_relative_alternates_entry_is_resolved_against_objects"]),
    "token userinfo accepted": ("re.compile(r'^(?:https?|git)://", "re.compile(r'^(?:nomatch)://", ["review:Rollback.test_a_token_as_the_only_userinfo_refuses"]),
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
            shutil.copy(ROOT / "tests" / "test_ah_clone_remove_review.py", tmp / "tests")
            for extra in ("install.py", "install_codex.py"):
                shutil.copy(ROOT / extra, tmp / extra)
            target = tmp / "harness" / "hooks" / ("command_guard.py" if name.startswith("hook-form") else "ah.py" if name.startswith("ah-") else "clone_remove.py")
            text = target.read_text()
            olds, news = (old, new) if isinstance(old, list) else ([old], [new])
            if any(o not in text for o in olds):
                print("MUTANT NOT APPLIED:", name)
                failures += 1
                continue
            for o, n in zip(olds, news):
                text = text.replace(o, n, 1)
            target.write_text(text)
            done = subprocess.run([sys.executable, "-B", "-m", "unittest"] + [("tests.test_ah_clone_remove_review." + t[7:]) if t.startswith("review:") else ("tests.test_ah_clone_remove." + t) for t in tests],
                                  cwd=str(tmp), capture_output=True, text=True)
            killed = done.returncode != 0
            print("%-36s %s" % (name, "KILLED" if killed else "SURVIVED (test is vacuous)"))
            failures += 0 if killed else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
