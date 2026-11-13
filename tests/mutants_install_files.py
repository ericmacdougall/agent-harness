"""Controlled broken variants of ah_install.py and the guard rule (goodqa#15742): each must make a named test fail.

Run: python3 -B tests/mutants_install_files.py   (copies the hooks and the tests into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INST = "ah_install.py"
GUARD = "command_guard.py"
AH = "ah.py"
T ="tests.test_ah_install."
G = "tests.test_command_guard_install_files."

# name -> (file, old text or list, new text or list, tests that must fail)
MUTANTS = {
    "unmerged commit accepted": (INST, ['git(repo, ["cat-file", "-e", ref + "^{commit}"], home, check=False).returncode != 0',
                                        'git(repo, ["merge-base", "--is-ancestor", ref, main], home, check=False).returncode != 0'],
                                 ["False", "False"], [T + "Source.test_an_unmerged_commit_refuses_before_any_remote_call"]),
    "objects not re-hashed": (INST, 'if hashlib.sha1(("%s %d\\0" % (kind_, len(body))).encode() + body).hexdigest() != oid:', 'if False:',
                              [T + "Source.test_a_planted_object_in_the_install_cache_has_no_effect_and_a_forged_object_after_the_fetch_is_caught"]),
    "replace refs accepted": (INST, 'if git(repo, ["for-each-ref", "refs/replace"], home).stdout.strip():', 'if False:',
                              [T + "Source.test_a_replace_ref_in_the_fetched_repository_refuses"]),
    "symlink blob accepted": (INST, 'if mode not in ("100644", "100755"):', 'if False:', [T + "Source.test_a_symlink_blob_refuses"]),
    "name list not checked": (INST, 'if name not in listed:', 'if False:', [T + "Listed.test_a_blob_that_exists_but_is_not_in_the_installer_list_refuses"]),
    "guard not last": (INST, 'return rest + (["command_guard.py"] if "command_guard.py" in names else [])',
                       'return (["command_guard.py"] if "command_guard.py" in names else []) + rest',
                       [T + "Install.test_the_guard_is_renamed_last_and_the_order_is_fixed"]),
    "read-back not compared": (INST, 'wrong = [n for n in todo if done["live"].get(n) != plan[n]["new_sha"]]', 'wrong = []',
                               [T + "SelfTest.test_a_read_back_sha_that_differs_after_the_rename_rolls_back_with_the_guard_first"]),
    "self-test never worse": (INST, 'def selftest_worse(before, after):\n    """None when `after` is no worse than `before`, else the reason.',
                              'def selftest_worse(before, after):\n    return None\n    """None when `after` is no worse than `before`, else the reason.',
                              [T + "SelfTest.test_an_allow_all_guard_rolls_every_file_back_with_the_guard_restored_first"]),
    "rollback skips the guard first": (INST, 'for name in (["command_guard.py"] if "command_guard.py" in names else []) + [n for n in reversed(names) if n != "command_guard.py"]:',
                                       'for name in names:', [T + "SelfTest.test_a_read_back_sha_that_differs_after_the_rename_rolls_back_with_the_guard_first"]),
    "unfinished runs ignored": (INST, 'return sorted({run for (run, _which), is_open in opened.items() if is_open})', 'return []',
                                [T + "Audit.test_a_lost_answer_after_the_first_rename_is_unknown_and_blocks_a_plain_rerun"]),
    "rollback checks backups after the start row": (INST, 'items, payload = _restore_items(home, remote, run_id, plan, to_restore, None) if to_restore else ([], b"")  # a plain refusal BEFORE the start row: unusable backups must not open an attempt',
                                                      'items, payload = [], b""\n    if to_restore:\n        locked_items = None',
                                                      [T + "Rollback.test_a_tampered_host_backup_falls_back_to_the_local_copy_and_both_tampered_refuse"]),
    "stale lock never taken over": (INST, 'STALE = 1800', 'STALE = 10**9', [T + "Lock.test_a_fresh_lock_refuses_and_a_stale_one_is_taken_over_atomically"]),
    "rollback ignores a later run": (INST, 'if live_sha != plan[name]["new_sha"] and name not in force_files:', 'if False:',
                                     [T + "Rollback.test_a_rollback_of_run_one_after_run_two_refuses_that_file_and_force_file_restores_it"]),
    "ticket not required": (INST, 'if not dry_run:\n            refuse("--ticket GoodQA project#N is required', 'if False:\n            refuse("--ticket GoodQA project#N is required',
                            [T + "Inputs.test_every_bad_input_refuses_before_any_ssh_call"]),
    "audit failure ignored": (INST, 'raise InstallError("audit_failed", "could not write the audit row; nothing was changed", 3, {"ok": False})\n    if not applied:',
                              'pass\n    if not applied:', [T + "Audit.test_a_failed_mac_audit_write_stops_before_any_remote_write_with_exit_3"]),
    "unknown reported as refused": (INST, 'if remote.started and error.code in ("lost", "unexpected"):', 'if False:',
                                    [T + "Audit.test_a_lost_answer_after_the_first_rename_is_unknown_and_blocks_a_plain_rerun"]),
    "mac copy not kept": (INST, '_keep_mac_copy(home, remote, run, name, plan[name]["old_sha"])', 'pass',
                          [T + "Install.test_a_good_install_backs_up_stages_renames_and_reports_every_sha"]),
    "a failed attempt is recorded as refused": (INST, 'if result == "refused" and kind_ in ("resume", "rollback"):', 'if False:',
                                                [T + "Receipt1c.test_a_rollback_lost_at_the_lock_does_not_clear_the_unfinished_run",
                                                 T + "Receipt1c.test_a_resume_refused_by_another_runs_lock_does_not_clear_the_unfinished_run"]),
    "unknown and attempt_refused clear a run": (INST, '"already_current", "refused")  # definite results', '"already_current", "refused", "unknown", "attempt_refused")  # definite results',
                                                [T + "Receipt1c.test_only_a_definite_result_clears_an_unfinished_run"]),
    "a resume is not treated as started": (INST, 'if resume_of:\n        remote.started = True', 'if False:\n        remote.started = True',
                                           [T + "Receipt1c.test_a_resume_that_fails_at_stage_is_unknown_and_the_host_keeps_refusing"]),
    "an after-test that does not answer is not rolled back": (INST, 'if error.code != "lost":\n                raise\n', 'raise\n',
                                                              [T + "Receipt1c.test_an_after_test_that_does_not_answer_in_time_attempts_a_rollback_guard_first"]),
    "a file the rollback could not remove is not checked": (INST, 'bad = [i["name"] for i in items if got["live"].get(i["name"]) != (None if i.get("remove_if_sha") else plan[i["name"]]["old_sha"])]\n    if bad:\n        return finish(home, run_id, host,',
                                                            'bad = [i["name"] for i in items if not i.get("remove_if_sha") and got["live"].get(i["name"]) != plan[i["name"]]["old_sha"]]\n    if bad:\n        return finish(home, run_id, host,',
                                                            [T + "Receipt1c.test_a_rollback_that_could_not_remove_a_file_does_not_report_restored"]),
    "fail-open baseline accepted": (INST, 'return (guard.get("deny_wal") or {}).get("verdict") == "block" and (guard.get("allow") or {}).get("verdict") == "allow"', 'return True',
                                    [T + "Hardening.test_a_host_guard_that_already_fails_open_refuses_before_any_write"]),
    "downgrade accepted": (INST, 'if not allow_older:\n                newer =', 'if False:\n                newer =',
                           [T + "Hardening.test_an_older_ref_that_would_downgrade_a_file_refuses_unless_allow_older_is_given_and_audited"]),
    "hooks symlink accepted": (INST, 'check_hooks()\nif op == "probe":', 'if op == "probe":', [T + "Hardening.test_a_hooks_directory_that_is_a_symlink_or_owned_by_another_user_refuses"]),
    "own lock not retaken": (INST, 'if holder == args["run"]:  # the same run', 'if False:  # the same run',
                             [T + "Lock.test_a_run_takes_its_own_leftover_lock_back_and_a_slow_run_does_not_look_stale"]),
    "unexpected error not caught": (INST, 'except Exception as error:  # noqa: BLE001 - an unexpected failure', 'except InstallError as error:  # noqa: BLE001 - an unexpected failure',
                                    [T + "Hardening.test_an_unexpected_error_after_the_first_live_write_is_unknown_with_json_not_a_traceback"]),
    "prune counts any entry": (INST, 'runs = sorted((n for n in os.listdir(BACKUPS) if re.fullmatch(r"ins-[0-9a-f]{12}", n)),', 'runs = sorted((n for n in os.listdir(BACKUPS)),',
                               [T + "Hardening.test_prune_keeps_ten_run_directories_and_ignores_other_entries"]),
    # goodqa#15913: the local targets
    "local target runs over ssh": (INST, "            if self.root:\n                done = self.runner(local_argv(", "            if False:\n                done = self.runner(local_argv(",
                                   [T + "LocalTarget.test_a_local_install_runs_the_same_program_without_ssh_and_reports_every_sha"]),
    "local root ignored": (INST, 'return [sys.executable, "-I", "-c", REMOTE_SCRIPT, op, json.dumps(args), root]',
                           'return [sys.executable, "-I", "-c", REMOTE_SCRIPT, op, json.dumps(args), "claude"]',
                           [T + "LocalCodex.test_local_codex_installs_into_the_codex_harness_directory_only"]),
    "script root not validated": (INST, 'if ROOT not in ROOTS:\n    raise SystemExit("bad root")', 'if False:\n    raise SystemExit("bad root")',
                                  [T + "LocalTarget.test_the_script_refuses_an_unknown_root_and_the_remote_argv_has_none"]),
    "script missing directory is a traceback": (INST, '        try:\n            st = os.lstat(path)\n        except FileNotFoundError:\n            raise SystemExit("the hooks directory does not exist")',
                                                '        st = os.lstat(path)',
                                                [T + "LocalTarget.test_the_script_refuses_an_unknown_root_and_the_remote_argv_has_none"]),
    "local env inherits the caller environment": (INST, "env = {k: os.environ[k] for k in LOCAL_ENV_KEYS if k in os.environ}", "env = dict(os.environ)",
                                                  [T + "LocalTarget.test_a_local_install_runs_the_same_program_without_ssh_and_reports_every_sha"]),
    "local PATH keeps relative entries": (INST, '    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if p.startswith("/")) or "/usr/bin:/bin"\n', '',
                                          [T + "LocalTarget.test_a_local_install_runs_the_same_program_without_ssh_and_reports_every_sha"]),
    "codex list not checked": (INST, '"codex": ("install_codex.py", "DELIVERY_HELPERS")}', '"codex": ("install.py", "HOOKS")}',
                               [T + "LocalCodex.test_a_name_outside_the_codex_list_refuses_before_any_call"]),
    "codex directory not checked before the fetch": (INST, 'if root == "codex" and not Path(home).joinpath(*CODEX_DIR).is_dir():', 'if False:',
                                                     [T + "LocalCodex.test_no_codex_harness_directory_refuses_and_creates_nothing"]),
    "codex drift not reported": (INST, "differs = codex_differs(home, plan)", "differs = []",
                                 [T + "LocalTarget.test_local_reports_the_codex_copies_that_differ_from_what_it_installed"]),
    "host audit row written on this machine": (INST, 'if op == "audit" and remote.root:\n            continue', 'if False:\n            continue',
                                               [T + "LocalTarget.test_a_local_install_runs_the_same_program_without_ssh_and_reports_every_sha"]),
    "local host names matched loosely": (INST, "(host not in HOSTS and host not in LOCAL_TARGETS)", '(host not in HOSTS and not host.startswith("local"))',
                                         [T + "LocalTarget.test_names_that_only_look_local_refuse_before_any_call"]),
    "rollback loses the local home": (INST, 'remote = Remote(host, runner, home)\n    state = remote.call("probe"', 'remote = Remote(host, runner)\n    state = remote.call("probe"',
                                      [T + "LocalTarget.test_a_local_rollback_and_a_local_resume_by_run_id"]),
    # goodqa#15913 round 2: the program in its own session, the hook-entry probes, the comment exit, CODEX_HOME, parents
    "local program shares the caller's session": (INST, "start_new_session=True, close_fds=True)", "start_new_session=False, close_fds=True)",
                                                  [T + "LocalKill.test_a_caller_side_timeout_leaves_the_local_program_running_in_its_own_session",
                                                   T + "LocalKill.test_a_caller_killed_after_one_of_three_renames_does_not_stop_the_program"]),
    "a caller timeout kills the local program": (INST, "    except subprocess.TimeoutExpired:\n        for stream in (proc.stdin, proc.stdout, proc.stderr):",
                                                 "    except subprocess.TimeoutExpired:\n        proc.kill()\n        for stream in (proc.stdin, proc.stdout, proc.stderr):",
                                                 [T + "LocalKill.test_a_caller_side_timeout_leaves_the_local_program_running_in_its_own_session"]),
    "local runner defaults to subprocess.run": (INST, "self.runner = runner or (detached_run if self.root else subprocess.run)", "self.runner = runner or subprocess.run",
                                                [T + "LocalKill.test_a_caller_killed_during_the_automatic_rollback_does_not_stop_the_restore"]),
    "hook probes not required": (INST, '        if now.get("exit") != 2 or now.get("rule") != rule:\n            return ("the hook entry probe', '        if False:\n            return ("the hook entry probe',
                                 [T + "LocalTarget.test_a_fail_open_hook_entry_is_rolled_back_on_both_local_targets"]),
    "hook probe accepts any exit 2": (INST, '        if now.get("exit") != 2 or now.get("rule") != rule:\n            return ("the hook entry probe', '        if now.get("exit") != 2:\n            return ("the hook entry probe',
                                      [T + "LocalTarget.test_the_hook_probes_are_absolute_after_the_install_and_never_compared_with_the_baseline"]),
    "hook probes compared with the baseline": (INST, '        if now.get("exit") != 2 or now.get("rule") != rule:\n            return ("the hook entry probe',
                                               '        if now != ((before.get("hook") or {}).get(key) or {}) and (now.get("exit") != 2 or now.get("rule") != rule):\n            return ("the hook entry probe',
                                               [T + "LocalTarget.test_the_hook_probes_are_absolute_after_the_install_and_never_compared_with_the_baseline"]),
    "self-test runs no hook probe": (INST, 'HOOK_PROBES = {"hook_deny_wal"', 'HOOK_PROBES = {} and {"hook_deny_wal"',
                                     [T + "LocalTarget.test_a_local_install_runs_the_same_program_without_ssh_and_reports_every_sha"]),
    "parent symlink accepted": (INST, "    for path in (os.path.dirname(HOOKS), HOOKS):", "    for path in (HOOKS,):",
                                [T + "LocalTarget.test_a_symlinked_claude_or_codex_parent_refuses_before_any_write"]),
    "failed local comment exits 0": (INST, "if host in LOCAL_TARGETS and exit_code == 0:", "if False:",
                                     [T + "LocalTarget.test_a_local_run_whose_ticket_comment_fails_exits_6_and_keeps_the_real_result_row"]),
    "comment exit status ignored": (INST, "return done.returncode == 0", "return True",
                                    [T + "LocalTarget.test_a_local_run_whose_ticket_comment_fails_exits_6_and_keeps_the_real_result_row"]),
    "CODEX_HOME ignored by local-codex": (INST, 'if root == "codex" and kind_ == "install" and codex_home_elsewhere(home):', "if False:",
                                          [T + "LocalTarget.test_codex_home_elsewhere_refuses_local_codex_and_is_noted_by_local"]),
    "CODEX_HOME not noted by local": (INST, "    elsewhere = codex_home_elsewhere(home)\n    if elsewhere:", "    elsewhere = None\n    if elsewhere:",
                                      [T + "LocalTarget.test_codex_home_elsewhere_refuses_local_codex_and_is_noted_by_local"]),
    "already_current runs the install steps": (INST, '    if not applied:\n        return finish(home, run, host, "already_current", 0,', '    if False:\n        return finish(home, run, host, "already_current", 0,',
                                               [T + "LocalTarget.test_a_rerun_at_the_same_commit_is_already_current_with_no_backup_stage_or_lock"]),
    # goodqa#15913 round 3 (N1, N4): the whole local run in its own session, resume's verdict, the registered probe form
    "local run not in its own session": (INST, "stderr=fds[1], start_new_session=True, close_fds=True,", "stderr=fds[1], start_new_session=False, close_fds=True,",
                                         [T + "LocalKill.test_a_caller_killed_after_the_commit_still_gets_the_verdict_and_the_automatic_rollback",
                                          T + "LocalKill.test_a_run_in_its_own_session_relays_its_output_and_exit_status_and_a_signal_is_unknown"]),
    "local runs never use their own session": (AH, "        target = ah_install.own_session_target(args, home_dir())\n        if target:",
                                               "        target = ah_install.own_session_target(args, home_dir())\n        if False:",
                                               [T + "Wiring.test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else"]),
    "a dry run uses its own session": (INST, 'if in_own_session() or getattr(args, "dry_run", False):', 'if in_own_session():',
                                       [T + "Wiring.test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else"]),
    "the session copy starts another": (INST, 'if in_own_session() or getattr(args, "dry_run", False):', 'if getattr(args, "dry_run", False):',
                                        [T + "Wiring.test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else"]),
    "resume goes by --host": (INST, 'run_id = getattr(args, "resume", None) or getattr(args, "rollback", None)', "run_id = None",
                              [T + "Wiring.test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else"]),
    "a signalled session exits 0": (INST, "    return code if code >= 0 else 5", "    return max(code, 0)",
                                    [T + "LocalKill.test_a_run_in_its_own_session_relays_its_output_and_exit_status_and_a_signal_is_unknown"]),
    "resume skips the verdict": (INST, "        why = selftest_worse(before, after)\n", "        why = None if resume_of else selftest_worse(before, after)\n",
                                 [T + "LocalKill.test_a_run_killed_after_the_commit_is_finished_by_resume_with_the_verdict_and_the_rollback"]),
    "hook probe not in the registered form": (INST, '["python3", entry, "hook"]', '[sys.executable, "-I", entry, "hook"]',
                                              [T + "LocalTarget.test_the_hook_probe_runs_the_entry_exactly_as_both_installers_register_it"]),
    "ticket comment not isolated": (INST, '[sys.executable, "-I", AH_PY, "ticket", "comment"', '["python3", AH_PY, "ticket", "comment"',
                                    [T + "LocalTarget.test_a_local_run_whose_ticket_comment_fails_exits_6_and_keeps_the_real_result_row"]),
    # goodqa#15913 round 4 (M1, L2): no --resume or --rollback while the run's own session lives; the session leader check
    "resume and rollback ignore a live session": (INST, "    busy = live_sessions(home, host, exclude=(os.getpid(),))\n    if busy:\n        refuse(\"run %s may still",
                                                  "    busy = []\n    if busy:\n        refuse(\"run %s may still",
                                                  [T + "LocalKill.test_resume_and_rollback_refuse_while_the_session_run_is_alive_and_the_audit_stays_consistent",
                                                   T + "LocalKill.test_a_session_record_counts_only_while_its_pid_and_start_time_match"]),
    "a reused pid counts as the run": (INST, '        if rec.get("start") and now and now != rec["start"]:', "        if False:",
                                       [T + "LocalKill.test_a_session_record_counts_only_while_its_pid_and_start_time_match"]),
    "the foreground records no session": (INST, "    record = None\n    if target:", "    record = None\n    if False:",
                                          [T + "LocalKill.test_resume_and_rollback_refuse_while_the_session_run_is_alive_and_the_audit_stays_consistent"]),
    "the session copy records nothing": (AH, "        ah_install.register_own_session(args, home_dir())", "        pass",
                                         [T + "Wiring.test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else"]),
    "an inherited marker is trusted": (INST, 'return os.environ.get(IN_SESSION_ENV) == "1" and os.getsid(0) == os.getpid()', 'return os.environ.get(IN_SESSION_ENV) == "1"',
                                       [T + "Wiring.test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else"]),
    "guard rule allows an environment prefix or wrapper": (GUARD, "        if depth or prefixed or changes_env:", "        if depth or changes_env:",
                                                           [G + "Forms.test_environment_wrappers_shells_and_a_missing_dash_i_are_refused_for_main_too"]),
    "guard rule allows a shell -c body for main": (GUARD, "        if depth or prefixed or changes_env:", "        if prefixed or changes_env:",
                                                   [G + "Forms.test_environment_wrappers_shells_and_a_missing_dash_i_are_refused_for_main_too"]),
    "guard rule ignores environment-changing segments": (GUARD, "        if depth or prefixed or changes_env:", "        if depth or prefixed:",
                                                         [G + "Forms.test_environment_wrappers_shells_and_a_missing_dash_i_are_refused_for_main_too"]),
    "guard rule drops -I": (GUARD, "            if head[-1] != rest[0] or '-I' not in head[1:-1]:", "            if False:",
                            [G + "Forms.test_environment_wrappers_shells_and_a_missing_dash_i_are_refused_for_main_too"]),
    "guard rule accepts a bare ah": (GUARD, "        elif first == 'ah':\n            return ('ah install-files: a bare", "        elif first == 'ah':\n            pass\n        elif False:\n            return ('ah install-files: a bare",
                                     [G + "Forms.test_a_script_named_ah_earlier_on_path_does_not_pass"]),
    "guard rule ignores bash -c": (GUARD, "if first in INSTALL_FILES_SHELLS and depth < 3:", "if False:",
                                   [G + "Forms.test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main"]),
    "guard rule reads raw text": (GUARD, "        if 'install' in re.sub(r'[\\'\"\\\\]', '', install_text):", "        if 'install-files' in install_text or 'ah_install' in install_text:",
                                  [G + "Forms.test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main"]),
    "guard rule splits inside quotes": (GUARD, "        if '\\n' in text:\n            raise ValueError('multi-line text')", "        if True:\n            raise ValueError('multi-line text')",
                                        [G + "Forms.test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main"]),
    "guard rule lets a sub-agent in": (GUARD, "        if not is_main:\n            return 'ah install-files: only the main agent", "        if False:\n            return 'ah install-files: only the main agent",
                                       [G + "Forms.test_a_sub_agent_is_refused_even_in_the_literal_form"]),
    "guard rule lets a sub-agent run a local target": (GUARD, "        if not is_main:\n            return 'ah install-files: only the main agent", "        if False:\n            return 'ah install-files: only the main agent",
                                                       [G + "Forms.test_the_local_targets_pass_for_main_and_are_refused_for_a_sub_agent"]),
    "guard rule accepts a worktree copy": (GUARD, "if len(rest) != 1 or rest[0] not in literal:", "if False:",
                                           [G + "Forms.test_the_installed_literal_form_passes_for_main_and_every_other_form_is_refused"]),
    "guard rule ignores flags": (GUARD, "if flag not in INSTALL_FILES_FLAGS:", "if False:",
                                 [G + "Forms.test_the_installed_literal_form_passes_for_main_and_every_other_form_is_refused"]),
}


def main():
    failures = 0
    for name, (target, old, new, tests) in MUTANTS.items():
        with tempfile.TemporaryDirectory(prefix="mutant-") as tmp:
            tmp = Path(tmp)
            shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
            (tmp / "tests").mkdir()
            for extra in ("test_ah_install.py", "test_command_guard_install_files.py"):
                shutil.copy(ROOT / "tests" / extra, tmp / "tests")
            for extra in ("install.py", "install_codex.py"):
                shutil.copy(ROOT / extra, tmp / extra)
            path = tmp / "harness" / "hooks" / target
            text = path.read_text()
            olds, news = (old, new) if isinstance(old, list) else ([old], [new])
            if any(o not in text for o in olds):
                print("MUTANT NOT APPLIED:", name)
                failures += 1
                continue
            for o, n in zip(olds, news):
                text = text.replace(o, n, 1)
            path.write_text(text)
            done = subprocess.run([sys.executable, "-B", "-m", "unittest", *tests], cwd=str(tmp), capture_output=True, text=True)
            killed = done.returncode != 0
            print("%-36s %s" % (name, "KILLED" if killed else "SURVIVED (test is vacuous)"))
            failures += 0 if killed else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
