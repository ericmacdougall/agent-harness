"""Controlled broken variants of ah_install.py and the guard rule (goodqa#15742): each must make a named test fail.

Run: python3 -B tests/mutants_install_files.py [--component guard|installer]
The runner copies the hooks and fixtures into temporary isolated trees."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INST = "ah_install.py"
GUARD = "command_guard.py"
T = "tests.test_ah_install."
G = "tests.test_command_guard_install_files."
POSITIVE = {
    INST: T + "Install.test_the_remote_command_string_reaches_python_unchanged_through_a_shell",
    GUARD: G + "NativeInstallAuthority.test_proven_desktop_main_passes_the_actual_install_hook",
}

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
    "self-test never worse": (INST, 'def selftest_worse(before, after):\n    """None when `after` is no worse than `before`, else the reason."""',
                              'def selftest_worse(before, after):\n    return None', [T + "SelfTest.test_an_allow_all_guard_rolls_every_file_back_with_the_guard_restored_first"]),
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
    "guard rule ignores bash -c": (GUARD, "if first in INSTALL_FILES_SHELLS and depth < 3:", "if False:",
                                   [G + "Forms.test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main"]),
    "guard rule reads raw text": (GUARD, "        if 'install' in re.sub(r'[\\'\"\\\\]', '', install_text):", "        if 'install-files' in install_text or 'ah_install' in install_text:",
                                  [G + "Forms.test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main"]),
    "guard rule splits inside quotes": (GUARD, "        if '\\n' in text:\n            raise ValueError('multi-line text')", "        if True:\n            raise ValueError('multi-line text')",
                                        [G + "Forms.test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main"]),
    "guard rule lets a sub-agent in": (GUARD, "    if proven_main is not True:\n        return 'ah install-files: only the main agent",
                                       "    if False:\n        return 'ah install-files: only the main agent",
                                       [G + "Forms.test_a_sub_agent_is_refused_even_in_the_literal_form"]),
    "guard rule accepts a worktree copy": (GUARD, "if len(rest) != 1 or rest[0] not in literal:", "if False:",
                                           [G + "Forms.test_the_installed_literal_form_passes_for_main_and_every_other_form_is_refused"]),
    "guard rule ignores flags": (GUARD, "if flag not in INSTALL_FILES_FLAGS:\n                # a redirection target",
                                 "if flag not in INSTALL_FILES_FLAGS:\n                i += 1\n                continue\n                # a redirection target",
                                 [G + "Forms.test_the_installed_literal_form_passes_for_main_and_every_other_form_is_refused"]),
}


CASES_RUNNER = """
import json
import os
import sys
import unittest

sys.path.insert(0, os.getcwd())

class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = {}
        self.assertions = []

    def startTest(self, test):
        self.cases.setdefault(test.id(), []).append([])
        super().startTest(test)

    def addFailure(self, test, err):
        if issubclass(err[0], AssertionError):
            self.assertions.append(test.id())
        super().addFailure(test, err)

    def addSubTest(self, test, subtest, err):
        self.cases[test.id()][-1].append(subtest.id())
        if err and issubclass(err[0], AssertionError):
            self.assertions.append(test.id())
        super().addSubTest(test, subtest, err)

loader = unittest.TestLoader()
suite = loader.loadTestsFromNames(sys.argv[1:])
result = unittest.TextTestRunner(resultclass=Result, buffer=True).run(suite)
print(json.dumps({
    "cases": result.cases, "assertions": result.assertions, "failures": len(result.failures),
    "invalid": (len(loader.errors) + len(result.errors) + len(result.skipped)
                + len(result.expectedFailures) + len(result.unexpectedSuccesses)),
}))
"""


def isolate(folder):
    shutil.copytree(ROOT / "harness" / "hooks", folder / "harness" / "hooks",
                    ignore=shutil.ignore_patterns("__pycache__"))
    tests = folder / "tests"
    tests.mkdir()
    (tests / "__init__.py").touch()
    for name in ("test_ah_install.py", "test_command_guard_install_files.py", "test_native_main.py"):
        shutil.copy(ROOT / "tests" / name, tests)
    for name in ("install.py", "install_codex.py"):
        shutil.copy(ROOT / name, folder)


def run_cases(folder, tests):
    try:
        done = subprocess.run([sys.executable, "-I", "-B", "-c", CASES_RUNNER, *tests],
                              cwd=folder, capture_output=True, text=True, timeout=90)
        result = json.loads(done.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if done.returncode != 0 or result["invalid"] or result["failures"] != len(result["assertions"]):
        return None
    if set(result["cases"]) != set(tests) or any(len(runs) != 1 for runs in result["cases"].values()):
        return None
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("all", "guard", "installer"), default="all")
    component = parser.parse_args(argv).component
    target_file = {"guard": GUARD, "installer": INST}.get(component)
    selected = {name: data for name, data in MUTANTS.items() if target_file in (None, data[0])}
    if not selected:
        parser.error("No mutations selected")
    failures = 0
    for name, (target, old, new, negatives) in selected.items():
        tests = [*negatives, POSITIVE[target]]
        with tempfile.TemporaryDirectory(prefix="mutant-") as directory:
            folder = Path(directory)
            isolate(folder)
            baseline = run_cases(folder, tests)
            if baseline is None or baseline["assertions"]:
                print("BASELINE FAILED:", name, flush=True)
                return 1
            subtests = sum(len(runs[0]) for runs in baseline["cases"].values())
            print(f"BASELINE PASS: {name} ({len(tests)} cases, {subtests} subtests)", flush=True)

            path = folder / "harness" / "hooks" / target
            source = path.read_text()
            pairs = list(zip(old, new, strict=True)) if isinstance(old, list) else [(old, new)]
            if any(source.count(before) != 1 for before, _ in pairs):
                print("MUTANT NOT APPLIED EXACTLY ONCE:", name, flush=True)
                failures += 1
                continue
            for before, after in pairs:
                source = source.replace(before, after, 1)
            path.write_text(source)

            result = run_cases(folder, tests)
            if result is None or result["cases"] != baseline["cases"]:
                verdict = "INVALID RESULT (test errors or changed coverage)"
            elif not result["assertions"]:
                verdict = "SURVIVED"
            elif not set(result["assertions"]).issubset(negatives):
                verdict = "INVALID RESULT (positive control failed)"
            else:
                count = len(result["assertions"])
                print(f"KILLED: {name} ({len(tests)} cases, {subtests} subtests, {count} expected assertion failures)",
                      flush=True)
                continue
            print(f"{verdict}: {name}", flush=True)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
