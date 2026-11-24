"""Mutation controls for tests/test_update_installed.py (goodqa#16947, PR 336 review F1-F7): each mutant removes one
refusal, hardening step or derivation of scripts/update_installed.py, and the named test must FAIL against it. Run from
the repository root:

    python3 tests/mutants_update_installed.py

Each mutant runs in a temporary copy of scripts/ and tests/ (harness/ is linked read-only; the real files are never
edited). A baseline over every named test runs first. Exit 1 if the baseline fails, or any mutant survives or no
longer applies.

Not covered by a mutant (no hermetic way to produce the input): the grafts, shallow and replace-ref refusals after a
fresh fetch of main only (they mirror ah_install.fetch_source and are defence in depth).
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
    # Source and commit (F3)
    ("an unmerged commit is accepted",
     '    if git(repo, ["cat-file", "-e", commit + "^{commit}"], home, check=False).returncode != 0:\n'
     '        raise Stop("%s is not a commit of the canonical main history; nothing was changed" % commit)\n'
     '    if git(repo, ["merge-base", "--is-ancestor", commit, main], home, check=False).returncode != 0:\n'
     '        raise Stop("%s is not on origin/main; nothing was changed" % commit)\n',
     '',
     T + "Refusals.test_commit_not_on_main_is_refused"),
    ("the caller's environment reaches git",
     '    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}',
     '    env = dict(os.environ)',
     T + "FreshSource.test_git_env_and_flags_match_ah_install"),
    ("git runs without the hardening flags",
     '    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.commitGraph=false",',
     '    argv = ["git", "-c", "core.commitGraph=false",',
     T + "FreshSource.test_git_env_and_flags_match_ah_install"),
    ("an object is not re-hashed",
     '    if hashlib.sha1(("%s %d\\0" % (kind, len(body))).encode() + body).hexdigest() != oid:',
     '    if False:',
     T + "FreshSource.test_an_object_that_does_not_hash_to_its_id_stops"),
    ("a cache folder open to others is used",
     '    if os.path.islink(root) or st.st_uid != os.getuid() or st.st_mode & 0o077:',
     '    if False:',
     T + "FreshSource.test_a_cache_folder_that_is_a_symlink_or_open_to_others_stops"),
    ("the run folder is left behind",
     '            shutil.rmtree(run, ignore_errors=True)',
     '            pass',
     T + "Refusals.test_commit_not_on_main_is_refused"),
    # install.py isolation (F2)
    ("install.py runs without -B -E -s",
     '[sys.executable, "-B", "-E", "-s", str(export / "install.py")',
     '[sys.executable, str(export / "install.py")',
     T + "FreshSource.test_install_py_runs_isolated_from_a_fresh_export"),
    ("the updater runs without -I",
     'if __name__ == "__main__" and not sys.flags.isolated:',
     'if False:',
     T + "AgentsAndConfirmation.test_without_isolation_the_script_stops_before_its_imports"),
    ("the lists and bytes come from main, not the commit",
     '        subject = export_commit(repo, a.home, commit, export)',
     '        subject = export_commit(repo, a.home, main_sha, export)',
     T + "FileList.test_the_lists_and_bytes_are_the_commits_not_mains"),
    # Agents and confirmation (F1, mitigation)
    ("an agent environment is not refused",
     '        if markers:',
     '        if False:',
     T + "AgentsAndConfirmation.test_an_agent_environment_is_refused_for_a_preview_and_a_real_run"),
    ("a real run is not confirmed",
     '            confirm(commit, reader)',
     '            pass',
     T + "AgentsAndConfirmation.test_a_real_run_needs_the_commit_typed_at_the_terminal"),
    ("any answer confirms",
     '    if got != commit[:12]:',
     '    if False:',
     T + "AgentsAndConfirmation.test_a_real_run_needs_the_commit_typed_at_the_terminal"),
    # Downgrade (F4)
    ("an older commit downgrades a Mac file",
     '        if older:',
     '        if False:',
     T + "FileList.test_an_older_commit_that_would_downgrade_a_mac_file_stops"),
    # Batches (F5)
    ("command_guard.py is not last",
     '    return [n for n in names if n != GUARD] + ([GUARD] if GUARD in names else [])',
     '    return list(names)',
     T + "FileList.test_remote_batches_hold_at_most_twenty_files_with_the_guard_last"),
    ("a failed batch gives no resume guidance",
     '            raise Stop(str(e) + resume_guidance(home, host, ticket, done, since))',
     '            raise',
     T + "RealRun.test_a_failed_batch_reports_what_was_installed_and_how_to_finish"),
    # Tests the review found missing (F6)
    ("a short or uppercase commit is accepted",
     '        if a.commit is not None and not SHA_RE.fullmatch(a.commit):',
     '        if False:',
     T + "Refusals.test_malformed_inputs_stop_before_anything_runs"),
    ("a malformed ticket is accepted",
     '        if a.ticket is not None and not TICKET_RE.fullmatch(a.ticket):',
     '        if False:',
     T + "Refusals.test_malformed_inputs_stop_before_anything_runs"),
    ("a non-literal installer list is read as empty",
     '                        raise Stop("install.py %s is not a literal tuple" % var)',
     '                        names = ()',
     T + "Refusals.test_a_non_literal_installer_list_stops"),
    ("the Mac is not re-checked after install.py",
     '            still = local_changes(export, a.home, lists)',
     '            still = []',
     T + "RealRun.test_a_mac_file_still_different_after_install_py_stops"),
    ("the remote is not re-checked after the install",
     '            left = remote_changes(a.home, h, commit, lists["hooks"], runner)',
     '            left = []',
     T + "RealRun.test_a_remote_file_still_different_after_the_install_stops"),
    ("a timed-out ah call is a traceback",
     '    except subprocess.TimeoutExpired:\n        raise Stop("%s timed out after %d s" % (what, INSTALL_TIMEOUT))',
     '    except ZeroDivisionError:\n        raise Stop("%s timed out after %d s" % (what, INSTALL_TIMEOUT))',
     T + "RealRun.test_timeouts_and_odd_answers_stop_cleanly"),
    ("a plan entry that is not a dict is accepted",
     ' or not all(isinstance(v, dict) for v in files.values())',
     '',
     T + "RealRun.test_timeouts_and_odd_answers_stop_cleanly"),
    # Registration (F7)
    ("unregistered hooks still say Done",
     '            return EXIT_REGISTER',
     '            pass',
     T + "Registration.test_new_unregistered_hooks_give_exit_3_and_old_gaps_are_kept_apart"),
    ("a hook wired before and not after goes on",
     '            if lost:',
     '            if False:',
     T + "Registration.test_a_hook_wired_before_and_not_after_stops"),
    # Kept from 7298d3ef
    ("preview goes on to install",
     '            print("Preview only: nothing was installed.")\n            return EXIT_OK',
     '            print("Preview only: nothing was installed.")',
     T + "Preview.test_preview_writes_nothing"),
    ("installed files are never compared",
     '            if file_sha(Path(home) / ".claude" / rel) != want:',
     '            if False:',
     T + "FileList.test_file_list_is_derived_from_the_installed_files"),
    ("a symlinked install counts as current",
     '    if p.is_symlink() or not p.is_file():',
     '    if not p.is_file():',
     T + "FileList.test_file_list_is_derived_from_the_installed_files"),
    ("every remote hook is sent, changed or not",
     '    return [n for n in ordered(hooks) if plan[n].get("action") != "already_current"]',
     '    return list(hooks)',
     T + "FileList.test_file_list_is_derived_from_the_installed_files"),
]


def copy(tmp):
    shutil.copytree(os.path.join(ROOT, "scripts"), os.path.join(tmp, "scripts"))
    shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"))
    os.symlink(os.path.join(ROOT, "harness"), os.path.join(tmp, "harness"))


def run(tmp, tests):
    return subprocess.run([sys.executable, "-m", "unittest", *tests], cwd=tmp, capture_output=True, text=True,
                          timeout=1800)


def main() -> int:
    src = open(os.path.join(ROOT, TARGET)).read()
    tmp = tempfile.mkdtemp(prefix="update-installed-baseline-")
    try:
        copy(tmp)
        base = run(tmp, sorted({m[3] for m in MUTANTS}))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("baseline (unmutated copy, every named test): %s" % ("PASS" if base.returncode == 0 else "FAIL"))
    if base.returncode:
        print(base.stderr[-2000:])
        print("a named test fails without any mutant, so KILLED would mean nothing")
        return 1
    bad = 0
    for name, old, new, test in MUTANTS:
        if src.count(old) != 1:
            print("STALE    %s" % name)
            bad += 1
            continue
        tmp = tempfile.mkdtemp(prefix="update-installed-mutant-")
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
