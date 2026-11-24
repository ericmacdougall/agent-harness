"""Mutation controls for tests/test_checkout_registry.py (goodqa#16947, spec v3): each mutant removes one control of
harness/hooks/checkout_registry.py, and the named test must FAIL against it. Run from the repository root:

    python3 tests/mutants_checkout_registry.py

Each mutant runs in a temporary copy (the real file is never edited). Exit 1 if any survives or no longer applies.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join("harness", "hooks", "checkout_registry.py")
T = "tests.test_checkout_registry."
MUTANTS = [
    ("an existing path is proposed as new (Pre-absent)",
     '        if f.get("exists") is True:\n            decide("existed-at-pre", tool_use_id=tid, path=c["path"])\n'
     '            continue',
     '        if False:\n            pass',
     T + "Writer.test_existing_path_gets_no_row"),
    ("a moved-in checkout is accepted (btime vs clock mark)",
     '    if f["btime_ns"] < rec["mark_ns"]:',
     '    if False:',
     T + "Writer.test_moved_in_or_wrong_kind_gets_no_row"),
    ("a plain clone counts as a linked worktree",
     '        if not f.get("linked"):\n            return None, "not-linked"',
     '        pass',
     T + "Writer.test_moved_in_or_wrong_kind_gets_no_row"),
    ("a checkout outside home is accepted",
     '    if f.get("in_home") is not True:\n        return None, "outside-home"',
     '    pass',
     T + "Writer.test_symlink_and_outside_home_get_no_row"),
    ("the pinned folder is not re-checked",
     '    if _dir_identity(c["anchor"]) != (c.get("anchor_dev"), c.get("anchor_ino")):',
     '    if False:',
     T + "Writer.test_folder_replaced_during_the_call_gets_no_row"),
    ("the made path may resolve elsewhere",
     '    if f.get("realpath") != expect:',
     '    if False:',
     T + "Writer.test_link_repointed_during_the_call_gets_no_row"),
    ("the clone origin is not compared",
     '        if not same:\n            return None, "origin-mismatch"',
     '        pass',
     T + "Writer.test_checkout_from_another_source_gets_no_row"),
    ("the worktree repo is not compared",
     '        if f.get("common_dir") != c.get("repo_common"):',
     '        if False:',
     T + "Writer.test_checkout_from_another_source_gets_no_row"),
    ("no btime still writes a row",
     '    if not f.get("btime_ns"):\n        return None, "no-btime"',
     '    if not f.get("btime_ns"):\n        f = dict(f, btime_ns=rec["mark_ns"])',
     T + "Writer.test_no_birth_time_gets_no_row"),
    ("git runs with the repo's fsmonitor",
     '"-c", "core.fsmonitor=false", ',
     '',
     T + "Writer.test_repo_config_runs_nothing_when_the_registry_reads_it"),
    ("a relative path after cd resolves against cwd",
     'base = None if moves else (os.path.realpath(cwd) if cwd and os.path.isabs(cwd) else None)',
     'base = os.path.realpath(cwd) if cwd and os.path.isabs(cwd) else None',
     T + "Writer.test_unsure_commands_propose_nothing"),
    ("a path that needs the shell is taken literally",
     '    if not raw or UNSAFE_PATH.search(raw):',
     '    if not raw:',
     T + "Writer.test_unsure_commands_propose_nothing"),
    ("an unknown long option is skipped",
     '            raise Unsure("unknown option " + name)',
     '            i += 1; continue',
     T + "Writer.test_unsure_commands_propose_nothing"),
    ("a remote command is parsed as local",
     '                if MENTION.search(" ".join(words[1:])):\n                    raise Unsure',
     '                if False:\n                    raise Unsure',
     T + "Writer.test_unsure_commands_propose_nothing"),
    ("redirections are kept as arguments",
     '        if REDIR_OP.fullmatch(t):',
     '        if False:',
     T + "Writer.test_common_real_shapes_are_proposed"),
    ("a path seen absent keeps its dead rows",
     '        retire_absent(expect, key)\n',
     '',
     T + "Ownership.test_inode_reuse_never_matches_the_old_row"),
    ("identity ignores btime",
     '    return (row.get("host"), row.get("dev"), row.get("ino"), row.get("btime_ns"))',
     '    return (row.get("host"), row.get("dev"), row.get("ino"))',
     T + "Ownership.test_inode_reuse_never_matches_the_old_row"),
    ("a second owner is written",
     '            return None, "already-held" if same else "second-owner"',
     '            pass',
     T + "Ownership.test_second_owner_for_the_same_identity_is_refused"),
    ("a contested path still gets a row",
     '    if _release(expect, tid):\n        return None, "contested"',
     '    _release(expect, tid)',
     T + "Ownership.test_two_calls_racing_for_one_path_write_no_row"),
    ("check and append run without the lock",
     '    with _locked():\n        live = current(HOST, key)',
     '    if True:\n        live = current(HOST, key)',
     T + "Ownership.test_two_writer_processes_produce_one_owner"),
    ("two created rows still name an owner",
     '                contested.add(ident)',
     '                pass',
     T + "Ownership.test_two_created_rows_mean_no_owner"),
    ("a pending record from another session is accepted",
     '            (tid, session, agent, _sha(cmd)):',
     '            (rec.get("tool_use_id"), rec.get("session"), rec.get("agent"), rec.get("cmd_sha")):',
     T + "Ownership.test_missing_forged_foreign_and_expired_pending_records_write_nothing"),
    ("an expired pending record is accepted",
     'not 0 <= time.time() - rec["at"] <= PENDING_TTL',
     'False',
     T + "Ownership.test_missing_forged_foreign_and_expired_pending_records_write_nothing"),
    ("the transcript binding is skipped",
     '    if code == "ok" and not bound_to_transcript(payload, session, agent, tid, rec["cmd_sha"]):',
     '    if False:',
     T + "Ownership.test_forged_hook_payloads_write_nothing"),
    ("a background launch keeps its pending record",
     '        _drop_pending(payload, "background")\n        return []',
     '        pass',
     T + "Ownership.test_background_launch_gets_no_row"),
    ("verify ignores the MAC",
     '    return bool(want) and hmac.compare_digest(want, row["mac"])',
     '    return bool(want)',
     T + "Integrity.test_edited_moved_and_foreign_key_rows_fail"),
    ("a row pasted into another host's file counts",
     '        if key and verify(row, key) and row.get("host") == host:',
     '        if key and verify(row, key):',
     T + "Integrity.test_edited_moved_and_foreign_key_rows_fail"),
    ("a partial line is not repaired",
     '        if st.st_size and os.pread(fd, 1, st.st_size - 1) != b"\\n":',
     '        if False:',
     T + "Integrity.test_partial_line_is_repaired_before_the_next_row"),
    ("a group-writable state folder is trusted",
     '    return stat_mod.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o022)',
     '    return stat_mod.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()',
     T + "Integrity.test_unsafe_state_dir_or_key_writes_nothing"),
    ("the key is read through a symlink",
     '        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))',
     '        fd = os.open(str(path), os.O_RDONLY)',
     T + "Integrity.test_unsafe_state_dir_or_key_writes_nothing"),
    ("another agent's folder prefix counts",
     '    if end < len(cwd) and cwd[end] != "/":\n        return None',
     '    pass',
     T + "Isolation.test_other_agents_folder_and_unregistered_folders_get_no_row"),
    ("an isolation worktree of another repo counts",
     '    if real not in listed or os.path.realpath(os.path.join(repo, ".git")) != f.get("common_dir"):',
     '    if False:',
     T + "Isolation.test_other_agents_folder_and_unregistered_folders_get_no_row"),
    ("the isolation birth window is ignored",
     '    if not f.get("btime_ns") or abs(f["btime_ns"] - t_birth) > ISO_WINDOW_NS:',
     '    if not f.get("btime_ns"):',
     T + "Isolation.test_no_transcript_or_outside_the_birth_window_gets_no_row"),
    ("unpushed commits do not block the verdict",
     '    elif int(unpushed):\n        reasons.append("unpushed")',
     '    elif False:\n        pass',
     T + "Stop.test_verdicts_and_nothing_is_removed"),
    ("nested checkouts do not block the verdict",
     '    if nested:\n        reasons.append("contains another checkout")',
     '    if False:\n        pass',
     T + "Stop.test_verdicts_and_nothing_is_removed"),
    ("note strings are not sanitised",
     '    return UNSAFE_TEXT.sub("?", str(value))[:limit]',
     '    return str(value)[:limit]',
     T + "Stop.test_verdicts_and_nothing_is_removed"),
    ("a clone is a removal candidate",
     '    if row["kind"] != "isolation":',
     '    if False:',
     T + "Stop.test_clone_is_listed_but_never_a_removal_candidate"),
    ("a hook error propagates",
     '        decide("hook-error", event=event, error=type(e).__name__)',
     '        raise',
     T + "FailOpen.test_internal_error_is_swallowed_and_recorded"),
]


def main() -> int:
    src = open(os.path.join(ROOT, TARGET)).read()
    bad = 0
    for name, old, new, test in MUTANTS:
        if src.count(old) != 1:
            print("STALE    %s" % name)
            bad += 1
            continue
        tmp = tempfile.mkdtemp(prefix="checkout-registry-mutant-")
        try:
            os.makedirs(os.path.join(tmp, "harness", "hooks"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tmp, "tests"))
            for f in ("install.py",):
                shutil.copy(os.path.join(ROOT, f), os.path.join(tmp, f))
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
