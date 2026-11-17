"""Slice 1 (b) variant harness (goodqa#16049, AC-15).

Every id this slice removes from PENDING, PENDING_RUNTIME or PENDING_B, and every NEG case with a broken-variant
clause, maps here to its explicit test methods (full dotted names) and at least one mutation. For each entry:

1. baseline: the mapped methods alone, on unmutated source, must all pass;
2. kill: each mutation is applied (exact, unique text swaps, restored in `finally`) and the mapped methods alone are
   run again. It counts as killed only when at least one mapped method fails with an AssertionError (a unittest
   failure) and none errors. An import or syntax failure, an error, a skip, a timeout or a method that did not run
   is INCONCLUSIVE, never a kill;
3. control: the first mutation again, with every mapped method replaced by a no-op. The harness must then see it
   unkilled, so the control reports the id UNPROVEN; a control that still kills means the harness is broken.

An entry is PROVEN only when its baseline passes, every mutation is killed and its control is unproven.
Run from the repo root: `python3 -B tests/variants/ahc_slice1b_variants.py [--only KEY] [output-file]`;
`--self-test` checks the classification on a throwaway fixture (NEG-32). It mutates tracked files while it runs, so
do not commit or run other suites at the same time. Not collected by unittest (no test_ prefix).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_run_mapped.py")
TIMEOUT = float(os.environ.get("AHC_VARIANT_TIMEOUT", "900"))
CONTRACTS = "harness/hooks/ahc_contracts.py"
RUNNER_PY = "harness/hooks/ahc_runner.py"

# key -> {"tests": [dotted ids], "mutations": [(name, [(old, new)], file)]}. Filled step by step as the slice lands.
HARNESS = "tests/variants/ahc_slice1b_variants.py"
HT = "tests.test_ahc_variants_harness.VariantHarnessTests."
ENTRIES = {
    "AC-15/NEG-32": {"tests": [HT + "test_slice1b_harness_self_test",
                               HT + "test_slice1b_classify_needs_an_assertion_in_a_mapped_method"],
                     "mutations": [("an error or a skip is counted as killed", [
                         ('    if any(v in ("error", "skip") for v in values):\n        return "inconclusive"\n', "")],
                         HARNESS)]},
}
MV = "tests.test_ahc_runner.MigrationV5Tests."
ENTRIES.update({
    "AC-11/NEG-39 manifest check": {
        "tests": [MV + "test_v5_entry_point_mismatch_refuses_before_any_backup"],
        "mutations": [("the preflight skips the entry-point manifest check", [
            ("        ahc_migrate.verify_entry_points(self.HOOKS_DIR, self._installed_extras())\n", "")],
            RUNNER_PY)]},
    "AC-11/NEG-39 failed check is held": {
        "tests": [MV + "test_v5_a_failed_open_file_check_counts_as_held"],
        "mutations": [("a failed open-file check counts as clear", [
            ('                raise MigrationRefused("migration-held: the open-file check failed (%s), which counts '
             'as held"\n                                       % error) from None\n',
             "                others = set()\n")], RUNNER_PY)]},
    "AC-11/NEG-39 held file clears the fence": {
        "tests": [MV + "test_v5_fence_over_v3_is_cleared_when_the_file_is_held"],
        "mutations": [("a held file refuses without clearing the fence", [
            ("            ahc_migrate.clear_fence(self.db, n)\n            raise MigrationRefused(\"%s; the fence",
             "            raise MigrationRefused(\"%s; the fence")], RUNNER_PY)]},
    "AC-11/NEG-43 fence before the check": {
        "tests": [MV + "test_v5_the_fence_is_committed_before_the_open_file_check"],
        "mutations": [("the fence is written after the open-file check", [
            ("        ahc_migrate.set_fence(self.db, n)\n", ""),
            ('        # (6) the verified online backup, which carries the fence\n',
             "        ahc_migrate.set_fence(self.db, n)\n")], RUNNER_PY)]},
    "AC-11 backup after the fence": {
        "tests": [MV + "test_v5_failure_restores_fenced_then_the_retry_migrates",
                  MV + "test_v5_the_fence_is_committed_before_the_open_file_check"],
        "mutations": [("the backup is taken before the fence", [
            ('        crash_before("runner.v5_fence")\n',
             '        copy = self.backup("pre-v%d" % SCHEMA_VERSION)\n        crash_before("runner.v5_fence")\n'),
            ('        copy = self.backup("pre-v%d" % SCHEMA_VERSION)\n        # (7)', "        # (7)")], RUNNER_PY)]},
    "AC-11/NEG-43 publish never replaces": {
        "tests": [MV + "test_v5_a_stray_file_at_the_absent_path_is_never_replaced"],
        "mutations": [("the restored copy is published by a replacing rename", [
            ("            fs.link_exclusive(self.paths.root, staged, self.path)   # the complete, fsynced, "
             "digest-checked copy\n", "            fs.rename(self.paths.root, staged, self.path)\n"),
            ("        fs.unlink(self.paths.root, staged)\n        crash_after(\"runner.restore_publish\")",
             "        crash_after(\"runner.restore_publish\")")], RUNNER_PY)]},
    "AC-11 layout refusal": {
        "tests": [MV + "test_v5_refuses_the_earlier_v4_layout_and_unknown_markers"],
        "mutations": [("the preflight does not check the layout", [
            ('            if layout not in ("pr258", "4d45fe40", "v5"):\n                raise MigrationRefused('
             '"migration-layout',
             '            if False:\n                raise MigrationRefused("migration-layout')], RUNNER_PY)]},
    "AC-11 PR 258 spec rows stay legacy": {
        "tests": [MV + "test_v5_pr258_layout_migrates_code_rows_keeps_spec_rows_legacy"],
        "mutations": [("PR 258 spec rows are copied into the v5 table", [
            ('where = "WHERE kind != \'spec\'" if (name == "reviews" and layout == "pr258") else ""',
             'where = ""')], "harness/hooks/ahc_migrate.py")]},
    "AC-11 rollback clears the fence": {
        "tests": [MV + "test_v5_rollback_restores_the_backup_clears_the_fence_and_old_code_opens_it"],
        "mutations": [("rollback restores without clearing the fence", [
            ("            self.restore(copy)\n            ahc_migrate.clear_fence(self.db, n)\n",
             "            self.restore(copy)\n")], RUNNER_PY)]},
    "AC-16/NEG-28 item in the review identity": {
        "tests": [MV + "test_v5_readmitted_workitem_never_gets_a_copied_row"],
        "mutations": [("require_review looks rows up without the item", [
            ('"SELECT id FROM reviews WHERE item=? AND kind=? AND',
             '"SELECT id FROM reviews WHERE ? IS NOT NULL AND kind=? AND')], CONTRACTS)]},
})
CK = "tests.test_ahc_clock.ClockTests."
CC = "tests.test_ahc_contracts.ClockTests."
CLOCK = "harness/hooks/ahc_clock.py"
ENTRIES.update({
    "AC-10 wall never backwards": {
        "tests": [CK + "test_effective_wall_never_goes_backwards_across_restarts"],
        "mutations": [("the high-water mark is never persisted", [
            ('            self.db.execute("INSERT OR REPLACE INTO contract_meta(k, v) VALUES (?, ?)", (self.HWM_KEY, '
             'repr(now)))\n', "")], CLOCK)]},
    "AC-10 escalation on either clock": {
        "tests": [CK + "test_escalation_fires_on_either_clock_and_on_a_new_boot"],
        "mutations": [("an escalation waits for both clocks", [
            ("return elapsed is None or wall_passed or elapsed >= float(duration)",
             "return elapsed is None or (wall_passed and elapsed >= float(duration))")], CLOCK)]},
    "AC-10 wait needs both clocks": {
        "tests": [CK + "test_wait_needs_both_clocks_and_restarts_on_a_new_boot"],
        "mutations": [("a wait ends on the wall clock alone", [
            ("        return wall_passed and elapsed >= float(duration)\n",
             "        return wall_passed or elapsed >= float(duration)\n")], CLOCK)]},
    "AC-10 new boot is unknown elapsed": {
        "tests": [CK + "test_escalation_fires_on_either_clock_and_on_a_new_boot",
                  CK + "test_wait_needs_both_clocks_and_restarts_on_a_new_boot",
                  CC + "test_new_boot_near_b47_expiry_expires_at_once_with_wall_back_or_forward",
                  CC + "test_new_boot_mid_wait_restarts_the_full_wait"],
        "mutations": [("a new boot keeps the old anchor", [
            (" or boot != self.boot_id:", ":")], CLOCK)]},
    "AC-10 elapsed from the boot clock": {
        "tests": [CK + "test_elapsed_comes_from_the_boot_clock_not_the_wall",
                  CC + "test_crash_loop_every_5_min_for_1_h_keeps_elapsed"],
        "mutations": [("elapsed is derived from wall timestamps", [
            ("        return max(0.0, float(self._boot()) - float(anchor))\n",
             "        return max(0.0, self.effective_wall() - (float(_deadline) - float(_duration)))\n")], CLOCK)]},
    "AC-10 restart keeps the anchor": {
        "tests": [CC + "test_crash_loop_every_5_min_for_1_h_keeps_elapsed"],
        "mutations": [("a restart resets every anchor", [
            ("                process_boot_id()\n        self.boot_id = boot_id\n",
             "                process_boot_id()\n        self.boot_id = boot_id\n"
             "        db.execute('UPDATE timers SET anchor=?', (float(self._boot()),))\n")], CLOCK)]},
    "AC-10 re-anchor commits on a refusal": {
        "tests": [CC + "test_new_boot_mid_wait_restarts_the_full_wait"],
        "mutations": [("the B55 wait is read inside the refusing transaction", [
            ('        waited = restart or self.clock.due(key, "B55", B55_REQUEST_SECONDS)\n        with self.tx():\n'
             '            row = self._row_or_raise(key)\n            if not waited:',
             '        with self.tx():\n            row = self._row_or_raise(key)\n'
             '            if not (restart or self.clock.due(key, "B55", B55_REQUEST_SECONDS)):')], CONTRACTS)]},
    "AC-10 B47 on either clock": {
        "tests": [CC + "test_b47_expiry_on_either_clock_with_wall_steps"],
        "mutations": [("the grant sweep reads the wall only", [
            ('                if not (expires <= now or self.clock.due(gid, "B47")):',
             '                if not (expires <= now):')], CONTRACTS)]},
    "AC-10 LATE_WATCH and B48 need both clocks": {
        "tests": [CC + "test_wall_forward_alone_never_ends_a_monitor_or_retention",
                  CC + "test_new_boot_near_late_watch_end_keeps_watching_with_wall_steps"],
        "mutations": [("the watch and retention end on the wall alone", [
            ('                if r[3] == "fenced" or not self.clock.due(r[0], "LATE_WATCH", self.LATE_WATCH_SECONDS)]',
             '                if r[3] == "fenced"]'),
            ('                if self.clock.due(k, "B48", B48_RETENTION_SECONDS)]', '                if True]')],
            CONTRACTS)]},
    "AC-10 CAP1 day never backwards": {
        "tests": [CC + "test_cap1_day_never_goes_backwards_on_a_wall_step_back"],
        "mutations": [("CAP1's day reads the raw wall", [
            ("        return int((self.clock.effective_wall() if at is None else at) // 86400)",
             "        return int((self.now() if at is None else at) // 86400)")], CONTRACTS)]},
    "AC-10 static inventory": {
        "tests": [CC + "test_every_wall_clock_read_outside_the_clock_service_is_inventoried"],
        "mutations": [("an uninventoried wall read", [
            ('            self.clock.start(key, "B37", B37_PROBE_SECONDS)\n',
             '            self.clock.start(key, "B37", B37_PROBE_SECONDS + 0 * self.now())\n')], CONTRACTS)]},
    "AC-10 canary age": {
        "tests": [CC + "test_canary_age_from_boot_and_mono_or_github_date_never_the_wall"],
        "mutations": [("canary age from the local wall", [
            ("            return max(0.0, float(self._boot()) - float(mono))\n",
             "            return max(0.0, float(self._wall()) - float(mono))\n")], CLOCK)]},
})

EG = "tests.test_ahc_runner.EgressTests."
SM = "tests.test_ahc_runner.StateMachineTests."
SHADOW = "harness/hooks/ahc_shadow.py"
ENTRIES.update({
    "AC-14/NEG-31 chokepoint scan": {
        "tests": [EG + "test_w03_notice_with_a_runtime_token_is_quarantined",
                  EG + "test_every_notice_kind_with_an_embedded_token_is_quarantined"],
        "mutations": [("a notice is written without the R5 scan (the chokepoint bypassed)", [
            ('        if tier["action"] == ahc_scan.QUARANTINE:\n            reason = "R5 quarantined',
             '        if False:\n            reason = "R5 quarantined')], CONTRACTS)]},
    "AC-14 delivery rescans": {
        "tests": [EG + "test_delivery_rescans_a_row_written_around_the_chokepoint"],
        "mutations": [("delivery writes a row without scanning it again", [
            ('            if tier["action"] != ahc_scan.CLEAN:\n', '            if False:\n')], SHADOW)]},
    "AC-14 E12 comment in the outbox": {
        "tests": [EG + "test_e12_comment_is_written_to_the_outbox_and_delivered_only_to_the_digest"],
        "mutations": [("E12 writes no comment or digest line", [
            ('            if unmarked and new["item"]:\n', '            if False:\n')], CONTRACTS)]},
    "AC-9/NEG-25 scheduler skips finished items": {
        "tests": [SM + "test_b_scheduler_skips_rows_of_a_finished_item"],
        "mutations": [("the scheduler offers rows of finished items", [
            ('            % (",".join("?" * len(held)), ",".join("?" * len(self.LIVE_INTENT))), held + self.LIVE_INTENT).fetchall()\n',
             '            % ("?", ",".join("?" * len(self.LIVE_INTENT))), ("none",) + self.LIVE_INTENT).fetchall()\n')], CONTRACTS)]},
    "AC-9 status shows inert rows": {
        "tests": [SM + "test_b_status_and_digest_show_inert_rows"],
        "mutations": [("status shows the row's own state", [
            ('        return "inert: item %s" % owner["state"]\n', '        return row["state"]\n')], SHADOW),
                      ("the digest gets no inert line", [
            ("            if inert:\n                state = ", "            if False:\n                state = ")],
             CONTRACTS)]},
    "AC-9/NEG-25 finding id rule": {
        "tests": [SM + "test_b_findings_producer_writes_finding_ids"],
        "mutations": [("any non-empty string is a finding id, with no cap", [
            ("            if isinstance(i, str) and cls.FINDING_ID.fullmatch(i) and len(kept) < cls.FINDING_IDS_MAX:\n",
             "            if isinstance(i, str) and i:\n")], CONTRACTS)]},
})

ENTRIES.update({
    "AC-5/NEG-14 W7 one grant and intent": {
        "tests": [SM + "test_w07_writes_the_grant_and_intent_only"],
        "mutations": [("W7 skips the non-terminal grant or Effect check", [
            ("            live = self._live_authority(item)\n            if live:\n",
             "            live = self._live_authority(item)\n            if False:\n")], CONTRACTS)]},
    "AC-5/NEG-11 W11 staging target": {
        "tests": [SM + "test_w11_hands_to_staging_and_beats_w12"],
        "mutations": [("W11 without a staging target", [
            ("            if not (isinstance(target, str) and target):\n", "            if False:\n")], CONTRACTS)]},
    "AC-5/NEG-12 W12 independent recorder": {
        "tests": [SM + "test_w12_needs_an_independent_headed_check_bound_to_h"],
        "mutations": [("W12 accepts a check by the author, owner, spec reviewer or evidence poster", [
            ('        if rec["recorder"] in excluded:\n', "        if False:\n")], CONTRACTS)]},
    "AC-5/NEG-13 W15 counts own-content blocks": {
        "tests": [SM + "test_w15_fires_only_on_b7_or_b33_exhaustion"],
        "mutations": [("a base-move re-review block counts toward B7", [
            ("\"('adversarial', 'red-team') AND state='findings' AND base_move=0\",",
             "\"('adversarial', 'red-team') AND state='findings'\",")], CONTRACTS)]},
    "AC-5/NEG-14 W19 incident or ticket": {
        "tests": [SM + "test_w19_incident_for_an_integrity_fault_and_a_ticket_otherwise"],
        "mutations": [("W19 writes a ticket comment for an integrity fault", [
            ('"incident" if refusal["kind"] == "integrity" else "ticket"', '"ticket"')], CONTRACTS)]},
    "AC-5/NEG-5 W22 needs a reported conflict": {
        "tests": [SM + "test_w22_conflict_tells_the_owner_and_the_next_item_heads_the_queue"],
        "mutations": [("W22 on an unknown mergeable_state", [
            ('            if not (o["mergeable"] is False and o["mergeable_state"] == "dirty"):\n',
             '            if o["mergeable"] is not False:\n')], CONTRACTS)]},
    "AC-5 W23 after ten minutes": {
        "tests": [SM + "test_w23_escalates_a_lost_update_after_ten_minutes"],
        "mutations": [("W23 fires before its 10 min", [
            ('            if state == "lost" or self.clock.due(rid, "W23", self.W23_SECONDS):\n',
             "            if True:\n")], CONTRACTS)]},
})

W16 = "tests.test_ahc_runner.W16Tests."
ENTRIES.update({
    "AC-6/NEG-15 W16 proof binding": {
        "tests": [W16 + "test_w16_needs_main_s_verified_proof_for_this_item_target_and_version"],
        "mutations": [("the proof's item, target and version are not checked", [
            ('        if (row["item"], row["target"], row["expected_version"]) != (item["id"], to, item["version"]):\n',
             "        if False:\n")], CONTRACTS),
                      ("an actor string without a proof is accepted", [
            ("        if row is None:\n            raise ContractError(\"W16 needs main's verified stamp proof id; "
             "an actor string is not proof\")\n",
             "        if row is None:\n            return\n")], CONTRACTS)]},
    "AC-6/NEG-15 W16 keeps the counters": {
        "tests": [W16 + "test_w16_to_pr_gate_leaves_b7_b33_and_findings_rows_unchanged"],
        "mutations": [("W16 resets B33", [
            ('            self.db.execute("UPDATE w16_proofs SET used=1 WHERE proof_id=?", (proof,))\n',
             '            self.db.execute("UPDATE w16_proofs SET used=1 WHERE proof_id=?", (proof,))\n'
             '            self.db.execute("UPDATE lineage_budget SET b33_used=0 WHERE lineage=?", (item["lineage"],))\n')],
             CONTRACTS)]},
    "AC-6/NEG-38 latest round and round identity": {
        "tests": [W16 + "test_w16_extension_round_flow_neg38"],
        "mutations": [("e1 and e2 read every round", [
            ('    LATEST_ROUND = " AND round = (SELECT MAX(x.round) FROM reviews x WHERE x.item = reviews.item AND '
             'x.kind = reviews.kind)"\n', '    LATEST_ROUND = ""\n')], CONTRACTS),
                      ("require_review ignores the round", [
            ('"AND packet_sha256=? AND policy_revision=? AND spec_core=? AND round=?",',
             '"AND packet_sha256=? AND policy_revision=? AND spec_core=? AND ?>0",')], CONTRACTS)]},
    "AC-6 W3 acceptance": {
        "tests": [W16 + "test_w16_with_unaccepted_finding_ids_w3_fires_again",
                  W16 + "test_w16_extension_round_flow_neg38"],
        "mutations": [("accepting some finding ids clears W3", [
            ("            if not ids or not set(ids) <= accepted:\n", "            if not ids or not set(ids) & accepted:\n")],
             CONTRACTS)]},
})

GUARD = "harness/hooks/ahc_guard.py"
NM = "tests.test_ahc_guard.NoModelInDaemonTests."
ENTRIES.update({
    "AC-13 unlisted executable": {
        "tests": [NM + "test_neg47_unlisted_executable_is_refused"],
        "mutations": [("an unlisted executable is added to the allowed set", [
            ('EXECUTABLES = ("git", "gh", "systemd-run", "systemctl", "lsof", "fuser", "sysctl")',
             'EXECUTABLES = ("git", "gh", "systemd-run", "systemctl", "lsof", "fuser", "sysctl", "curl")'),
            ("    def _check_sysctl(self, args, cwd):\n",
             "    def _check_curl(self, args, cwd):\n        return None\n\n    def _check_sysctl(self, args, cwd):\n")],
            GUARD)]},
    "AC-13 python -c and helper hash": {
        "tests": [NM + "test_neg47_python_only_as_a_bound_unchanged_helper"],
        "mutations": [("python -c is allowed", [
            ('        if len(args) < 2 or args[1].startswith("-"):\n', "        if len(args) < 2:\n"),
            ('        self.refuse("python: %s is not an installed helper script" % args[1][:120])',
             '        return "python"')], GUARD),
                      ("a listed helper with a changed hash runs", [
            (' or hashlib.sha256(Path(script).read_bytes()).hexdigest() != sha:', ':')], GUARD),
                      ("the helper env is not compared", [
            ("        if env != self.helper_env:\n", "        if False:\n")], GUARD)]},
    "AC-13 inherited environment": {
        "tests": [NM + "test_neg47_resolution_env_and_shell_are_refused",
                  NM + "test_neg44_git_with_added_env_keys_is_refused"],
        "mutations": [("an inherited environment (env None) is accepted", [
            ("        if env is None:\n            self.refuse(", "        if env is None and False:\n            self.refuse("),
            ("        if dict(env) != self.env(name):\n", "        if env is not None and dict(env) != self.env(name):\n")],
            GUARD),
                      ("git env keys are not compared", [
            ("        if dict(env) != self.env(name):\n", "        if False:\n")], GUARD)]},
    "AC-13 trusted file at launch": {
        "tests": [NM + "test_neg47_group_writable_after_start_is_refused"],
        "mutations": [("the launch-time trust check is dropped", [
            ("        problem = trusted_file_problem(args[0])\n        if problem:\n",
             "        problem = trusted_file_problem(args[0])\n        if False:\n")], GUARD)]},
    "AC-13/NEG-44 git table": {
        "tests": [NM + "test_neg44_git_forms_outside_the_table_are_refused"],
        "mutations": [("git options and positionals are not checked", [
            ('            if tok.startswith("-") or not self._git_positional(tok, kinds):\n', "            if False:\n")],
            GUARD),
                      ("the SAFE prefix is not required", [
            ("        if args[:len(prefix)] != prefix:\n", "        if False:\n"),
            ("        rest = args[len(prefix):]\n", "        rest = args[len(prefix):] if args[:len(prefix)] == prefix else args\n")],
            GUARD)]},
    "AC-13/NEG-45 gh table": {
        "tests": [NM + "test_neg45_gh_forms_outside_the_table_are_refused"],
        "mutations": [("any endpoint fills a template", [
            ('        if name is None or m.group("repo").lower() not in self.repos:\n', "        if False:\n"),
            ('        if "--paginate" in rest and not READ_TEMPLATES[name]["paginate"]:\n', "        if False:\n")],
            GUARD)]},
    "AC-13/NEG-45 W21 PUT": {
        "tests": [NM + "test_neg45_w21_put_needs_the_flag_and_the_armed_expectation"],
        "mutations": [("the W21 PUT needs no armed expectation", [
            ('        if armed is None or [self.exe.get("gh")] + list(args) != armed:\n', "        if False:\n")], GUARD),
                      ("AHC_W21_SEND is not checked", [
            ('        if os.environ.get("AHC_W21_SEND") != "1":\n', "        if False:\n")], GUARD)]},
    "AC-13/NEG-46 units": {
        "tests": [NM + "test_neg46_systemd_run_only_the_armed_committed_command_line",
                  NM + "test_neg46_systemctl_verbs_outside_the_table_are_refused",
                  NM + "test_recovery_stop_needs_reconciliation_and_the_review_slice"],
        "mutations": [("systemd-run is not byte-compared with the armed line", [
            ("        if full != armed[0] or argv_digest(full) != armed[1]:\n", "        if False:\n")], GUARD),
                      ("an armed expectation is not consumed", [
            ('        armed = self.armed.pop("systemd-run", None)\n', '        armed = self.armed.get("systemd-run")\n')],
             GUARD),
                      ("recovery stop outside startup reconciliation", [
            ("            if self.reconciling and UNIT.fullmatch(unit) and unit in self.slice_ok:\n",
             "            if UNIT.fullmatch(unit) and unit in self.slice_ok:\n")], GUARD),
                      ("recovery stop without the Slice check", [
            ("            if self.reconciling and UNIT.fullmatch(unit) and unit in self.slice_ok:\n",
             "            if self.reconciling and UNIT.fullmatch(unit):\n")], GUARD)]},
    "AC-13/NEG-48 sockets": {
        "tests": [NM + "test_neg48_sockets_only_unix_paths_under_the_root"],
        "mutations": [("the socket check is dropped", [
            ("        policy.check_connect(args[0], args[1] if len(args) > 1 else None)\n", "        pass\n")], GUARD)]},
    "AC-13/NEG-30 import hook": {
        "tests": [NM + "test_neg30_runtime_provider_import_is_refused_in_a_child"],
        "mutations": [("the import hook is dropped", [
            ("        sys.meta_path.insert(0, _ProviderFinder())\n", ""),
            ('    elif event == "import" and args and isinstance(args[0], str) and _is_provider(args[0]):\n',
             '    elif False:\n')], GUARD)]},
})

ENTRIES.update({
    "ruling 4 macOS boot id": {
        "tests": ["tests.test_ahc_clock.BootIdTests.test_default_boot_id_is_the_host_s_and_stable_across_processes"],
        "mutations": [("macOS keeps the per-process boot id", [
            ('read_boot_id(run=ahc_guard.sysctl_run if sys.platform == "darwin" else None)', "read_boot_id(run=None)")],
            "harness/hooks/ahc_clock.py")]},
})


OBSERVE = "harness/hooks/ahc_observe.py"
OP = "tests.test_ahc_observe.ProducerTests."
OC = "tests.test_ahc_observe.ChecksEvidenceTests."
ENTRIES.update({
    "AC-1/NEG-2 PR identity": {
        "tests": [OP + "test_neg2_another_repo_number_or_short_head_is_refused"],
        "mutations": [("another repo's PR is accepted", [
            ('        if str(base_repo or "").lower() != repo or p.get("number") != pr:\n',
             '        if p.get("number") != pr:\n')], OBSERVE),
                      ("a short head is accepted", [
            ('        if not (isinstance(head, str) and SHA.fullmatch(head)):\n            raise ObservationRefused("the PR head',
             '        if not isinstance(head, str):\n            raise ObservationRefused("the PR head')], OBSERVE)]},
    "AC-1/NEG-3 count check": {
        "tests": [OP + "test_neg3_a_changed_files_count_that_disagrees_fails_closed"],
        "mutations": [("the changed_files count check is dropped", [
            ("        if type(changed) is not int or changed != count:\n", "        if False:\n")], OBSERVE)]},
    "AC-1/NEG-3 local paths and messages": {
        "tests": [OP + "test_neg3_local_git_sees_the_3001st_file_and_the_251st_commit"],
        "mutations": [("commit messages are not read", [
            ("any(foreign_closing_keyword(t, repo) for t in messages + [body])",
             "any(foreign_closing_keyword(t, repo) for t in [body])")], OBSERVE)]},
    "AC-1/NEG-33 M..H not B..H": {
        "tests": [OP + "test_neg33_divergent_history_counts_only_the_prs_own_changes",
                  OP + "test_ac1_fields_come_from_their_named_sources"],
        "mutations": [("paths are read over B..H", [
            ('"--find-renames", "-z", merge_base, head]', '"--find-renames", "-z", tip, head]')], OBSERVE)]},
    "AC-1/NEG-4 head re-read": {
        "tests": [OP + "test_neg4_head_moves_timeout_byte_cap_and_rate_limit_refuse"],
        "mutations": [("the end-of-session head re-read is not compared", [
            ("        if head2 != head:\n", "        if False:\n")], OBSERVE),
                      ("the byte cap is not checked", [
            ('        if len(out.encode("utf-8", "replace")) > ahc_guard.READ_TEMPLATES[name]["max_bytes"]:\n',
             "        if False:\n")], OBSERVE),
                      ("a rate limit does not back off", [
            ("        if self._backing_off(repo):\n", "        if False:\n")], OBSERVE)]},
    "AC-1 budget and deadline": {
        "tests": [OP + "test_ac1_the_call_budget_and_deadline_fail_closed"],
        "mutations": [("the call budget is not enforced", [
            ("        if s[\"calls\"] >= CALL_BUDGET or self.tick_left <= 0:\n", "        if False:\n")], OBSERVE)]},
    "AC-1/NEG-34 body on every read": {
        "tests": [OP + "test_neg34_body_keyword_body_edit_and_bad_body_read"],
        "mutations": [("the body is not checked for a closing keyword", [
            ("any(foreign_closing_keyword(t, repo) for t in messages + [body])",
             "any(foreign_closing_keyword(t, repo) for t in messages)")], OBSERVE),
                      ("a missing body passes as empty", [
            ('        if "body" not in p:\n', "        if False:\n"),
            ('        body = p["body"] if p["body"] is not None else ""\n', '        body = p.get("body") or ""\n')],
                       OBSERVE)]},
    "AC-1 persisted by id": {
        "tests": [OP + "test_ac1_each_read_gets_its_own_id_and_guards_load_it_by_id"],
        "mutations": [("the loaded observation is not checked against its digest", [
            ('        if _sha(fields) != row["digest"]:\n            raise ContractError("observation %s does not match',
             '        if False:\n            raise ContractError("observation %s does not match')], CONTRACTS)]},
    "AC-2/NEG-6 reruns": {
        "tests": [OC + "test_neg6_failed_then_passed_rerun_is_false"],
        "mutations": [("only the latest attempt counts", [("        for r in mine:\n", "        for r in mine[-1:]:\n")],
                       OBSERVE)]},
    "AC-2/NEG-6 duplicate and app": {
        "tests": [OC + "test_neg6_duplicate_context_and_spoofed_app_are_false"],
        "mutations": [("a context also posted as a status is accepted", [
            ("        if ctx in status_contexts:\n", "        if False:\n")], OBSERVE),
                      ("another app's run is accepted", [("            if slug != app:\n", "            if False:\n")],
                       OBSERVE)]},
    "AC-2/NEG-6 missing page": {
        "tests": [OC + "test_neg6_a_missing_page_is_false_or_refused"],
        "mutations": [("the total_count check is dropped", [
            ("    if type(total) is not int or total != len(runs):\n", "    if False:\n")], OBSERVE),
                      ("a gap in the Link chain is accepted", [
            ("        if not last and nxt != idx + 2:\n", "        if False:\n")], OBSERVE)]},
    "AC-2/NEG-6 binding": {
        "tests": [OC + "test_neg6_stale_b_another_head_or_revision_is_false",
                  OC + "test_neg6_injected_true_without_bound_evidence_is_false"],
        "mutations": [("the binding is not compared", [
            ('    return evidence.get("binding") == want\n', "    return True\n")], OBSERVE)]},
    "AC-2/NEG-6 ahc-local": {
        "tests": [OC + "test_neg6_ahc_local_checks_are_false_in_this_slice"],
        "mutations": [("ahc-local requirements are ignored", [
            ('    if req.get("ahc_local"):\n', "    if False:\n")], OBSERVE)]},
})

SB = "tests.test_ahc_runner.ShadowBoundaryTests."
ST = "tests.test_ahc_runner.ShadowTickTests."
SI = "tests.test_ahc_runner.ShadowIntegratedTests."
CRASH = "harness/hooks/ahc_crash.py"
_PUMP = '        if self.w21 is not None:\n            summary["w21"] = self.w21.pump()\n'


def _inject(call):
    """A mutation that adds one gh call on the shadow tick's path, through the producer's gh."""
    return [(_PUMP, "        self.producer._gh(%r, 30)\n" % (call,) + _PUMP)]


ENTRIES.update({
    "AC-3/NEG-7 zero mutating calls": {
        "tests": [SI + "test_ac3_integrated_tick_zero_mutating_calls_one_pipeline_per_repo"],
        "mutations": [
            ("a PUT merge on the tick path", _inject(["api", "--method", "PUT", "repos/o/r/pulls/9/" + "mer" + "ge"]),
             SHADOW),
            ("a GraphQL updateRefs on the tick path",
             _inject(["api", "graphql", "-f", "query=mutation { updateRefs(input: {}) { clientMutationId } }"]),
             SHADOW),
            ("a gh pr comment on the tick path", _inject(["pr", "comment", "9", "-b", "x"]), SHADOW)]},
    "AC-3/NEG-8 one pipeline per repo": {
        "tests": [SI + "test_ac3_integrated_tick_zero_mutating_calls_one_pipeline_per_repo",
                  SI + "test_neg8_a_repo_with_a_live_legacy_item_stays_legacy"],
        "mutations": [
            ("a listed repo with a live legacy item goes shadow", [
                ("    if shadow_on() and repo in listed and repo not in legacy_live_repos(db):\n",
                 "    if shadow_on() and repo in listed:\n")], SHADOW),
            ("a shadow repo's submit enters the legacy pipeline", [
                ('        if ahc_shadow.pipeline_of(ledger.db, norm["repo"], config) == "shadow":\n',
                 "        if False:\n")], RUNNER_PY)]},
    "AC-3 AHC_SHADOW exact value": {
        "tests": [SB + "test_ac3_only_the_exact_value_1_enables_shadow"],
        "mutations": [("a truthy value enables shadow", [
            ('    return os.environ.get(SHADOW_ENV) == "1"\n',
             '    return os.environ.get(SHADOW_ENV, "").strip() in ("1", "true", "yes")\n')], SHADOW)]},
    "AC-3 mutating-call classifier": {
        "tests": [SB + "test_neg7_every_mutating_call_form_is_named"],
        "mutations": [("gh verbs other than api are treated as reads", [
            ("    if args[0] != \"api\":\n        return True\n", "    if args[0] != \"api\":\n        return False\n")],
            SHADOW)]},
    "AC-4/NEG-9 event id": {
        "tests": [ST + "test_neg9_w5_w6_w5_with_identical_facts_each_apply_and_each_item_moves_once_per_tick",
                  ST + "test_ac4_event_id_is_a_function_of_observation_item_and_row_only"],
        "mutations": [("the event id ignores the observation", [
            ("json.dumps([obs_id, item, row])", "json.dumps([item, row])")], SHADOW)]},
    "AC-4/NEG-10 version CAS and guard re-read": {
        "tests": [ST + "test_neg10_two_ticks_on_one_ledger_apply_each_move_exactly_once"],
        "mutations": [("neither the version nor the From state is re-read", [
            ("            if frm not in src:\n                raise ContractError(\"%s does not leave %s\" % (row_id, "
             "frm))\n            if row_id == \"W24\":\n",
             "            if row_id == \"W24\":\n"),
            ("            if item[\"version\"] != expected_version:\n                raise VersionConflict(",
             "            if False:\n                raise VersionConflict(")], CONTRACTS)]},
    "AC-4 admission through an observation": {
        "tests": [ST + "test_ac4_admission_is_refused_when_the_head_moved",
                  ST + "test_ac4_a_held_request_is_admitted_through_one_observation"],
        "mutations": [("admission ignores a moved head", [
            # anchor follows goodqa#16262: the guard is the negated form that drops the request
            ('            if obs["pr_head"] != req["head"] or obs["pr_state"] != "OPEN":\n',
             '            if obs["pr_state"] != "OPEN":\n')], SHADOW)]},
    "AC-4 named crash points": {
        "tests": ["tests.test_ahc_crash.NamedPointTests."
                  "test_ac4_named_points_are_counted_and_a_crash_at_each_keeps_the_invariants"],
        "mutations": [("the tick has no crash point after the producer stamps", [
            ('        crash_at("tick.observed")\n', "        pass\n")], SHADOW)]},
    "AC-13 tick raises incidents": {
        "tests": ["tests.test_ahc_runner.TickIncidentTests.test_ac13_the_tick_raises_collected_refusals_as_incidents"],
        "mutations": [("collected refusals are never raised", [
            ("        while policy.incidents:\n", "        while False:\n")], RUNNER_PY)]},
})


W21 = "tests.test_ahc_runner.W21Tests."
W21_PY = "harness/hooks/ahc_w21.py"

ENTRIES.update({
    "AC-7/NEG-17 attempted commits before the one call": {
        "tests": [W21 + "test_ac7_attempted_commits_before_the_one_call_and_a_lost_response_is_never_resent",
                  W21 + "test_neg17_two_processes_race_one_intent_row_and_exactly_one_sends"],
        "mutations": [
            ("the call is made before the intent->attempted CAS", [
                ('        if not self.c.w21_attempt(rid):\n'
                 '            return None                                    # another process or tick took it, or it is not intent\n',
                 '        self.gh(put_args(row["repo"], row["pr"], row["head"]), 30)\n'
                 '        if not self.c.w21_attempt(rid):\n'
                 '            return None\n')], W21_PY),
            ("the CAS is a plain update that does not check the state", [
                ('        return self._w21_move(rid, ("intent",), "attempted", "send", ", attempted_at=?", (self.now(),))\n',
                 '        self.db.execute("UPDATE w21_sends SET state=\'attempted\', attempted_at=? WHERE request_id=?",\n'
                 '                        (self.now(), rid))\n'
                 '        return True\n')], CONTRACTS)]},
    "AC-7/NEG-16 the flag gates W21 itself": {
        "tests": [W21 + "test_neg16_with_the_flag_off_w21_is_not_applied_at_all"],
        "mutations": [
            ("flag off still writes the intent and the log line", [
                ('            if os.environ.get("AHC_W21_SEND") != "1":\n', '            if False:\n')], CONTRACTS),
            ("a truthy flag value enables the sender", [
                ('    return os.environ.get(FLAG) == "1"\n',
                 '    return os.environ.get(FLAG, "").strip().lower() in ("1", "true")\n')], W21_PY),
            ("the repo policy field is not required", [
                ('            if not (isinstance(pol, dict) and pol.get("w21") is True):\n', '            if False:\n')],
             CONTRACTS)]},
    "AC-7/NEG-19/NEG-41 controls re-read at the send decision": {
        "tests": [W21 + "test_neg19_and_neg41_a_blocking_control_cancels_the_intent_keeps_the_head_then_refires_once",
                  W21 + "test_ac7_send_itself_re_reads_the_controls_for_any_caller"],
        "mutations": [
            ("a direct send skips the controls", [
                ('        why = self.blocked(row)\n', '        why = None\n')], W21_PY),
            ("only the flag is re-read at the send decision", [
                ('        why = self.blocked(row)\n',
                 '        why = None if enabled() else "flag"\n')], W21_PY),
            ("a stale kill reading is accepted", [
                ('                not 0 <= float(self.c._mono()) - float(mono) <= KILL_MAX_AGE:\n',
                 '                False:\n')], W21_PY),
            ("cancel leaves the row holding the repo slot", [
                ('            return self._w21_move(rid, ("intent",), "cancelled", reason, ", reason=?", (str(reason)[:300],))\n',
                 '            return True\n')], CONTRACTS)]},
    "AC-7 cancel only from intent": {
        "tests": [W21 + "test_ac7_cancel_is_reachable_only_from_intent_and_restart_cancels_intent_only"],
        "mutations": [
            ("cancel is allowed from attempted", [
                ('            if row is None or row["state"] != "intent" or row["attempted_at"] is not None:\n',
                 '            if row is None:\n'),
                ('            return self._w21_move(rid, ("intent",), "cancelled", reason, ", reason=?", (str(reason)[:300],))\n',
                 '            return self._w21_move(rid, ("intent", "attempted"), "cancelled", reason, ", reason=?",\n'
                 '                                  (str(reason)[:300],))\n')], CONTRACTS),]},
    "AC-7/NEG-20 read-back records only ahc's update": {
        "tests": [W21 + "test_neg20_neg21_readback_records_only_ahcs_update_and_the_successor_keeps_the_head"],
        "mutations": [
            ("the tree check is dropped (an evil merge passes)", [
                ('        if not tree or tree != merged:\n', '        if not tree:\n')], W21_PY),
            ("parent1 is not checked", [
                ('        if p1 != row["head"] or not (p2 and SHA.fullmatch(p2)):\n',
                 '        if not (p2 and SHA.fullmatch(p2)):\n')], W21_PY)]},
    "AC-7/NEG-21 the successor keeps the queue head": {
        "tests": [W21 + "test_neg20_neg21_readback_records_only_ahcs_update_and_the_successor_keeps_the_head"],
        "mutations": [("no successor exception", [
            ('            if self.w21_successor(item):\n', '            if False:\n')], CONTRACTS)]},
    "AC-7/NEG-37 lost blocks the item until main's W16": {
        "tests": [W21 + "test_neg37_after_a_lost_update_the_next_item_takes_w21_and_the_lost_item_waits_for_w16",
                  W21 + "test_ac7_attempted_commits_before_the_one_call_and_a_lost_response_is_never_resent"],
        "mutations": [
            ("W16 does not resolve the lost send", [
                ('            self.db.execute("UPDATE w21_sends SET state=\'resolved\', reason=?, version=version+1, updated=? WHERE "\n',
                 '            self.db.execute("UPDATE w21_sends SET reason=?, version=version+1, updated=? WHERE "\n')],
             CONTRACTS),
            ("the per-item block is dropped", [
                ('            if self.db.execute("SELECT 1 FROM w21_sends WHERE item=? AND state IN (\'intent\', \'attempted\', "\n',
                 '            if self.db.execute("SELECT 1 FROM w21_sends WHERE item=? AND 0 AND state IN (\'intent\', \'attempted\', "\n')],
             CONTRACTS),
            ("a lost send also blocks the repo", [
                ('            if self.db.execute("SELECT 1 FROM w21_sends WHERE repo=? AND state IN (\'intent\', \'attempted\', "\n'
                 '                               "\'readback-pending\')", (item["repo"],)).fetchone():\n',
                 '            if self.db.execute("SELECT 1 FROM w21_sends WHERE repo=? AND state IN (\'intent\', \'attempted\', "\n'
                 '                               "\'readback-pending\', \'lost\')", (item["repo"],)).fetchone():\n')],
             CONTRACTS)]},
    "AC-7 one unresolved send per repo": {
        "tests": [W21 + "test_ac7_one_unresolved_send_per_repo_by_the_guard_and_by_the_index"],
        "mutations": [
            ("the per-repo guard is dropped", [
                ('            if self.db.execute("SELECT 1 FROM w21_sends WHERE repo=? AND state IN (\'intent\', \'attempted\', "\n',
                 '            if self.db.execute("SELECT 1 FROM w21_sends WHERE repo=? AND 0 AND state IN (\'intent\', \'attempted\', "\n')],
             CONTRACTS),
            ("the partial unique index is dropped", [
                ('CREATE UNIQUE INDEX IF NOT EXISTS w21_one_unresolved_per_repo ON w21_sends(repo)\n',
                 'CREATE INDEX IF NOT EXISTS w21_one_unresolved_per_repo ON w21_sends(repo)\n')], CONTRACTS)]},
    "AC-7/NEG-42 retry writes the same line": {
        "tests": [W21 + "test_neg42_a_retry_after_a_rolled_back_w21_writes_the_same_line_and_sends_once"],
        "mutations": [
            ("the line carries a time stamp", [
                ('                               "request_id": rid, "action": "update-branch"})\n',
                 '                               "request_id": rid, "action": "update-branch", "at": self.now()})\n')],
             CONTRACTS),
            ("the request id is random", [
                ('        rid, aev = "w21-" + key[:32], "w21:" + key[:32]\n',
                 '        rid, aev = "w21-" + os.urandom(8).hex(), "w21:" + os.urandom(8).hex()\n')], CONTRACTS)]},
    "AC-7 authority log flock": {
        "tests": [W21 + "test_ac7_the_authority_append_holds_an_exclusive_flock",
                  W21 + "test_neg17_two_processes_race_one_intent_row_and_exactly_one_sends"],
        "mutations": [("the read-check-append runs without the lock", [
            ('            fcntl.flock(lock, fcntl.LOCK_EX)\n', '            pass\n')], CONTRACTS)]},
    "AC-7/NEG-18 named send points": {
        "tests": ["tests.test_ahc_crash.NamedPointTests.test_ac4_named_points_are_counted_and_a_crash_at_each_keeps_the_invariants"],
        "mutations": [
            ("w21.before_send is not a crash point", [('        crash_at("w21.before_send")\n', '')], W21_PY),
            ("restart re-sends an attempted row", [
                ('        for (rid,) in self.c.db.execute("SELECT request_id FROM w21_sends WHERE state=\'intent\' ORDER BY created, "\n',
                 '        for (rid,) in self.c.db.execute("SELECT request_id FROM w21_sends WHERE state IN (\'intent\', \'attempted\') ORDER BY created, "\n'),
                ('        if row is None or row["state"] != "intent":\n            return None\n',
                 '        if row is None or row["state"] not in ("intent", "attempted"):\n            return None\n'),
                ('        why = self.blocked(row)\n', '        why = None if row["state"] == "attempted" else self.blocked(row)\n'),
                ('        if not self.c.w21_attempt(rid):\n'
                 '            return None                                    # another process or tick took it, or it is not intent\n',
                 '        if not self.c.w21_attempt(rid) and self.c._row("w21_sends", "request_id", rid)["state"] != "attempted":\n'
                 '            return None\n')], W21_PY)]},
})


LP = "tests.test_ahc_guard.LegacyProductionPathTests."

ENTRIES.update({
    "AC-13 helper sha from the release list": {
        "tests": [LP + "test_helper_sha_binds_to_the_release_list_not_the_file_at_start",
                  LP + "test_the_shipped_release_list_binds_each_helper_to_its_repo_file"],
        "mutations": [
            ("the helper sha is the file's at daemon start (owner ruling e)", [
                ('            want = self.release.get(name)\n',
                 '            want = hashlib.sha256(Path(script).read_bytes()).hexdigest()\n')], GUARD),
            ("the shipped list carries no helpers section", [
                ('    want = {"files": current(), "helpers": helpers(),\n',
                 '    want = {"files": current(), "helpers": {},\n')], "scripts/ahc_release_hashes.py")]},
})


RT = "tests.test_ahc_contracts.RuntimeTests."
OR = "tests.test_ahc_guard.OrphanRecoveryTests."
REVIEW_PY = "harness/hooks/ahc_review.py"

ENTRIES.update({
    "AC-8 R3 test_r03 launch intent": {
        "tests": [RT + "test_r03_the_intent_binds_the_full_command_line_and_charges_b33_once"],
        "mutations": [
            ("the digest leaves the systemd-run properties out", [
                ('            digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode("utf-8")).hexdigest()\n',
                 '            digest = hashlib.sha256(json.dumps(argv[argv.index("--"):], separators=(",", ":")).encode("utf-8")).hexdigest()\n')],
             CONTRACTS),
            ("no B33 charge at intent", [
                ('            self.charge_b33(lineage)\n            self._a0("launch_intent", iid, None, "open",',
                 '            self._a0("launch_intent", iid, None, "open",')], CONTRACTS),
            ("the bound argv carries --author-harness", [
                ('        "--expected-head", row["head"], "--snapshot-base", base, "--base", base,\n',
                 '        "--expected-head", row["head"], "--snapshot-base", base, "--base", base, "--author-harness", "claude",\n')], REVIEW_PY)]},
    "AC-8 R3 runner and isolation": {
        "tests": [RT + "test_r03_without_isolation_the_row_goes_to_infra_wait_and_no_runner_comes_from_config",
                  RT + "test_r03_rc_is_allowed_only_for_the_sandbox_repo"],
        "mutations": [
            ("a runner is injectable through the constructor", [
                ('    def __init__(self, contracts, policy, helper_script, root, clone):\n',
                 '    def __init__(self, contracts, policy, helper_script, root, clone, runner=None):\n')],
             REVIEW_PY),
            ("production always builds the runner", [
                ('        self.runner = SystemdRunner(policy) if SystemdRunner.available(policy) and wrapper.is_file() else None\n',
                 '        self.runner = SystemdRunner(policy)\n')], REVIEW_PY),
            ("R-c on any repo", [
                ('        if self.policy.unit_scope == "--user" and row["repo"] != sandbox_repo:\n', '        if False:\n')],
             REVIEW_PY)]},
    "AC-8/NEG-22 CAS failure": {
        "tests": [RT + "test_neg22_a_failed_start_attempt_stops_the_unit_and_keeps_the_charge_until_b33_is_spent"],
        "mutations": [
            ("the unit is not stopped", [
                ('    try:\n        runner.stop(unit)\n    except ahc_guard.LaunchRefused:\n        return None\n'
                 '    return observed_inactive(',
                 '    try:\n        pass\n    except ahc_guard.LaunchRefused:\n        return None\n'
                 '    return observed_inactive(')], REVIEW_PY),
            ("the charge is refunded", [
                ('        if self.retire(intent["id"]):\n            return "refused", why\n',
                 '        if self.retire(intent["id"]):\n'
                 '            self.c.db.execute("UPDATE lineage_budget SET b33_used = b33_used - 1")\n'
                 '            return "refused", why\n')], REVIEW_PY),
            ("B33 is not checked at intent", [
                ('            if used >= budget:\n                raise ContractError("B33 spent: %d of %d model runs for the lineage; the row stops launching"\n',
                 '            if False:\n                raise ContractError("B33 spent: %d of %d model runs for the lineage; the row stops launching"\n')],
             CONTRACTS)]},
    "AC-8/NEG-36 orphan recovery": {
        "tests": [RT + "test_neg36_an_orphan_unit_is_stopped_once_charged_once_and_settles_nothing",
                  "tests.test_ahc_crash.NamedPointTests.test_ac4_named_points_are_counted_and_a_crash_at_each_keeps_the_invariants"],
        "mutations": [
            ("the orphan is not stopped", [
                ('        self.retire(out, intent["id"], "unit of intent %s" % intent["id"])\n',
                 '        self.c.intent_retire(intent["id"], "inactive", "not stopped")\n'
                 '        out["orphaned"].append(intent["id"])\n')], REVIEW_PY),
            ("a second unit starts while one may be live", [
                ('            if self.db.execute("SELECT 1 FROM launch_intents WHERE row=? AND state IN (%s)"\n',
                 '            if self.db.execute("SELECT 1 FROM launch_intents WHERE row=? AND 0 AND state IN (%s)"\n')],
             CONTRACTS),
            ("startup reconciliation is skipped", [
                ('            units = self.runner.list_units()\n', '            units = []\n')], REVIEW_PY)]},
    "AC-13/NEG-49 orphan recovery through the guard": {
        "tests": [OR + "test_neg49_orphan_recovery_through_the_production_launch_guard",
                  OR + "test_neg49_a_unit_never_confirmed_inactive_blocks_its_row_after_60_s_and_nothing_else"],
        "mutations": [
            ("the Slice check is dropped", [
                ('            if self.reconciling and UNIT.fullmatch(unit) and unit in self.slice_ok:\n',
                 '            if self.reconciling and UNIT.fullmatch(unit):\n')], GUARD),
            ("the startup-only rule is dropped", [
                ('            if self.reconciling and UNIT.fullmatch(unit) and unit in self.slice_ok:\n',
                 '            if UNIT.fullmatch(unit) and unit in self.slice_ok:\n')], GUARD),
            ("the R3 command line leaves --slice out", [
                ('        "--unit=" + unit, "--slice=" + ahc_guard.REVIEW_SLICE, "--collect",',
                 '        "--unit=" + unit, "--collect",')], REVIEW_PY),
            ("an unconfirmed stop is not bounded", [
                ('        if contracts._mono() - start >= bound:\n            return None\n        sleep(1.0)\n'
                 '    return None\n',
                 '        if contracts._mono() - start >= bound:\n            return "inactive"\n        sleep(1.0)\n'
                 '    return "inactive"\n')], REVIEW_PY)]},
    "AC-8 R4 peer uid": {
        "tests": [RT + "test_r04_the_peer_uid_comes_from_a_real_socketpair"],
        "mutations": [
            ("the uid is the bound one, not the socket's", [
                ('    uid = peer_uid(sock)\n    to, receipt = _final(read_final(sock))\n',
                 '    uid = contracts._row("reviews", "id", rid)["producer_uid"]\n    to, receipt = _final(read_final(sock))\n')],
             REVIEW_PY),
            ("an oversize FINAL is truncated", [
                ('        if size > limit:\n            raise C.ContractError("the FINAL is longer than %d bytes; refused" % limit)\n',
                 '        if size > limit:\n            break\n')], REVIEW_PY)]},
    "AC-8 R4 test_r04_rc_refuses_usage_store": {
        "tests": [RT + "test_r04_rc_refuses_usage_store"],
        "mutations": [
            ("a usage-store FINAL is accepted", [
                ('    if source != "stdout-pipe":\n', '    if False:\n')], REVIEW_PY),
            ("the InvocationID is not compared", [
                ('    if not invocation_id or invocation_id != expected_invocation or exit_status != 0:\n',
                 '    if exit_status != 0:\n')], REVIEW_PY)]},
})


SR = "tests.test_ahc_runner.StartupReconcileTests."

ENTRIES.update({
    "AC-8/NEG-36 reconciliation at daemon start": {
        "tests": [SR + "test_ac8_startup_reconciliation_stops_an_orphan_and_raises_its_incident",
                  SR + "test_ac8_the_daemon_reconciles_before_its_first_tick"],
        "mutations": [
            ("the daemon does not reconcile at start", [
                ('    log.info("startup reconciliation %s", json.dumps(startup_reconcile(paths, policy, role=args.role), default=str))\n',
                 '')],
             RUNNER_PY),
            ("reconciliation findings are not raised", [
                ('        for text in out["incidents"]:\n            raise_incident(contracts, "reconcile", text)\n', '')],
             RUNNER_PY)]},
})


SCAN_PY = "harness/hooks/ahc_scan.py"

ENTRIES.update({
    "AC-8 R2 test_r02 core-built packet": {
        "tests": [RT + "test_r02_core_builds_the_packet_from_its_own_snapshot_and_lints_it",
                  RT + "test_r02_the_build_fails_closed_and_queues_only_its_own_packet"],
        "mutations": [
            ("NEG-23: the fence does not escape its terminator", [
                ('    body = str(text).replace("\\\\", "\\\\\\\\").replace("<<<", "<<\\\\<")\n', '    body = str(text)\n')],
             REVIEW_PY),
            ("the owner section is not linted", [
                ('    findings = lint((("diff", diff), ("commit messages", messages), ("owner section", owner_text)))\n',
                 '    findings = lint((("diff", diff), ("commit messages", messages)))\n')], REVIEW_PY),
            ("the commit messages are not linted", [
                ('    findings = lint((("diff", diff), ("commit messages", messages), ("owner section", owner_text)))\n',
                 '    findings = lint((("diff", diff), ("owner section", owner_text)))\n')], REVIEW_PY),
            ("a failed git read builds a packet anyway", [
                ('        if rc != 0:\n            raise C.ContractError("R2: git %s failed; the packet is not built" % args[0])\n',
                 '        if rc != 0:\n            return ""\n')], REVIEW_PY),
            ("any packet queues the row", [
                ('    if (packet["sha256"], packet["head"], packet["snapshot_base"]) != (row["packet_sha256"], row["head"],\n',
                 '    if False and (packet["sha256"], packet["head"], packet["snapshot_base"]) != (row["packet_sha256"], row["head"],\n')],
             REVIEW_PY)]},
    "AC-8 R5 test_r05 encodings and corpus": {
        "tests": [RT + "test_r05_every_encoding_and_alignment_reaches_the_tiers_and_the_corpus_covers_fixtures"],
        "mutations": [
            ("the fixtures leave the corpus", [
                ('        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "*.py", "*.md", "tests/data/*"],\n',
                 '        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "*.py", "*.md"],\n')],
             "tests/test_ahc_scan.py"),
            ("the exemption list is not a protected path", [
                ('    return any(fnmatch.fnmatch(name, pattern) for pattern in PROTECTED) or path.startswith(".claude/")\n',
                 '    return (any(fnmatch.fnmatch(name, pattern) for pattern in PROTECTED) and "corpus_exempt" not in name) or path.startswith(".claude/")\n')],
             RUNNER_PY)]},
})


RTT = "tests.test_ahc_runner.ReviewTickTests."
OPT_A = RTT + "test_ac8_the_tick_admits_schedules_r3_settles_through_the_peer_uid_and_offers_the_next_row"

ENTRIES.update({
    "AC-8 option A: the tick schedules R3": {
        "tests": [OPT_A],
        "mutations": [
            ("the tick drops the scheduler call", [
                ('            summary["scheduled"] = ReviewScheduler(self.c, self.review.launch_row, slots=self.review.slots).tick(tag)\n',
                 '            summary["scheduled"] = {"offered": [], "started": [], "refused": []}\n')], SHADOW),
            ("admission keeps the owner's packet sha", [
                # anchor follows goodqa#16262: admit_item runs in admit_requests' own transaction
                ('                                             packet["sha256"], event_id=event_id(obs["id"], key, "W1"),\n',
                 '                                             req["packet_sha256"], event_id=event_id(obs["id"], key, "W1"),\n')],
             SHADOW),
            ("the tick never settles completion signals", [
                ('            summary["review"] = self.review.settle()\n',
                 '            summary["review"] = {"settled": [], "unverified": [], "unknown": []}\n')], SHADOW)]},
    "AC-8 option A: core reads the verdict from the report": {
        "tests": [OPT_A, RT + "test_r04_option_a_settles_only_from_the_core_read_report",
                  RT + "test_r04_option_a_every_mismatch_settles_nothing"],
        "mutations": [
            ("core takes the wrapper's verdict field", [
                ('    verdict = report_verdict(raw, row) if rc in (ahc_core.EXIT_PASS, ahc_core.EXIT_BLOCK) else None\n',
                 '    verdict = json.loads(data.decode("utf-8")).get("verdict") or (report_verdict(raw, row) if rc in '
                 '(ahc_core.EXIT_PASS, ahc_core.EXIT_BLOCK) else None)\n')],
             REVIEW_PY),
            ("the report sha256 is not checked", [
                ('    if hashlib.sha256(raw).hexdigest() != fin["report_sha256"]:\n', '    if False:\n')], REVIEW_PY),
            ("the InvocationID is not checked", [
                ('    if not props.get("InvocationID") or props.get("InvocationID") != fin["invocation_id"]:\n',
                 '    if False:\n')], REVIEW_PY),
            ("the reviewed packet sha is not checked", [
                ('    if fields.get("Reviewed packet SHA-256") != row["packet_sha256"]:\n', '    if False:\n')],
             REVIEW_PY),
            ("the reviewed head is not checked", [
                ('    if fields.get("Reviewed HEAD") != row["head"]:\n', '    if False:\n')], REVIEW_PY),
            ("a verdict anywhere in the report counts", [
                ('    match = ahc_core._PASS_LINE.fullmatch(first)\n',
                 '    match = ahc_core._PASS_LINE.search(raw.decode("utf-8", errors="replace"))\n')], REVIEW_PY),
            ("the report is read following links", [
                ('        raw = ahc_core.read_regular_resolved(output, ahc_core.REPORT_MAX_BYTES)\n    except ahc_core.Unreadable as error:\n',
                 '        raw = open(output, "rb").read()\n    except OSError as error:\n        error.kind = "absent"\n')],
             REVIEW_PY)]},
    "AC-8 option A: outcome-unknown and the report directory": {
        "tests": [RT + "test_r07_option_a_a_unit_that_ends_or_outlives_its_bound_with_no_final_is_outcome_unknown",
                  RT + "test_r03_the_intent_binds_the_full_command_line_and_charges_b33_once"],
        "mutations": [
            ("a unit that ended is waited on", [
                ('        return state in C.Contracts.CONFIRMED_INACTIVE or (state == "active" and props.get("SubState") == "exited")\n',
                 '        return False\n')], REVIEW_PY),
            ("a silent unit is waited on forever", [
                ('                    if not over and now - li["updated"] <= REVIEW_MAX + SETTLE_GRACE:\n',
                 '                    if not over:\n')], REVIEW_PY),
            ("the report directory is not granted to the unit's uid", [
                ('                self.runner.grant_output(attempt["out_dir"], uid)\n', '                pass\n')],
             REVIEW_PY),
            ("the report directory is made world-writable (makedirs + chmod 0777), not fresh", [
                ('            ahc_fs.make_fresh_dir(self.root, attempt["out_dir"])\n',
                 '            os.makedirs(attempt["out_dir"], exist_ok=True)\n            os.chmod(attempt["out_dir"], 0o777)\n')],
             REVIEW_PY)]},
})


ENTRIES.update({
    "AC-7 W21 successor at H' (B_r = parent2, R2 packet)": {
        "tests": ["tests.test_ahc_runner.ShadowTickTests.test_ac7_w21_successor_at_h_prime_gets_core_r2_packet_with_b_r_parent2"],
        "mutations": [
            ("the successor's B_r is the item's base", [
                ('            kw["successor_packet"], kw["successor_base"] = packet["sha256"], base\n',
                 '            kw["successor_packet"], kw["successor_base"] = packet["sha256"], None\n')], SHADOW),
            ("H'^2 is not checked", [
                ('            if rc != 0 or out.strip() != base:\n', '            if False:\n')], SHADOW),
            ("the successor's rows are not queued", [
                ('                    self.r2_queue_item(succ, packet)\n', '                    pass\n')], SHADOW),
            ("a resolved send is not recognised (W4 waits forever)", [
                ('        if send:\n            base = send[0]\n', '        if False:\n            base = send[0]\n')],
             SHADOW)]},
})


ENTRIES.update({
    "AC-11/AC-13 open-file probe under the guard": {
        "tests": ["tests.test_ahc_guard.MigrateProbeTests.test_ac11_the_probe_runs_through_the_policy_form_at_the_root_only_while_migrating",
                  "tests.test_ahc_guard.MigrateProbeTests.test_ac11_the_ledger_opens_the_migrating_gate_for_the_migration_only"],
        "mutations": [
            ("the probe runs at cwd /", [
                ('    rc, out, err = ahc_core.run_argv(full, timeout, cwd=policy.root, env=policy.env(name))\n',
                 '    rc, out, err = ahc_core.run_argv(full, timeout, cwd="/", env=policy.env(name))\n')], GUARD),
            ("the ledger never opens the gate", [
                ('            policy.migrating = True\n', '            policy.migrating = False\n')], RUNNER_PY),
            ("the gate stays open after the migration", [
                ('            if policy is not None:\n                policy.migrating = False\n',
                 '            pass\n')], RUNNER_PY)]},
})


ENTRIES.update({
    "PR 272 F1 a current v5 ledger takes no migration lock; only core reconciles": {
        "tests": ["tests.test_ahc_runner.MigrationV5Tests.test_f1_a_current_v5_ledger_opens_while_the_review_role_runs",
                  "tests.test_ahc_runner.MigrationV5Tests.test_f1_both_roles_start_together_on_a_v5_ledger",
                  "tests.test_ahc_runner.StartupReconcileTests.test_f1_only_core_reconciles_and_migrates_at_start"],
        "mutations": [
            ("a current v5 ledger still waits on both role locks", [
                ('        if self._v5_current():\n            return\n        root = self.paths.root\n',
                 '        root = self.paths.root\n')], RUNNER_PY),
            ("the review role reconciles (and opens a migrating ledger) at start", [
                ('    if role not in ("core", "all"):\n        return {"skipped"',
                 '    if False:\n        return {"skipped"')], RUNNER_PY)]},
    "PR 272 F2 no R3 launch until a reconciliation succeeds": {
        "tests": ["tests.test_ahc_runner.ReviewTickTests.test_neg36_a_failed_unit_listing_closes_every_launch_until_a_reconciliation_succeeds",
                  "tests.test_ahc_contracts.RuntimeTests.test_neg36_launch_intent_refuses_until_a_reconciliation_succeeds"],
        "mutations": [
            ("launch_intent ignores the reconciliation gate", [
                ('            if not self.reconcile_open():\n                raise ContractError("the last reconciliation',
                 '            if False:\n                raise ContractError("the last reconciliation')], CONTRACTS),
            ("the Launcher never retries reconciliation", [
                ('            Reconciler(self.c, self.policy, self.runner).run()\n            if not self.c.reconcile_open():',
                 '            if not self.c.reconcile_open():')], REVIEW_PY),
            ("a list-units failure is recorded as success", [
                ('self.c.reconcile_state("failed", "list-units failed")',
                 'self.c.reconcile_state("ok", "list-units failed")')], REVIEW_PY)]},
    "PR 272 F3 the settled receipt names the report's finding ids": {
        "tests": ["tests.test_ahc_runner.ReviewTickTests.test_ac9_a_block_reports_finding_ids_reach_w3_and_main_accepts_them"],
        "mutations": [
            ("the receipt names no finding id", [
                ('    ids = report_finding_ids(raw) if verdict != "PASS" else []\n', '    ids = []\n')], REVIEW_PY),
            ("a heading marker hides the id", [
                ('(?:#{1,6}[ \\t]+|[-*][ \\t]+)?(?:Finding', '(?:Finding')], REVIEW_PY)]},
    "PR 272 F4 no crash window strands a review": {
        "tests": ["tests.test_ahc_contracts.RuntimeTests.test_f4_a_crash_before_the_unit_starts_is_orphaned_and_the_row_launches_again",
                  "tests.test_ahc_contracts.RuntimeTests.test_f4_b_a_crash_right_after_start_attempt_leaves_a_started_intent_that_the_sweep_settles",
                  "tests.test_ahc_contracts.RuntimeTests.test_f4_reconciliation_recovers_a_running_row_whose_intent_is_still_open"],
        "mutations": [
            ("the running binding commits without the started move", [
                ("            if intent is not None:\n                li = self._row(\"launch_intents\", \"id\", intent)",
                 "            if False:\n                li = self._row(\"launch_intents\", \"id\", intent)")], CONTRACTS),
            ("reconciliation skips intents whose unit is not listed", [
                ('                if li["unit"] not in listed:\n',
                 '                if False:\n')], REVIEW_PY),
            ("reconciliation orphans the listed unit of a bound running row", [
                ('        if state == "open":\n            if self.bound_running(intent):\n                self.recover_bound(out, intent)\n'
                 '                return\n', '        if state == "open":\n')], REVIEW_PY),
            ("reconciliation orphans the absent unit of a bound running row", [
                ('        if intent["state"] == "open":\n            if self.bound_running(intent):\n'
                 '                self.recover_bound(out, intent)\n                return\n',
                 '        if intent["state"] == "open":\n')], REVIEW_PY)]},
    "PR 272 F5 an intent closes only on a confirmed stop": {
        "tests": ["tests.test_ahc_contracts.RuntimeTests.test_f5_an_unconfirmed_cleanup_stop_keeps_the_intent_and_no_replacement_unit_starts",
                  "tests.test_ahc_contracts.RuntimeTests.test_f5_reconciliation_stops_an_active_unit_whose_intent_is_closed_or_orphaned"],
        "mutations": [
            ("the launch cleanup closes the intent whatever the stop did", [
                ('        if self.retire(intent["id"]):\n            return "refused", why\n',
                 '        if self.c.intent_retire(intent["id"], "inactive", "unconfirmed"):\n            return "refused", why\n')],
             REVIEW_PY),
            ("the stop's return value is taken as the confirmation", [
                ("    try:\n        runner.stop(unit)\n    except ahc_guard.LaunchRefused:\n        return None\n"
                 "    return observed_inactive(contracts, runner, unit, bound=bound, sleep=sleep)\n",
                 "    try:\n        return 'inactive' if runner.stop(unit) else None\n    except ahc_guard.LaunchRefused:\n"
                 "        return None\n")], REVIEW_PY),
            ("the sweep never retries a stopping intent (an abandoned launch)", [
                ("            done = self.launcher.retire(iid)\n",
                 "            done = self.launcher.retire(iid) if state != 'stopping' else None\n")], REVIEW_PY),
            ("reconciliation skips an active unit of a closed or orphaned intent", [
                ('            if props.get("ActiveState") in C.Contracts.CONFIRMED_INACTIVE:\n                return\n'
                 '            self.incident(out, "reconciliation: %s is %s although',
                 '            if True:\n                return\n'
                 '            self.incident(out, "reconciliation: %s is %s although')], REVIEW_PY)]},
    "PR 272 F6 cancellation stops the unit and completes R15": {
        "tests": ["tests.test_ahc_runner.ReviewTickTests.test_f6_w20_owner_cancel_stops_the_unit_and_settles_the_row_superseded",
                  "tests.test_ahc_runner.ReviewTickTests.test_f6_w4_head_supersede_stops_the_unit_and_settles_the_row_superseded",
                  "tests.test_ahc_contracts.RuntimeTests.test_f6_a_cancelled_outcome_unknown_row_settles_superseded"],
        "mutations": [
            ("the sweep leaves cancelling rows alone", [
                ('                else:\n                    self.c.intent_move(iid, ("started",), "stopping", "the row is %s" % (',
                 '                elif row["state"] == "cancelling":\n                    continue\n                else:\n'
                 '                    self.c.intent_move(iid, ("started",), "stopping", "the row is %s" % ('),
                ("\"SELECT id, version FROM reviews r WHERE state='cancelling' AND NOT EXISTS",
                 "\"SELECT id, version FROM reviews r WHERE state='never' AND NOT EXISTS")], REVIEW_PY),
            ("a cancellation completes without a confirmed stop", [
                ('    observed = confirm_stopped(contracts, runner, li["unit"], bound=bound, sleep=sleep)\n'
                 '    if observed is None:\n        return None\n',
                 '    observed = "inactive"\n')], REVIEW_PY),
            ("an outcome-unknown row cancelled after its intent closed never settles", [
                ("\"SELECT id, version FROM reviews r WHERE state='cancelling' AND NOT EXISTS",
                 "\"SELECT id, version FROM reviews r WHERE state='never' AND NOT EXISTS")], REVIEW_PY)]},
    "PR 272 F7 the policy's B33 and exhaustion bind the scheduler": {
        "tests": ["tests.test_ahc_contracts.RuntimeTests.test_f7_launch_intent_takes_b33_from_the_items_recorded_policy",
                  "tests.test_ahc_contracts.RuntimeTests.test_f7_launch_intent_refuses_a_row_of_an_exhausted_item",
                  "tests.test_ahc_contracts.RuntimeTests.test_f7_offerable_rows_skip_exhausted_items_and_spent_lineages",
                  "tests.test_ahc_runner.ReviewTickTests.test_f7_a_policy_b33_of_one_stops_every_launch_and_charge_after_the_first"],
        "mutations": [
            ("launch_intent ignores the recorded policy budget", [
                ("            used, budget = self.launch_budget(item, budget_obs) if item else self.b33(lineage, "
                 "budget_obs)\n", "            used, budget = self.b33(lineage, budget_obs)\n")], CONTRACTS),
            ("launch_intent launches a row of an exhausted item", [
                ('            if item is not None and item["state"] == "exhausted":\n',
                 '            if False:\n')], CONTRACTS),
            ("offerable_rows offers exhausted items", [
                ('        held = self.FINISHED + ("exhausted",)\n', '        held = self.FINISHED\n')], CONTRACTS),
            ("offerable_rows offers a spent lineage", [
                ("            if used < budget:\n                out.append(self._row(\"reviews\", \"id\", rid))\n",
                 "            if True:\n                out.append(self._row(\"reviews\", \"id\", rid))\n")], CONTRACTS),
            ("the integrated tick: neither gate", [
                ("            used, budget = self.launch_budget(item, budget_obs) if item else self.b33(lineage, "
                 "budget_obs)\n", "            used, budget = self.b33(lineage, budget_obs)\n"),
                ('        held = self.FINISHED + ("exhausted",)\n', '        held = self.FINISHED\n'),
                ('            if item is not None and item["state"] == "exhausted":\n', '            if False:\n'),
                ("            if used < budget:\n                out.append(self._row(\"reviews\", \"id\", rid))\n",
                 "            if True:\n                out.append(self._row(\"reviews\", \"id\", rid))\n")], CONTRACTS)]},
})

RX = "tests.test_ahc_contracts.RuntimeTests.test_rescue_"
ENTRIES.update({
    "PR 272 rescue F1 the unit lifecycle is a durable state machine": {
        "tests": [RX + "f1_a_valid_final_never_retires_the_intent_before_its_unit_is_confirmed_stopped",
                  RX + "f1_a_crash_between_settlement_and_the_stop_leaves_cleanup_that_is_finished",
                  RX + "f1_remain_after_exit_an_exited_unit_is_given_up_and_still_stopped_before_it_retires",
                  RX + "f1_only_intent_retire_writes_a_terminal_state_and_only_on_a_confirmed_stop",
                  RX + "f1_a_stopping_intent_after_a_restart_is_retried_through_the_guards_intent_form",
                  RX + "f1_the_observed_t2_dev_triple_active_exited_success_is_ended_but_never_a_stop",
                  RX + "f1_a_final_sent_just_after_the_drain_by_a_unit_that_then_exits_is_settled_not_given_up"],
        "mutations": [
            ("the sweep reads ended() after the inbox drain (a FINAL sent just before the exit is given up)", [
                ('        self.sweep(out, ended)\n', '        self.sweep(out)\n')], REVIEW_PY),
            ("Result=success counts as a confirmed stop (the t2-dev triple active/exited/success)", [
                ('            state = (runner.show(unit, ("ActiveState",)) or {}).get("ActiveState")\n',
                 '            props = runner.show(unit, ("ActiveState", "Result")) or {}\n'
                 '            state = "inactive" if props.get("Result") == "success" else props.get("ActiveState")\n')],
             REVIEW_PY),
            ("a settled attempt's intent closes before its unit is stopped", [
                ('            if not self.intent_move(iid, ("started",), "stopping", reason, retire_to="closed"):\n',
                 '            if not self.db.execute("UPDATE launch_intents SET state=\'closed\' WHERE id=?", (iid,)).rowcount:\n')],
             CONTRACTS),
            ("an active (exited) unit counts as a confirmed stop", [
                ('        if state in C.Contracts.CONFIRMED_INACTIVE:\n            return state\n',
                 '        if state in C.Contracts.CONFIRMED_INACTIVE or state == "active":\n            return "inactive"\n')],
             REVIEW_PY),
            ("RemainAfterExit: an active/exited unit is not ended", [
                (' or (state == "active" and props.get("SubState") == "exited")\n', '\n')], REVIEW_PY),
            ("stopping is not a live intent (the guard and the sweep forget it)", [
                ('    LIVE_INTENT = ("open", "started", "stopping")\n', '    LIVE_INTENT = ("open", "started")\n')],
             CONTRACTS),
            ("intent_move takes any edge, a terminal target included (both halves of the edge check removed)", [
                ('        if to in self.TERMINAL_INTENT or any((f, to) not in self.INTENT_EDGES for f in frm):\n',
                 '        if False:\n')], CONTRACTS),
            ("intent_retire accepts an unconfirmed observation", [
                ('        if observed not in self.CONFIRMED_INACTIVE:\n            raise ContractError(',
                 '        if False:\n            raise ContractError(')], CONTRACTS),
            ("reconciliation leaves a stopping intent alone", [
                ('        state = intent["state"]\n        if state == "started":\n',
                 '        state = intent["state"]\n        if state in ("started", "stopping"):\n')], REVIEW_PY)]},
    "PR 272 rescue F2 the bound argv carries --snapshot-base B_r": {
        "tests": [RX + "f2_the_r3_command_line_names_b_r_as_the_snapshot_base_inside_the_digest",
                  "tests.test_ahc_contracts.R3SnapshotBaseTests.test_rescue_f2_the_real_helper_reviews_b_r_to_h_when_b_r_is_not_h_first_parent",
                  "tests.test_ahc_contracts.RuntimeTests.test_r03_the_intent_binds_the_full_command_line_and_charges_b33_once"],
        "mutations": [
            ("no --snapshot-base (peer_review snapshots H^1..H)", [
                ('"--snapshot-base", base, "--base", base,\n', '"--base", base,\n')], REVIEW_PY),
            ("--snapshot-base names H, not B_r", [
                ('"--snapshot-base", base, "--base", base,\n', '"--snapshot-base", row["head"], "--base", base,\n')],
             REVIEW_PY)]},
    "PR 272 rescue A-1 production fails closed to infra-wait while the wrapper is absent": {
        "tests": [RX + "a1_every_production_r3_launch_goes_to_infra_wait_while_the_wrapper_is_absent"],
        "mutations": [
            ("production builds the runner without the wrapper", [
                ('        self.runner = SystemdRunner(policy) if SystemdRunner.available(policy) and wrapper.is_file() else None\n',
                 '        self.runner = SystemdRunner(policy) if SystemdRunner.available(policy) else None\n')], REVIEW_PY)]},
})

# PR 273 receipt (main's exact-head BLOCK at 3932ba67): r273-F1..F3, labelled apart from the f532d495 F1-F4
R273 = "tests.test_ahc_contracts.RuntimeTests.test_r273_"
AHC_CORE = "harness/hooks/ahc_core.py"
ENTRIES.update({
    "PR 273 receipt F1 a pass needs the helper's exit 0 in the completion signal": {
        "tests": [R273 + "f1_a_bound_pass_report_left_after_a_failed_publication_check_never_passes",
                  R273 + "f1_the_verdict_carrying_final_forms_apply_the_same_exit_rule",
                  RTT + "test_r273_f1_a_pass_report_with_a_failed_publication_exit_settles_outcome_unknown_through_the_tick"],
        "mutations": [
            ("settle_final ignores the helper's exit status", [
                ('    verdict = report_verdict(raw, row) if rc in (ahc_core.EXIT_PASS, ahc_core.EXIT_BLOCK) else None\n',
                 '    verdict = report_verdict(raw, row)\n'),
                ('    if verdict is None or ahc_core.helper_outcome(rc, verdict) is None:\n', '    if verdict is None:\n')],
             REVIEW_PY),
            ("helper_outcome lets a PASS through with any exit status", [
                ('        return verdict if rc == EXIT_PASS else None\n', '        return verdict\n')], AHC_CORE),
            ("the completion signal takes a JSON boolean as the helper's integer exit status", [
                ('    if type(doc.get(FINAL_STATUS)) is not int:\n', '    if not isinstance(doc.get(FINAL_STATUS), int):\n')],
             REVIEW_PY),
            ("helper_outcome reads a boolean exit status as 1 or 0", [
                ('    if type(rc) is not int:\n        return None\n', '    if not isinstance(rc, int):\n        return None\n')],
             AHC_CORE)]},
})


def run_tests(root, ids, noop=(), timeout=TIMEOUT):
    env = dict(os.environ, AHC_NOOP_TESTS=",".join(noop), PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run([sys.executable, "-B", RUNNER] + list(ids), cwd=root, capture_output=True, text=True,
                              timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return "timeout"
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("{"):
            try:
                return json.loads(line)["results"]
            except (ValueError, KeyError):
                break
    return "no-result"


def classify(outcomes, ids):
    """killed / survived / inconclusive for one mutated run of the mapped ids."""
    if not isinstance(outcomes, dict) or set(outcomes) != set(ids):
        return "inconclusive"
    values = [outcomes[i] for i in ids]
    if any(v in ("error", "skip") for v in values):
        return "inconclusive"
    if any(v == "fail" for v in values):
        return "killed"
    return "survived"


class _Mutated:
    def __init__(self, root, swaps, rel):
        self.src = os.path.join(root, rel)
        self.swaps = swaps
        self.bak = self.src + ".vs.bak"

    def __enter__(self):
        shutil.copyfile(self.src, self.bak)
        text = open(self.bak, encoding="utf-8").read()
        for old, new in self.swaps:
            if text.count(old) != 1:
                self.__exit__(None, None, None)
                raise SystemExit("anchor not unique in %s (%d): %r" % (self.src, text.count(old), old[:80]))
            text = text.replace(old, new)
        with open(self.src, "w", encoding="utf-8") as handle:
            handle.write(text)
        return self

    def __exit__(self, *exc):
        if os.path.exists(self.bak):
            shutil.copyfile(self.bak, self.src)
            os.remove(self.bak)
        return False


def evaluate(root, key, entry, timeout=TIMEOUT):
    ids = list(entry["tests"])
    report = {"key": key, "tests": ids, "mutations": []}
    base = run_tests(root, ids, timeout=timeout)
    report["baseline"] = base if isinstance(base, str) else ("pass" if all(base.get(i) == "pass" for i in ids)
                                                             else "not-pass: %s" % base)
    if report["baseline"] != "pass":
        report["verdict"] = "UNPROVEN (baseline)"
        return report
    killed_all = True
    for name, swaps, rel in entry["mutations"]:
        with _Mutated(root, swaps, rel):
            got = run_tests(root, ids, timeout=timeout)
        verdict = "inconclusive" if isinstance(got, str) else classify(got, ids)
        report["mutations"].append({"name": name, "result": verdict, "outcomes": got})
        killed_all = killed_all and verdict == "killed"
    if not entry["mutations"]:
        killed_all = False
    name, swaps, rel = entry["mutations"][0] if entry["mutations"] else (None, [], None)
    if rel:
        with _Mutated(root, swaps, rel):
            got = run_tests(root, ids, noop=ids, timeout=timeout)
        control = "inconclusive" if isinstance(got, str) else classify(got, ids)
        report["control"] = "unproven" if control != "killed" else "HARNESS-FAULT (no-op control still killed)"
    else:
        report["control"] = "unproven"
    inconclusive = any(m["result"] == "inconclusive" for m in report["mutations"])
    if report["control"] != "unproven":
        report["verdict"] = "HARNESS-FAULT"
    elif killed_all:
        report["verdict"] = "PROVEN"
    else:
        report["verdict"] = "INCONCLUSIVE" if inconclusive else "UNPROVEN"
    return report


def self_test(timeout=6.0):
    """NEG-32 on a throwaway fixture: a name-only test, an unrelated killer, a broken import, a timeout, an error
    and a real assertion. Returns the list of problems (empty when the harness classifies every case right)."""
    root = tempfile.mkdtemp(prefix="ahc-vh-")
    try:
        os.makedirs(os.path.join(root, "fx"))
        open(os.path.join(root, "fx", "__init__.py"), "w").close()
        with open(os.path.join(root, "fx", "mod.py"), "w") as handle:
            handle.write("VALUE = 1\n\ndef spin():\n    return VALUE\n")
        with open(os.path.join(root, "fx", "test_fx.py"), "w") as handle:
            handle.write(
                "import unittest\nfrom fx import mod\n\n\nclass T(unittest.TestCase):\n"
                "    def test_r05_x(self):\n        mod.spin()\n\n"          # resolves the id by name, asserts nothing
                "    def test_unrelated(self):\n        self.assertEqual(mod.VALUE, 1)\n\n"
                "    def test_real(self):\n        self.assertEqual(mod.spin(), 1)\n")
        problems = []
        mod = "fx/mod.py"
        cases = [
            ("name-only test, unrelated killer", {"tests": ["fx.test_fx.T.test_r05_x"],
                                                  "mutations": [("flip", [("VALUE = 1", "VALUE = 2")], mod)]},
             "UNPROVEN"),
            ("broken import", {"tests": ["fx.test_fx.T.test_real"],
                               "mutations": [("syntax", [("VALUE = 1", "VALUE = (")], mod)]}, "INCONCLUSIVE"),
            ("timeout", {"tests": ["fx.test_fx.T.test_real"],
                         "mutations": [("hang", [("    return VALUE", "    while True:\n        pass")], mod)]},
             "INCONCLUSIVE"),
            ("error, not assertion", {"tests": ["fx.test_fx.T.test_real"],
                                      "mutations": [("raise", [("    return VALUE", "    raise KeyError(1)")], mod)]},
             "INCONCLUSIVE"),
            ("real assertion", {"tests": ["fx.test_fx.T.test_real"],
                                "mutations": [("flip", [("VALUE = 1", "VALUE = 2")], mod)]}, "PROVEN"),
        ]
        for label, entry, want in cases:
            got = evaluate(root, label, entry, timeout=timeout)
            if got["verdict"] != want:
                problems.append("%s: verdict %s, expected %s (%s)" % (label, got["verdict"], want, got))
            if got.get("control") != "unproven":
                problems.append("%s: control %s, expected unproven" % (label, got.get("control")))
        return problems
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv):
    if "--self-test" in argv:
        problems = self_test()
        print("SELF-TEST %s%s" % ("OK" if not problems else "FAILED: ", "; ".join(problems)))
        return 1 if problems else 0
    only, rest = [], []                 # --only KEY may repeat; a KEY ending in * selects by prefix
    i = 0
    while i < len(argv):
        if argv[i] == "--only" and i + 1 < len(argv):
            only.append(argv[i + 1])
            i += 2
            continue
        rest.append(argv[i])
        i += 1
    argv = rest
    out_path = argv[0] if argv else os.path.join(ROOT, ".ahc-local", "variants_slice1b.out")
    reports = []
    for key, entry in ENTRIES.items():
        if only and not any(key == o or (o.endswith("*") and key.startswith(o[:-1])) for o in only):
            continue
        reports.append(evaluate(ROOT, key, entry))
    lines = []
    for r in reports:
        lines.append("== %s %s baseline=%s control=%s" % (r["key"], r["verdict"], r["baseline"], r.get("control")))
        for m in r["mutations"]:
            lines.append("   %s: %s" % (m["name"], m["result"]))
    bad = [r["key"] for r in reports if r["verdict"] != "PROVEN"]
    lines.append("SUMMARY: %d entries, %d PROVEN, not proven: %s" % (len(reports), len(reports) - len(bad), bad))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if bad or not reports else 0


RTR = "tests.test_ahc_runner.ReviewTickTests.test_r273_"
ENTRIES.update({
    "PR 273 receipt F3 the packet carries the attached core's criteria and text": {
        "tests": [R273 + "f3_the_packet_carries_the_attached_cores_text_and_criteria_or_is_not_built",
                  "tests.test_ahc_contracts.RuntimeTests.test_r02_core_builds_the_packet_from_its_own_snapshot_and_lints_it",
                  "tests.test_ahc_observe.ProducerTests.test_r273_f3_the_attached_cores_text_is_verified_handed_to_r2_and_never_persisted",
                  RTR + "f3_the_reviewer_gets_the_attached_cores_criteria_and_text_at_admission_and_for_a_successor",
                  RTR + "f3_without_the_attached_cores_text_no_packet_is_built_and_the_request_is_held"],
        "mutations": [
            ("R2 takes the spec core text without checking it against the attached core", [
                ('    if hashlib.sha256(data).hexdigest() != spec_core_sha:\n', '    if False:\n')], REVIEW_PY),
            ("the packet renders the digest as the spec core", [
                ('             "", "## Spec core (sha256 %s)" % spec_core_sha, spec_text.rstrip("\\n"),\n',
                 '             "", "## Spec core (sha256 %s)" % spec_core_sha, spec_core_sha,\n')], REVIEW_PY),
            ("a core without acceptance criteria still builds a packet", [
                ('    if not acceptance.strip():\n', '    if False:\n')], REVIEW_PY),
            ("the producer accepts a spec core text that is not the attached core", [
                ('    if hashlib.sha256(text).hexdigest() != gq.get("attached_core"):\n', '    if False:\n')],
             "harness/hooks/ahc_observe.py"),
            ("the observation drops the verified text before R2", [
                ('        return dict(self.c.load_observation(stamp["id"]), **s.get("attach", {}))\n',
                 '        return self.c.load_observation(stamp["id"])\n')], "harness/hooks/ahc_observe.py")]},
})

STT = "tests.test_ahc_runner.ShadowTickTests."
ENTRIES.update({
    "PR 273 receipt F2 rows required after admission are queued by the tick": {
        "tests": [RTR + "f2_a_w16_extension_round_is_queued_and_launched_by_the_next_tick",
                  RTR + "f2_an_altered_or_missing_stored_packet_keeps_the_row_required_and_says_so",
                  STT + "test_r273_f2_w27_replacement_code_rows_are_queued_and_offered_by_the_real_scheduler",
                  RT + "test_r273_f2_a_stored_packet_rereads_the_lint_core_found_not_one_planted_in_the_spec_or_owner_text"],
        "mutations": [
            ("the stored packet's lint is read from the first lint heading (a planted one in the spec)", [
                ('    at = text.rfind(marker, 0, owner) if owner >= 0 else -1\n',
                 '    at = text.find(marker) if owner >= 0 else -1\n')], REVIEW_PY),
            ("the tick never runs the R2 pass for later rows", [
                ('        self.r2_required(summary)\n', '        pass\n')], SHADOW),
            ("the stored packet is queued without checking its hash", [
                ('    if hashlib.sha256(data).hexdigest() != sha:\n', '    if False:\n')], REVIEW_PY),
            ("a row that cannot be queued is dropped from the tick's report", [
                ('                summary["refused"].append((rid, "R2 for a later round: %s" % str(error)[:200]))\n',
                 '                pass\n')], SHADOW)]},
})


# goodqa#16262 d5 AC-3: the variants the criterion names, each of which must fail a named test.
W1C = "tests.test_ahc_runner.W1CheckTests."
CB = "tests.test_ahc_contracts.LineageBindingTests."
RF = "tests.test_ahc_observe.RefsTests."
BIND_BLOCK = (
    '            if ticket is not None:\n'
    '                lineage = self.lineage_of(repo, pr)\n'
    '                self.db.execute("INSERT OR IGNORE INTO lineage_tickets(lineage, repo, pr, project, number, bound_at, "\n'
    '                                "event_id) VALUES (?,?,?,?,?,?,?)",\n'
    '                                (lineage, repo, int(pr), ticket[0], ticket[1], now, event_id))\n'
    '                stored = tuple(self.db.execute("SELECT project, number FROM lineage_tickets WHERE lineage=?",\n'
    '                                               (lineage,)).fetchone())\n'
    '                if stored != ticket:\n'
    '                    raise BindingMismatch("lineage bound to %s#%d" % stored)\n')
WI_INSERT_END = '                             packet_sha256, "pr-gate", 1, now, now, 1 if red_team else 0))\n'
ENTRIES.update({
    "goodqa#16262 AC-3 the W1 binding (check 5)": {
        "tests": [W1C + "test_ac3f_neg14_check5_a_lineage_bound_to_another_ticket_is_held_permanently_with_nothing_written",
                  CB + "test_rt18_a_mismatch_caught_inside_an_enclosing_transaction_commits_nothing",
                  CB + "test_ac3g_a_successor_writes_no_row_and_inherits_the_binding"],
        "mutations": [
            ("a plain INSERT on lineage_tickets (an IntegrityError escapes the tick)", [
                ('self.db.execute("INSERT OR IGNORE INTO lineage_tickets(',
                 'self.db.execute("INSERT INTO lineage_tickets(')], CONTRACTS),
            ("the binding is written after the work_items INSERT", [
                (BIND_BLOCK, ''),
                (WI_INSERT_END, WI_INSERT_END + BIND_BLOCK)], CONTRACTS),
            ("a successor writes a binding row", [
                ('                               red_team=bool(item["red_team"]))\n        return succ["id"]\n',
                 '                               red_team=bool(item["red_team"]), ticket=("goodqa", int(item["pr"])))\n'
                 '        return succ["id"]\n')], CONTRACTS)]},
    "goodqa#16262 AC-3 the W1 checks and holds": {
        "tests": [W1C + "test_ac3b_check1_a_refs_problem_is_a_permanent_hold_until_a_new_head",
                  W1C + "test_ac3c_check3_no_attached_spec_is_retryable_then_the_attach_admits_at_the_same_head",
                  W1C + "test_ac3d_neg15_check2_request_ticket_is_parsed_strictly_and_names_the_required_form",
                  RF + "test_w1_with_a_refs_problem_skips_the_reader_and_is_not_refused",
                  RF + "test_a_live_item_calls_the_reader_with_its_lineage_binding_and_never_parses_refs",
                  "tests.test_ahc_runner.ShadowTickTests."
                  "test_16262_ac3e_a_same_head_resubmit_for_a_live_item_is_consumed_before_any_observation"],
        "mutations": [
            ("the binding takes the request's ticket and check 2 is skipped", [
                ('                                             ticket=C.parse_ticket_text(obs.get("refs_ticket")))\n',
                 '                                             ticket=C.parse_request_ticket(req.get("ticket")))\n'),
                ('    if C.parse_request_ticket(req.get("ticket")) != refs:',
                 '    if False:')], SHADOW),
            ("a live item's reader call re-parses Refs", [
                ('            ticket = self.c.lineage_ticket(item)\n',
                 '            ticket = parse_refs(messages, shas)[0]\n')], OBSERVE),
            ("a Refs failure refuses the observation", [
                ('            refs_ticket, refs_problem = parse_refs(messages, shas)\n',
                 '            refs_ticket, refs_problem = parse_refs(messages, shas)\n'
                 '            if refs_problem:\n                raise ObservationRefused(refs_problem)\n')], OBSERVE),
            ("a held request is deleted", [
                ('            summary["held"].append((key, reason))\n',
                 '            summary["held"].append((key, reason))\n'
                 '            self.c.db.execute("DELETE FROM contract_meta WHERE k=?", (key,))\n')], SHADOW),
            ("a retryable hold is never retried", [
                ('                if hold.get("kind") != "retryable" or seq < int(hold.get("next_tick") or 0):\n',
                 '                if True:\n')], SHADOW),
            ("the request is observed before the duplicate lookup", [
                ("            # admit_item's own live-item predicate; admit_item's live return stays as the in-transaction recheck.\n",
                 "            # admit_item's own live-item predicate; admit_item's live return stays as the in-transaction recheck.\n"
                 '            self._observe(summary, req["repo"], req["pr"], base=req.get("base"), head=req["head"])\n')],
             SHADOW)]},
})

ENTRIES.update({
    "goodqa#16262 AC-7 status names a held request's reason": {
        "tests": [W1C + "test_ac7_status_names_each_held_request_and_its_reason_and_the_items_spec_core"],
        "mutations": [
            ("status shows a hold without its reason", [
                ('        out.append("%s held (%s%s): %s" % (label, hold.get("kind"), when, hold.get("reason")))\n',
                 '        out.append("%s held (%s%s)" % (label, hold.get("kind"), when))\n')], SHADOW),
            ("status omits waiting requests", [
                ('            out.append("%s waiting for admission" % label)\n', '            pass\n')], SHADOW)]},
})

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
