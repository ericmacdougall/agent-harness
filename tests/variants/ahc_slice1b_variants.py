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
            ("        self.boot_id = boot_id if boot_id is not None else (read_boot_id() or process_boot_id())\n",
             "        self.boot_id = boot_id if boot_id is not None else (read_boot_id() or process_boot_id())\n"
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
            ('            % ",".join("?" * len(self.FINISHED)), self.FINISHED).fetchall()\n',
             '            % "?", ("none",)).fetchall()\n')], CONTRACTS)]},
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
    only = None
    if "--only" in argv:
        only = argv[argv.index("--only") + 1]
        argv = [a for a in argv if a not in ("--only", only)]
    out_path = argv[0] if argv else os.path.join(ROOT, ".ahc-local", "variants_slice1b.out")
    reports = []
    for key, entry in ENTRIES.items():
        if only and key != only:
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
