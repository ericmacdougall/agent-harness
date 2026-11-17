"""ahc_merge variant harness (goodqa#16049, M-1 AC-6, AC-8, T9; the same rules as ahc_slice1b_variants.py).

Each entry maps a broken variant of harness/hooks/ahc_merge.py to its explicit test methods (full dotted names). The
machinery is the slice 1 (b) harness, loaded from its file and reused unchanged: the baseline must pass; a mutation
counts as killed only when a mapped method fails with an AssertionError (an error, skip, timeout or import failure is
INCONCLUSIVE, never a kill); the control re-runs the first mutation with every mapped method replaced by a no-op and
must come out unkilled. An entry is PROVEN only when its baseline passes, every mutation is killed and its control is
unproven.

Run from the repo root: `python3 -B tests/variants/ahc_merge_variants.py [--only KEY] [output-file]`. It mutates
harness/hooks/ahc_merge.py on disk while it runs (restored in `finally`), so do not commit or run other suites at
the same time. Not collected by unittest (no test_ prefix).

Out of scope here, with the reason: the W21 variants (update every behind PR; update-branch without
expected_head_sha or for a non-head item) belong to the daemon's W21 send (owner ruling, slice 1(b) spec r9 AC-7);
the "W4 or W13 fires first" and "W26 dropped" variants mutate ahc_contracts' WorkItem table, which this slice does
not edit (tests.test_ahc_merge.EffectTests.test_13_head_race is their mapped test when that harness adds them).
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("ahc_slice1b_variants", os.path.join(HERE, "ahc_slice1b_variants.py"))
VH = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VH)

ROOT = VH.ROOT
MERGE = "harness/hooks/ahc_merge.py"
T = "tests.test_ahc_merge."
EF, T9, ID, TR = T + "EffectTests.", T + "T9Tests.", T + "IdentityTests.", T + "TransportTests."

SETTLE = ('        done = self.applied(row, read)\n        try:\n            if state == "absent-proven":\n')
PAYLOAD = '                "beforeOid": row["base"],\n                "afterOid": reviewed,\n                "force": False}'

ENTRIES = {
    # ---- the eight the brief names
    "afterOid other than the reviewed H": {
        "tests": [EF + "test_09_same_key_with_other_parameters_is_an_error_and_nothing_is_sent"],
        "mutations": [("the payload takes the request's afterOid without comparing it to the reviewed H", [
            (' or req.get("afterOid") != reviewed:', ":"),
            ('                "afterOid": reviewed,\n', '                "afterOid": req["afterOid"],\n')], MERGE)]},
    "force true": {
        "tests": [EF + "test_01_success_tip_h_activity_entry_pr_merged",
                  TR + "test_the_send_is_one_graphql_update_refs_with_force_false"],
        "mutations": [("the sender's payload sets force true", [
            (PAYLOAD, PAYLOAD.replace('"force": False}', '"force": True}'))], MERGE),
                      ("the GraphQL body sets force true", [
            ('"afterOid": after_oid, "force": False}]', '"afterOid": after_oid, "force": True}]')], MERGE)]},
    "send before the dispatch commit": {
        "tests": [EF + "test_01_success_tip_h_activity_entry_pr_merged"],
        "mutations": [("the request leaves before E2 commits", [
            ("            try:\n                obs = self.observe(row, epoch, canary)\n",
             '            early = self._send({"repo": row["repo"], "ref": "refs/heads/%s" % self._branch(row), '
             '"beforeOid": row["base"], "afterOid": reviewed, "force": False})\n'
             "            try:\n                obs = self.observe(row, epoch, canary)\n"),
            ("            result = self._send(payload)\n", "            result = early\n")], MERGE)]},
    "no beforeOid": {
        "tests": [EF + "test_01_success_tip_h_activity_entry_pr_merged"],
        "mutations": [("the payload drops beforeOid", [
            (PAYLOAD, PAYLOAD.replace('"beforeOid": row["base"]', '"beforeOid": None'))], MERGE)]},
    "kill epoch re-read dropped": {
        "tests": [T9 + "test_the_epoch_is_re_read_under_the_lock_at_every_dispatch"],
        "mutations": [("the sender uses the epoch it read at start", [
            ("            epoch = self.kill.read()                                 # T9: the kill epoch, re-read under "
             "the lock\n", "            epoch = self._epoch_at_start\n")], MERGE)]},
    "second send after outcome-unknown": {
        "tests": [EF + "test_07_timeout_with_no_conclusive_readback_is_held",
                  EF + "test_11_untyped_error_with_tip_at_b_stays_unknown_and_never_retries"],
        "mutations": [("E5 resends the request", [
            ('                state = row["state"]                                                 # E5\n',
             '                state = row["state"]                                                 # E5\n'
             '                self._send({"repo": row["repo"], "ref": "refs/heads/%s" % self._branch(row), '
             '"beforeOid": row["base"], "afterOid": row["head"], "force": False})\n')], MERGE)]},
    "fences take the lock shared instead of exclusive": {
        "tests": [T9 + "test_18_a_paused_sender_is_terminated_and_confirmed_gone_before_the_fence_returns"],
        "mutations": [("kill, revoke and disable take LOCK_SH", [
            ("        took = self.lock.acquire(fcntl.LOCK_EX, timeout=self.bound)",
             "        took = self.lock.acquire(fcntl.LOCK_SH, timeout=self.bound)")], MERGE)]},
    "identity check skipped": {
        "tests": [ID + "test_the_check_is_stale_after_10_minutes_or_a_reboot_and_nothing_is_sent",
                  ID + "test_a_failed_recheck_clears_the_last_good_one"],
        "mutations": [("dispatch never asks whether the identity check is fresh", [
            ("            if not self.identity.fresh():                            # AC-8",
             "            if False:                            # AC-8")], MERGE)]},
    # ---- the spec's other named variants and owner-ruled extras
    "send without holding the lock": {
        "tests": [T9 + "test_lock_modes",
                  T9 + "test_18_a_paused_sender_is_terminated_and_confirmed_gone_before_the_fence_returns"],
        "mutations": [("the sender skips the shared lock", [
            ("        with self.lock.shared(SENDER_LOCK_WAIT_SECONDS) as held:     # T9: shared while it re-reads "
             "and sends\n", "        for held in (True,):\n")], MERGE)]},
    "fence returns after writing the epoch alone": {
        "tests": [T9 + "test_18_a_paused_sender_is_terminated_and_confirmed_gone_before_the_fence_returns"],
        "mutations": [("no terminate-and-confirm", [
            ("                if not self._stop_sender():\n",
             '                return {"result": "%s complete" % what, "in_flight": in_flight}\n'
             "                if not self._stop_sender():\n")], MERGE)]},
    "untyped error treated as absence": {
        "tests": [EF + "test_11_untyped_error_with_tip_at_b_stays_unknown_and_never_retries"],
        "mutations": [("the sender records an untyped error as p1", [
            ('        if result["outcome"] in (P1, P3):\n',
             '        if result["outcome"] == UNTYPED:\n'
             '            result = SendResult(P1, result["detail"], kind="non-fast-forward")\n'
             '        if result["outcome"] in (P1, P3):\n')], MERGE),
                      ("the classifier types an untyped GraphQL error as p1", [
            ('        return SendResult(UNTYPED, text or "an error without a message")',
             '        return SendResult(P1, text, kind="non-fast-forward")')], MERGE)],
        "extra_tests": [TR + "test_classification"]},
    "confirm by reachability alone": {
        "tests": [EF + "test_10_later_integration_containing_h_confirms_only_by_the_activity_entry"],
        "mutations": [("H reachable from the tip counts as applied", [
            (SETTLE, SETTLE.replace("        done = self.applied(row, read)\n",
                                    '        done = self.applied(row, read) or self.t.compare(row["repo"], '
                                    'row["head"], read["tip"]) in ("ahead", "identical") or None\n'))], MERGE)]},
    "plain push fallback": {
        "tests": [EF + "test_14_no_passing_chk_cas_is_ineligible_and_sends_nothing"],
        "mutations": [("without CHK-CAS the sender falls back to git push", [
            ('                return Outcome("refused", "CHK-CAS has not passed for this repo under the merge '
             'identity")', '                return Outcome("refused", str(self.t.push_git(row["repo"], '
             'row["head"])))')], MERGE)]},
    "attribution ahc-proven after a lost response": {
        "tests": [EF + "test_05_timeout_then_readback_shows_the_activity_entry"],
        "mutations": [("every confirm is credited ahc-proven", [
            ('        attribution = "ahc-proven" if key in self._own_success else "observed"',
             '        attribution = "ahc-proven"')], MERGE)]},
    "merging-off check dropped": {
        "tests": [T9 + "test_18_a_paused_sender_is_terminated_and_confirmed_gone_before_the_fence_returns"],
        "mutations": [("a disabled repo still dispatches", [
            ('            if self.port.merging_off(row["repo"]):', "            if False:")], MERGE)]},
    "E16 credited as confirmed": {
        "tests": [EF + "test_16_absent_proven_while_h_is_on_the_branch_abandons_with_an_incident"],
        "mutations": [("an absent-proven op with H on the branch goes to the confirm path", [
            (SETTLE, SETTLE.replace('if state == "absent-proven":', 'if state == "absent-proven" and done is not '
                                                                     'True:'))], MERGE)]},
    # ---- PR #270 review round 1 (Codex R1 at 517de8b): one entry per finding
    "F1 canary age at E2": {
        "tests": [EF + "test_14_an_expired_or_unstamped_canary_at_e2_sends_nothing"],
        "mutations": [("E2 ignores the canary facts", [
            ('            if canary is None:\n                return Outcome("refused", "the CHK-CAS canary is '
             'expired', '            if False:\n                return Outcome("refused", "the CHK-CAS canary is '
             'expired')], MERGE),
                      ("the age has no upper bound", [
            ("not 0 <= age < CANARY_MAX_SECONDS:", "not 0 <= age:")], MERGE)]},
    "F2 the deadline cancels the local send": {
        "tests": [T9 + "test_a_send_paused_before_the_transport_never_starts_after_a_fence"],
        "mutations": [("the deadline abandons the worker without cancelling it", [
            ("            stopped = gate.cancel()\n", '            stopped = "abandoned"\n')], MERGE),
                      ("the transport is called without the gate", [
            ('payload["force"], self.send_deadline, gate=gate)', 'payload["force"], self.send_deadline)')],
                       MERGE)]},
    "F3 an interrupted canary invalidates the old pass": {
        "tests": [T + "CanaryTests.test_an_interrupted_failed_canary_never_leaves_the_old_pass_authoritative"],
        "mutations": [("no in-progress record at the start", [
            ('            self._record(repo, "in-progress", False, {}, bool(prior.get("escalated")) and not '
             'prior.get("passed"),\n                         attempt)\n', "")], MERGE),
                      ("an exception mid-canary escapes without a failed record or merging off", [
            ('                error = "%s during the canary" % type(exc).__name__\n', "                raise\n")],
                       MERGE)]},
    # ---- PR #270 delta review (Codex R1 at bb0852c): F1 the raw canary stamp, F4 the canary attempt
    "F1d the raw canary stamp is validated before its age": {
        "tests": [EF + "test_14_a_non_finite_future_or_malformed_canary_stamp_at_e2_sends_nothing"],
        "mutations": [("canary_facts trusts the clamped age without checking the raw stamp", [
            ('        if canary_stamp_problem(facts["canary"], self.port.boot_id(), self.port.mono()) is not None:\n'
             '            return None\n', "")], MERGE),
                      ("a mono later than the boot clock passes the check", [
            ("    if not value <= now:\n", "    if False:\n")], MERGE),
                      ("a huge JSON int escapes the check as an exception", [
            ("    except (OverflowError, ValueError):\n", "    except ValueError:\n")], MERGE)]},
    "F1d each stamp condition on its own": {
        "tests": [EF + "test_14_the_canary_stamp_validator_names_each_problem"],
        "mutations": [("the boot check is dropped (masked at E2 by canary_age, killed by the validator test)", [
            ('    if boot_id is None or canary.get("boot") != boot_id:\n', "    if False:\n")], MERGE),
                      ("a non-finite mono passes the finiteness check (masked at E2 by the later checks)", [
            ("    if not math.isfinite(value):\n", "    if False:\n")], MERGE),
                      ("a boolean mono counts as a number", [
            ("    if isinstance(mono, bool) or not isinstance(mono, (int, float)):\n",
             "    if not isinstance(mono, (int, float)):\n")], MERGE),
                      ("a negative mono passes the check", [
            ("    if value < 0:\n", "    if False:\n")], MERGE)]},
    "F4 same-repo canary attempts serialize": {
        "tests": [T + "CanaryTests.test_a_second_canary_attempt_for_the_repo_is_deferred_while_the_first_runs"],
        "mutations": [("the canary lock is opened but never taken", [
            ("            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n", "            pass\n")], MERGE),
                      ("a busy lock is treated as free", [
            ("        if held_canary is None:\n            return Outcome(\"deferred\", \"another canary attempt",
             "        if held_canary is None:\n            held_canary = -1\n        if False:\n"
             "            return Outcome(\"deferred\", \"another canary attempt"),
            ("    def unlock(fd):\n        try:\n", "    def unlock(fd):\n        if fd == -1:\n            return\n"
                                                    "        try:\n")], MERGE)]},
    "F4 the final record is a compare-and-write on the attempt id": {
        "tests": [T + "CanaryTests.test_an_older_attempt_never_publishes_over_a_newer_marker"],
        "mutations": [("the final record is written without comparing the attempt", [
            ('        if not isinstance(current, dict) or current.get("attempt") != attempt:\n',
             "        if False:\n")], MERGE),
                      ("a removed record counts as this attempt's", [
            ('        if not isinstance(current, dict) or current.get("attempt") != attempt:\n',
             '        if isinstance(current, dict) and current.get("attempt") != attempt:\n')], MERGE)]},
    "F4 an unusable canary lock fails closed": {
        "tests": [T + "CanaryTests.test_an_unusable_canary_lock_defers_and_changes_nothing"],
        "mutations": [("an unsafe lock file is ignored and the attempt runs", [
            ("            except OSError:\n                return None\n"
             "        if fd is None:\n            return None\n",
             "            except OSError:\n                return -1\n"
             "        if fd is None:\n            return None\n"),
            ("    def unlock(fd):\n        try:\n", "    def unlock(fd):\n        if fd == -1:\n            return\n"
                                                    "        try:\n")], MERGE)]},
}

# an entry's extra_tests are mapped too (the classifier mutation is killed by them)
for _entry in ENTRIES.values():
    _entry["tests"] = list(_entry["tests"]) + list(_entry.pop("extra_tests", []))


def main(argv):
    only = [argv[i + 1] for i, a in enumerate(argv) if a == "--only" and i + 1 < len(argv)]
    rest = [a for i, a in enumerate(argv) if a != "--only" and (i == 0 or argv[i - 1] != "--only")]
    out_path = rest[0] if rest else os.path.join(ROOT, ".ahc-local", "variants_merge.out")
    reports = [VH.evaluate(ROOT, key, entry) for key, entry in ENTRIES.items() if not only or key in only]
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
