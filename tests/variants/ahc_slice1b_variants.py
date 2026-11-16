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
                  CK + "test_wait_needs_both_clocks_and_restarts_on_a_new_boot"],
        "mutations": [("a new boot keeps the old anchor", [
            (" or boot != self.boot_id:", ":")], CLOCK)]},
    "AC-10 elapsed from the boot clock": {
        "tests": [CK + "test_elapsed_comes_from_the_boot_clock_not_the_wall"],
        "mutations": [("elapsed is derived from wall timestamps", [
            ("        return max(0.0, float(self._boot()) - float(anchor))\n",
             "        return max(0.0, self.effective_wall() - (float(_deadline) - float(_duration)))\n")], CLOCK)]},
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
