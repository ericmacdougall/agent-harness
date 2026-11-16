"""Failing-first controls for slice 1 (a) of goodqa#16049: the WorkItem tables, R14 and the spec-core binding.

Each variant applies exact, unique text swaps to one source file, runs the named tests, and restores the source from a
`.vs.bak` copy in `finally`. Every variant must make its tests fail; the summary names any that did not. Run from the
repo root: `python3 -B tests/variants/ahc_slice1a_variants.py [output-file]`. It mutates tracked files while it runs,
so do not commit or run other suites at the same time. Not collected by unittest (no test_ prefix).
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, ".ahc-local", "variants_slice1a.out")
CONTRACTS = "harness/hooks/ahc_contracts.py"
TABLES = ["tests.test_ahc_core.TransitionTableTests"]
REVIEW = ["tests.test_ahc_contracts.ReviewTests"]
SM = ["tests.test_ahc_runner.StateMachineTests"]
TIMEOUT = float(os.environ.get("AHC_VARIANT_TIMEOUT", "900"))   # seconds per variant; a timeout is inconclusive
V = [
    ("Q-A6: spec_core dropped from the row id and the unique key", [
        ('        if kind == "spec":       # code rows keep their pre-Q-A6 ids\n            binding["spec_core"] = '
         'spec_core\n', ""),
        ("  UNIQUE(kind, repo, pr, head, snapshot_base, packet_sha256, policy_revision, spec_core));",
         "  UNIQUE(kind, repo, pr, head, snapshot_base, packet_sha256, policy_revision));")], CONTRACTS, REVIEW),
    ("Q-A6: R11 does not compare the attach record's core", [
        ('            want["spec_core"] = row["spec_core"]\n            got["spec_core"] = receipt.get("spec_core")\n',
         "            pass\n")], CONTRACTS, REVIEW),
    ("Q-A6: no CHECK on spec_core", [
        ("  CHECK ((kind = 'spec' AND length(spec_core) = 64 AND spec_core NOT GLOB '*[^0-9a-f]*')\n"
         "         OR (kind != 'spec' AND spec_core = '')),\n", "")], CONTRACTS, REVIEW),
    ("Q-A6: a spec row accepts any core", [
        ("            if not (isinstance(spec_core, str) and len(spec_core) == 64 and _is_oid(spec_core)):\n",
         "            if False:\n")], CONTRACTS, REVIEW),
    ("R14: outcome-unknown goes straight to superseded again", [
        ('        ("outcome-unknown", "cancelling"): D,  # R14', '        ("outcome-unknown", "superseded"): D,  # R14'),
        ('                to = "cancelling" if state in ("running", "outcome-unknown") else "superseded"\n',
         '                to = "cancelling" if state == "running" else "superseded"\n')], CONTRACTS, REVIEW + TABLES),
    ("AC-1: W26 loses its defensive exhausted source", [
        ('        "W26": (("pr-gate", "waiting-dep", "waiting-ask", "exhausted"), ("merged",), "ahc-core"),\n',
         '        "W26": (("pr-gate", "waiting-dep", "waiting-ask"), ("merged",), "ahc-core"),\n')], CONTRACTS, TABLES),
    ("AC-1: W20 taken by ahc-core instead of the owner", [
        ('        "W20": (("pr-gate",), ("cancelled",), "owner"),\n',
         '        "W20": (("pr-gate",), ("cancelled",), "ahc-core"),\n')], CONTRACTS, TABLES),
    ("AC-1: the pinned core constant moved off the attached spec", [
        ('SPEC_CORE_SHA256 = "0130008d', 'SPEC_CORE_SHA256 = "a320dda4')], CONTRACTS, TABLES),
    # WorkItem transition function (StateMachineTests)
    ("T7 dropped: an unsettled Effect does not stop any row", [
        ("            if unsettled and row_id not in self.T7_ALLOWED:\n", "            if False:\n")],
     CONTRACTS, SM),
    ("T7 as a block-list of the rows it names as waiting (lets W15 and W20 through)", [
        ("            if unsettled and row_id not in self.T7_ALLOWED:\n",
         '            if unsettled and row_id in ("W4", "W5", "W13", "W14", "W17", "W18", "W27"):\n')],
     CONTRACTS, SM),
    ("note 8: absent-proven treated as settled", [
        ('    T7_UNSETTLED = ("dispatched", "outcome-unknown", "held", "fenced", "absent-proven")\n',
         '    T7_UNSETTLED = ("dispatched", "outcome-unknown", "held", "fenced")\n')], CONTRACTS, SM),
    ("T6: the version is checked before the replay", [
        ("            prior = self.db.execute(\"SELECT entity, id, data FROM transitions WHERE event_id=?\",\n",
         "            if item[\"version\"] != expected_version:\n                raise VersionConflict(\"stale\")\n"
         "            prior = self.db.execute(\"SELECT entity, id, data FROM transitions WHERE event_id=?\",\n")],
     CONTRACTS, SM),
    ("T6: a replay on another item is accepted as a no-op", [
        ('                if prior[0] == "work_item" and prior[1] == iid and data.get("row") == row_id:\n',
         '                if prior[0] == "work_item":\n')], CONTRACTS, SM),
    ("NEG-11: the actor check dropped", [
        ("            if actor != row_actor:\n", "            if False:\n")], CONTRACTS, SM),
    ("W8: merged without a confirmed Effect", [
        ('            if "confirmed" not in effects:\n', "            if False:\n")], CONTRACTS, SM),
    ("W9: a marked item returns to pr-gate", [
        ("            if marks:\n                raise ContractError(\"W9 is for an unmarked item",
         "            if False:\n                raise ContractError(\"W9 is for an unmarked item")], CONTRACTS, SM),
    ("W25: the mark does not pick the terminal", [
        ("            if want != to:\n", "            if False:\n")], CONTRACTS, SM),
    ("W24: applies without an unsettled Effect", [
        ("            if not unsettled:\n                raise ContractError(\"W24 applies only",
         "            if False:\n                raise ContractError(\"W24 applies only")], CONTRACTS, SM),
    ("NEG-11: a resubmit at the same head makes a second item", [
        ("            if live:\n                return self._row(\"work_items\", \"id\", live[0])\n",
         "            pass\n")], CONTRACTS, SM),
    ("unwired rows applied without their guards", [
        ("            if row_id not in self.WI_WIRED:\n", "            if False:\n")], CONTRACTS, SM),
    ("T7 precedence by table order instead of row number", [
        ("        return min(rows, key=lambda r: int(r[1:]))\n", "        return rows[0]\n")], CONTRACTS, SM),
    ("T2: a WorkItem observation is not checked for age", [
        ("        self._fresh(obs)\n        if str(obs.get(\"repo\", \"\")).lower() != item[\"repo\"]",
         "        if str(obs.get(\"repo\", \"\")).lower() != item[\"repo\"]")], CONTRACTS, SM),
    ("T2: an observation for another PR is accepted", [
        ("        if str(obs.get(\"repo\", \"\")).lower() != item[\"repo\"] or obs.get(\"pr\") != item[\"pr\"]:\n",
         "        if False:\n")], CONTRACTS, SM),
    ("W18: the caller's 'explained' flag is trusted", [
        ("        elif row_id == \"W18\" and not self.db.execute(\n",
         "        elif row_id == \"W18\" and not obs.get(\"explained\") and not self.db.execute(\n")], CONTRACTS, SM),
    ("W4: the old Review rows are left open", [
        ("            self.supersede_reviews(item[\"repo\"], item[\"pr\"], new[\"head\"],\n",
         "            (lambda *a: None)(item[\"repo\"], item[\"pr\"], new[\"head\"],\n")], CONTRACTS, SM),
    ("W4: an unsent intent is not abandoned (E9)", [
        ("                if state == \"intent\":                                # E9",
         "                if False:                                # E9")], CONTRACTS, SM),
    ("W14: taken even when this item's own Effect made the merge", [
        ("            if row_id == \"W14\" and \"confirmed\" in effects:\n", "            if False:\n")],
     CONTRACTS, SM),
    ("W24: the mark is not checked against the observation", [
        ("            if not fact:\n                raise ContractError(\"W24's observation",
         "            if False:\n                raise ContractError(\"W24's observation")], CONTRACTS, SM),
    ("T7 precedence: G8 and G9 outrank the WorkItem rows", [
        ('    T7_ORDER = ("W4", "W13", "W14", "W18", "W19", "W17", "G8", "G9")\n',
         '    T7_ORDER = ("G8", "G9", "W4", "W13", "W14", "W18", "W19", "W17")\n')], CONTRACTS, SM),
]
out, survivors, inconclusive = [], [], []
for name, swaps, rel, tests in V:
    src = os.path.join(ROOT, rel)
    bak = src + ".vs.bak"
    shutil.copyfile(src, bak)
    try:
        text = open(bak).read()
        for old, new in swaps:
            if text.count(old) != 1:
                sys.exit("anchor not unique for %s (%d): %r" % (name, text.count(old), old[:70]))
            text = text.replace(old, new)
        open(src, "w").write(text)
        try:
            proc = subprocess.run([sys.executable, "-B", "-m", "unittest"] + tests, cwd=ROOT, capture_output=True,
                                  text=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:   # a hang is not a failing test: inconclusive, and the run exits nonzero
            out.append("== variant %s rc=timeout INCONCLUSIVE (tests did not finish in %s s)" % (name, TIMEOUT))
            inconclusive.append(name)
            continue
        lines = [l for l in proc.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED", "OK"))]
        out.append("== variant %s rc=%d\n%s" % (name, proc.returncode, "\n".join(lines)))
        if proc.returncode == 0:
            survivors.append(name)
    finally:
        shutil.copyfile(bak, src)
        os.remove(bak)
out.append("SUMMARY: %d variants, %d did not fail: %s; %d inconclusive (timeout): %s"
           % (len(V), len(survivors), survivors, len(inconclusive), inconclusive))
open(OUT, "w").write("\n".join(out) + "\n")
print("\n".join(out))
sys.exit(1 if survivors or inconclusive else 0)
