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
    ("AC-18: T6 replay checked after the version (the WorkItem crash scenario's stale retry fails)", [
        ("            prior = self.db.execute(\"SELECT entity, id, data FROM transitions WHERE event_id=?\",\n",
         "            if item[\"version\"] != expected_version:\n                raise VersionConflict(\"stale\")\n"
         "            prior = self.db.execute(\"SELECT entity, id, data FROM transitions WHERE event_id=?\",\n")],
     CONTRACTS, ["tests.test_ahc_crash.CrashPointTests"]),
    ("AC-18: a WorkItem move without its audit row", [
        ("            self._a0(\"work_item\", iid, frm, to, event_id, actor, row=row_id, cause=cause,\n",
         "            (lambda *a, **k: None)(\"work_item\", iid, frm, to, event_id, actor, row=row_id, cause=cause,\n")],
     CONTRACTS, ["tests.test_ahc_crash.CrashPointTests"]),
    # D-a3: observation age on the monotonic clock, bound to this boot
    ("D-a3: age measured on the wall clock (the merged behaviour)", [
        ("        if not 0 <= float(self._mono()) - float(obs[\"mono\"]) < self.OBSERVATION_SECONDS:\n",
         "        if not 0 <= self.now() - float(obs[\"at\"]) < self.OBSERVATION_SECONDS:\n")],
     CONTRACTS, ["tests.test_ahc_contracts.OperationTests"]),
    ("D-a3: a stamp from another boot accepted", [
        ("        if obs.get(\"boot\") != self.boot_id:\n", "        if False:\n")],
     CONTRACTS, ["tests.test_ahc_contracts.OperationTests"]),
    ("D-a3: a missing monotonic stamp accepted as now", [
        ("        if not 0 <= float(self._mono()) - float(obs[\"mono\"]) < self.OBSERVATION_SECONDS:\n",
         "        if not 0 <= float(self._mono()) - float(obs.get(\"mono\") or self._mono()) "
         "< self.OBSERVATION_SECONDS:\n"),
        (" or not num(obs.get(\"at\")) or not num(obs.get(\"mono\")):", " or not num(obs.get(\"at\")):")],
     CONTRACTS, ["tests.test_ahc_contracts.OperationTests"]),
    ("goodqa#16193: E13 delays measured on wall stamps (the merged behaviour)", [
        ("            if row[\"wait_boot\"] != self.boot_id or float(first[\"mono\"]) < start + E13_FIRST_READ_SECONDS:\n",
         "            if float(first[\"at\"]) < float(row[\"dispatched_at\"] or 0) + E13_FIRST_READ_SECONDS:\n"),
        ("            if float(second[\"mono\"]) - float(first[\"mono\"]) < E13_READ_GAP_SECONDS:\n",
         "            if float(second[\"at\"]) - float(first[\"at\"]) < E13_READ_GAP_SECONDS:\n")],
     CONTRACTS, ["tests.test_ahc_contracts.OperationTests"]),
    ("goodqa#16193: a restart keeps the old boot's wait stamp", [
        ("            if row[\"wait_boot\"] == self.boot_id and isinstance(row[\"wait_mono\"], (int, float)):\n",
         "            if isinstance(row[\"wait_mono\"], (int, float)):\n")],
     CONTRACTS, ["tests.test_ahc_contracts.OperationTests"]),
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
    # ELIG (step 5): each clause, the fail-closed paths, the queue and the rows that read it
    ("ELIG e1: B_r ancestry not checked", [
        ("or any(s != \"passed\" or anc.get(br) is not True for s, br, _p, _r in code)):",
         "or any(s != \"passed\" for s, br, _p, _r in code)):")], CONTRACTS, SM),
    ("ELIG e1: the PR head is not compared with H", [
        ("        if (not code or o[\"pr_head\"] != head or pol.get(\"revision\")",
         "        if (not code or pol.get(\"revision\")")], CONTRACTS, SM),
    ("ELIG e1: the policy revision read now is not compared (Q-A5.1)", [
        (" or pol.get(\"revision\") != item[\"policy_revision\"]\n", "\n")], CONTRACTS, SM),
    ("ELIG e2: the spec row is not bound to the core attached now", [
        ("        if o[\"attached_core\"] != item[\"spec_core\"] or [s for (s,) in spec] != [\"passed\"]:\n",
         "        if [s for (s,) in spec] != [\"passed\"]:\n")], CONTRACTS, SM),
    ("ELIG e2: a missing spec row counts as passed (NEG-18)", [
        ("        if o[\"attached_core\"] != item[\"spec_core\"] or [s for (s,) in spec] != [\"passed\"]:\n",
         "        if o[\"attached_core\"] != item[\"spec_core\"] or any(s != \"passed\" for (s,) in spec):\n")],
     CONTRACTS, SM),
    ("ELIG e3: a truthy findings count passes", [
        ("        if o[\"open_findings\"] != 0 or isinstance(o[\"open_findings\"], bool):\n",
         "        if o[\"open_findings\"]:\n")], CONTRACTS, SM),
    ("ELIG e4: an empty path list passes", [
        ("(not isinstance(paths, list) or not paths or o[\"foreign_closing_keyword\"]",
         "(not isinstance(paths, list) or o[\"foreign_closing_keyword\"]")], CONTRACTS, SM),
    ("NEG-6: .github/** not protected", [('"settings*.json", "hooks_manifest.json", ".github/**", ',
                                          '"settings*.json", "hooks_manifest.json", ')], CONTRACTS, SM),
    ("NEG-6: names matched only at the root", [
        ("            elif fnmatch.fnmatchcase(name, pat):\n", "            elif fnmatch.fnmatchcase(path, pat):\n")],
     CONTRACTS, SM),
    ("ELIG e5: the repo's merging-off flag is ignored", [
        ("or pol.get(\"checks_green\") is not True or (flags and flags[0])):",
         "or pol.get(\"checks_green\") is not True):")], CONTRACTS, SM),
    ("ELIG e6: a frozen authority epoch is ignored", [
        ("        if o[\"kill_switch\"] is not False or (frozen and frozen[0] == \"1\"):\n",
         "        if o[\"kill_switch\"] is not False:\n")], CONTRACTS, SM),
    ("ELIG e7: CAP1 not checked", [("        if self.cap_used(item[\"repo\"]) >= self.CAP1_PER_DAY:\n",
                                     "        if False:\n")], CONTRACTS, SM),
    ("ELIG e8: a draft passes", [("        if o[\"pr_state\"] != \"OPEN\" or o[\"draft\"] is not False:\n",
                                   "        if o[\"pr_state\"] != \"OPEN\":\n")], CONTRACTS, SM),
    ("ELIG e9: canary age unbounded", [(" or not 0 <= age < 86400:", " or not 0 <= age:")], CONTRACTS, SM),
    ("ELIG e10: not checked", [("        if o[\"compare\"] != \"ahead\" or tip == head:\n", "        if False:\n")],
     CONTRACTS, SM),
    ("ELIG: a bad observation fails nothing (fail open)", [
        ("            return [\"e1\", \"e2\", \"e3\", \"e4\", \"e5\", \"e6\", \"e7\", \"e8\", \"e9\", \"e10\"]\n",
         "            return []\n")], CONTRACTS, SM),
    ("W5: any ELIG failure counts as a dependency", [
        ("            if not (set(failed) & {\"e5\", \"e6\", \"e7\", \"e8\", \"e10\"}) and not mirror_down:\n",
         "            if not failed and not mirror_down:\n")], CONTRACTS, SM),
    ("W2/W6: the values ELIG passed on are not recorded (W27 never fires)", [
        ("                extra = {\"elig_core\": item[\"spec_core\"], \"elig_policy\": item[\"policy_revision\"]}\n",
         "                extra = {}\n")], CONTRACTS, SM),
    ("W27: no replacement Review rows", [
        ("                if kind != \"spec\" and new[\"policy_revision\"] == item[\"policy_revision\"]:\n",
         "                if True:\n")], CONTRACTS, SM),
    ("W27: the item keeps the old core and policy", [
        ("                extra = {\"spec_core\": obs[\"attached_core\"], \"policy_revision\": obs[\"policy\"][\"revision\"]}\n",
         "                extra = {}\n")], CONTRACTS, SM),
    ("queue: newest lineage first", [("ORDER BY admitted, w.created, \"\n", "ORDER BY admitted DESC, w.created, \"\n")],
     CONTRACTS, SM),
    ("queue: e10 required of the head", [
        ("            if iid in observations and not self.elig(item, observations[iid], skip=(\"e10\",)):\n",
         "            if iid in observations and not self.elig(item, observations[iid]):\n")], CONTRACTS, SM),
    ("W21: taken by an item that is not the queue head", [
        ("            if self.queue_head(item[\"repo\"], queue) != item[\"id\"]:\n", "            if False:\n")],
     CONTRACTS, SM),
    ("W21: a second update at the same B", [
        ("            if item[\"w21_base\"] == o[\"tip\"]:\n", "            if False:\n")], CONTRACTS, SM),
    ("W21: no authority log line first", [
        ("                self.authority.append({\"event_id\": event_id, \"item\": iid, \"row\": \"W21\",",
         "                (lambda r: None)({\"event_id\": event_id, \"item\": iid, \"row\": \"W21\",")], CONTRACTS, SM),
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
