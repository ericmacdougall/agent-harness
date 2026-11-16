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
]
out, survivors = [], []
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
                                  text=True, timeout=900)
        except subprocess.TimeoutExpired:   # a hang is recorded and the run goes on; it is not a survivor
            out.append("== variant %s rc=timeout (tests did not finish in 900 s)" % name)
            continue
        lines = [l for l in proc.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED", "OK"))]
        out.append("== variant %s rc=%d\n%s" % (name, proc.returncode, "\n".join(lines)))
        if proc.returncode == 0:
            survivors.append(name)
    finally:
        shutil.copyfile(bak, src)
        os.remove(bak)
out.append("SUMMARY: %d variants, %d did not fail: %s" % (len(V), len(survivors), survivors))
open(OUT, "w").write("\n".join(out) + "\n")
print("\n".join(out))
