"""Failing-first set for the guard-file install gate (goodqa#16944, PR 326a). Each variant removes one control in a
temporary copy of the tree; tests.test_guard_install_gate must fail against every variant and pass against the real files.

    python3 -B tests/mutants_guard_install_gate.py      exit 0 when every variant is killed and the real tree passes
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AI = "harness/hooks/ah_install.py"
GF = "harness/hooks/guard_files.py"
LC = "harness/hooks/launch_check.py"
RR = "harness/hooks/release_receipt.py"
MG = "harness/hooks/mission_gate.py"
SUITES = ("tests.test_guard_install_gate",)

VARIANTS = [
    # ah_install.guard_gate
    ("gate never consulted", AI,
     '    gate = None if dry_run else guard_gate(host, ref, list(files), ticket, home, "install", allow_older, allow_remote=allow_remote)\n',
     "    gate = None\n"),
    ("launch check skipped", AI, "    reason, facts = launch_check.check(PROOF_ENV, allow_remote)\n",
     "    reason, facts = None, {}\n"),
    ("agent may downgrade, resume or roll back", AI, '    if kind_ != "install" or allow_older:\n', "    if False:\n"),
    ("no stamp needed", AI,
     "                                  home=home, bound=True) is None:\n", "                                  home=home, bound=True) is None and False:\n"),
    ("stamp not bound to the call", AI, "                                  home=home, bound=True) is None:\n",
     "                                  home=home, bound=False) is None:\n"),
    ("receipt failure ignored", AI,
     '        refuse("%s. %s. %s." % (head, error, main_route), "guard_file", data={"ok": False, "launch_facts": facts})\n',
     "        receipt = {}\n"),
    ("rollback ungated", AI,
     '    gate = guard_gate(host, row.get("ref"), sorted(row["files"]), ticket, home, "rollback", forced=recorded_guard(row),\n'
     '                      allow_remote=allow_remote)\n', "    gate = None\n"),
    ("resume ungated before the fetch", AI,
     '    gate = guard_gate(row["host"], row["ref"], sorted(row["files"]), ticket, home, "resume", forced=recorded_guard(row),\n'
     '                      allow_remote=allow_remote)\n', "    gate = None\n"),
    ("ref tree not gated", AI, "    if not dry_run and gate is None and ref_guard:\n", "    if False:\n"),
    ("forced names dropped", AI, "    guard = sorted(set(guard_files.guard_subset(files, HOOKS_DIR)) | set(forced))\n",
     "    guard = sorted(set(guard_files.guard_subset(files, HOOKS_DIR)))\n"),
    ("pre-gate rows fail open", AI, '        return sorted(row.get("files") or ())\n', "        return []\n"),
    # guard_files
    ("static names not starting points", GF,
     "        roots |= {name for name in present if is_guard_file(name)}  # the static names are starting points too (F2)\n", ""),
    ("odd manifest shape fails open", GF, "    if not found:\n", "    if False:\n"),
    ("command_guard imports unlisted", GF, '    "safe_input.py", "redact.py", "shell_words.py", "shellwords.py",\n', ""),
    ("closure not used", GF, "    return sorted(b for b in bases if is_guard_file(b) or b in closure)\n",
     "    return sorted(b for b in bases if is_guard_file(b))\n"),
    ("named files not followed", GF, "    out = {w for w in WORD.findall(text) if w in present}\n", "    out = set()\n"),
    ("imports not followed", GF, "            if mod in modules:\n", "            if False:\n"),
    ("unreadable manifest fails open", GF, "    if closure is None:\n        return sorted(bases)\n",
     "    if closure is None:\n        return []\n"),
    ("unreadable module skipped", GF,
     '            raise Unreadable("%s: %s" % (name, type(error).__name__)) from None\n', "            continue\n"),
    ("data and run-by-name files unlisted", GF, '    "dropbox_budget.conf", "domain_checklists.json",\n',
     '    "domain_checklists.json",\n'),
    # launch_check
    ("no terminal needed", LC, '        if not facts["stdin_tty"]:\n', "        if False:\n"),
    ("agent variables ignored", LC, "        if marker:\n", "        if False:\n"),
    ("agent ancestor ignored", LC, "        found = agent_ancestor(table, env.pid())\n", "        found = None\n"),
    ("detached process passes", LC, "        if not root:\n", "        if False:\n"),
    ("ssh or multiplexer passes", LC, "        if remote and not allow_remote:\n", "        if False:\n"),
    ("process table error passes", LC,
     '            return "the process table could not be read to check for an agent ancestor", facts\n', "            table = {}\n"),
    ("surprise fails open", LC, '        return "the launch check failed (%s)" % type(error).__name__, facts\n',
     "        return None, facts\n"),
    # release_receipt
    ("any merge commit counts", RR, 'if (pr.get("merged_at") and pr.get("merge_commit_sha") == ref and base.get("ref") == "main"',
     'if (pr.get("merged_at") and base.get("ref") == "main"'),
    ("unmerged PR counts", RR, 'if (pr.get("merged_at") and pr.get("merge_commit_sha") == ref',
     'if (pr.get("merge_commit_sha") == ref'),
    ("any base branch counts", RR, ' and base.get("ref") == "main"\n', "\n"),
    ("any repository counts", RR, "                and str(repo.get(\"full_name\", \"\")).lower() == CANONICAL_REPO\n", ""),
    ("two PRs accepted", RR, "    if len(found) != 1:\n", "    if not found:\n"),
    ("gh failure ignored", RR, "    if done.returncode != 0:\n", "    if False:\n"),
    ("asserted waiver accepted", RR, '    good = [r for r in rows if r.get("approval_source") in SOURCES]\n', "    good = rows\n"),
    ("waiver head not compared", RR, ' and str(r.get("pr")) == str(number) and r.get("head") == head]',
     ' and str(r.get("pr")) == str(number)]'),
    ("waiver chain not verified", RR, "        records = merge_gate._read_waivers(state_dir)\n",
     "        records = [__import__('json').loads(l) for l in (state_dir / merge_gate.WAIVER_FILE).read_text().splitlines()] "
     "if (state_dir / merge_gate.WAIVER_FILE).exists() else []\n"),
    # mission_gate stamp
    ("dry run or downgrade stamped", MG,
     "        if args.dry_run or args.allow_older or args.resume or args.rollback or not args.from_ref or not args.files:\n",
     "        if not args.from_ref or not args.files:\n"),
    ("computed words stamped", MG,
     '        if not argv or str(argv[0]) != "install-files" or any(getattr(w, "computed", False) for w in argv):\n',
     '        if not argv or str(argv[0]) != "install-files":\n'),
]


def run(tree: Path) -> int:
    return subprocess.run([sys.executable, "-B", "-m", "unittest", "-f", *SUITES], cwd=str(tree),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800).returncode


def copy_tree(dest: Path):
    for part in ("harness/hooks", "scripts", "tests", "templates"):
        if (ROOT / part).is_dir():
            shutil.copytree(ROOT / part, dest / part, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(ROOT / "install.py", dest / "install.py")


def main() -> int:
    survivors, bad = [], []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "real"
        copy_tree(base)
        if run(base) != 0:
            print("the real tree fails its own tests; nothing measured")
            return 1
        for number, (name, rel, old, new) in enumerate(VARIANTS):
            tree = Path(tmp) / ("v%02d" % number)
            shutil.copytree(base, tree)
            path = tree / rel
            text = path.read_text()
            if text.count(old) != 1:
                bad.append(name)
                print("NOT APPLIED  %s" % name)
                shutil.rmtree(tree)
                continue
            path.write_text(text.replace(old, new))
            rc = run(tree)
            print("%-9s %s" % ("killed" if rc else "SURVIVED", name))
            if rc == 0:
                survivors.append(name)
            shutil.rmtree(tree)
    print("%d variants, survivors: %s, not applied: %s" % (len(VARIANTS), ", ".join(survivors) or "none",
                                                          ", ".join(bad) or "none"))
    return 1 if survivors or bad else 0


if __name__ == "__main__":
    sys.exit(main())
