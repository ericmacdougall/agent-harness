"""Failing-first set for the guard-file install gate (goodqa#16944, PR 326a). Each variant removes one control in a
temporary copy of the tree; tests.test_guard_install_gate must fail against every variant and pass against the real files.

    python3 -B tests/mutants_guard_install_gate.py [--jobs N] [--full] [--only NAME]...
        exit 0 when the real tree passes and every variant is killed

A variant listed in KILLERS counts as killed only when EACH of its named end-to-end tests fails, run alone in that
variant's tree (so a variant cannot be "killed" by an unrelated test while the test meant for it passes: PR 345 review
F11). Any other variant counts as killed when the whole suite fails; the first failing test is printed. --full runs the
whole suite for every variant and prints every failing test. GATE_COVERAGE maps every guard_gate call site in
ah_install.py, and each gating argument and skip condition there, to its variants; tests/test_guard_gate_coverage.py
(not run inside the variants, so it cannot kill one) fails when a call site or argument has none.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import re
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
    # ah_install: each gating argument at each guard_gate call site (PR 345 review F11: fix the class)
    ("install: no files reach the gate", AI,
     'guard_gate(host, ref, list(files), ticket, home, "install", allow_older, allow_remote=allow_remote)',
     'guard_gate(host, ref, [], ticket, home, "install", allow_older, allow_remote=allow_remote)'),
    ("install: --allow-older not passed to the gate", AI,
     'guard_gate(host, ref, list(files), ticket, home, "install", allow_older, allow_remote=allow_remote)',
     'guard_gate(host, ref, list(files), ticket, home, "install", False, allow_remote=allow_remote)'),
    ("install: ssh or a multiplexer always allowed", AI,
     'guard_gate(host, ref, list(files), ticket, home, "install", allow_older, allow_remote=allow_remote)',
     'guard_gate(host, ref, list(files), ticket, home, "install", allow_older, allow_remote=True)'),
    ("resume: no files reach the gate", AI, 'row["ref"], sorted(row["files"]), ticket, home, "resume",',
     'row["ref"], [], ticket, home, "resume",'),
    ("resume gated as an install", AI, 'ticket, home, "resume", forced=recorded_guard(row),',
     'ticket, home, "install", forced=recorded_guard(row),'),
    ("resume ignores the recorded gate", AI, 'ticket, home, "resume", forced=recorded_guard(row),',
     'ticket, home, "resume", forced=(),'),
    ("resume: ssh or a multiplexer always allowed", AI,
     'home, "resume", forced=recorded_guard(row),\n                      allow_remote=allow_remote)',
     'home, "resume", forced=recorded_guard(row),\n                      allow_remote=True)'),
    ("rollback: no files reach the gate", AI, 'row.get("ref"), sorted(row["files"]), ticket, home, "rollback",',
     'row.get("ref"), [], ticket, home, "rollback",'),
    ("rollback gated as an install", AI, 'ticket, home, "rollback", forced=recorded_guard(row),',
     'ticket, home, "install", forced=recorded_guard(row),'),
    ("rollback ignores the recorded gate", AI, 'ticket, home, "rollback", forced=recorded_guard(row),',
     'ticket, home, "rollback", forced=(),'),
    ("rollback: ssh or a multiplexer always allowed", AI,
     'home, "rollback", forced=recorded_guard(row),\n                      allow_remote=allow_remote)',
     'home, "rollback", forced=recorded_guard(row),\n                      allow_remote=True)'),
    ("ref gate: no files reach it", AI,
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=allow_remote)",
     "guard_gate(host, ref, [], ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=allow_remote)"),
    ("ref gate treats every run as an install", AI,
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=allow_remote)",
     "guard_gate(host, ref, files, ticket, home, 'install', allow_older, forced=ref_guard, allow_remote=allow_remote)"),
    ("ref gate: --allow-older not passed", AI,
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=allow_remote)",
     "guard_gate(host, ref, files, ticket, home, kind_, False, forced=ref_guard, allow_remote=allow_remote)"),
    ("ref gate ignores the ref's guard files", AI,
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=allow_remote)",
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=(), allow_remote=allow_remote)"),
    ("ref gate: ssh or a multiplexer always allowed", AI,
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=allow_remote)",
     "guard_gate(host, ref, files, ticket, home, kind_, allow_older, forced=ref_guard, allow_remote=True)"),
    ("ref-only guard files left out of the record", AI,
     '        gate = dict(gate, guard_files=sorted(set(gate["guard_files"]) | set(ref_guard)))\n', "        pass\n"),
    ("a dry run writes", AI,
     '    if dry_run:\n        try:\n            audit(home, {"event": "result", "run": run, "host": host, "kind": "dry_run"',
     '    if False:\n        try:\n            audit(home, {"event": "result", "run": run, "host": host, "kind": "dry_run"'),
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
    # the stamp key: main's stamp covers that exact host, ref, file set and ticket (the non-gating call-site arguments)
    ("stamp key ignores the host", GF,
     '    return [str(host), str(ref), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]\n',
     '    return [str(ref), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]\n'),
    ("stamp key ignores the ref", GF,
     '    return [str(host), str(ref), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]\n',
     '    return [str(host), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]\n'),
    ("stamp key ignores the files", GF,
     '    return [str(host), str(ref), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]\n',
     '    return [str(host), str(ref), str(ticket)]\n'),
    ("stamp key ignores the ticket", GF,
     '    return [str(host), str(ref), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]\n',
     '    return [str(host), str(ref), ",".join(sorted(str(f) for f in (files or ())))]\n'),
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
    ("the refusal names the flag", LC, 'so this is refused here (docs/harness-repair.md, guard files)" % remote[0]), facts',
     'so this needs --from-ssh-or-multiplexer typed by the user" % remote[0]), facts'),
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


G = "Gate."
# The end-to-end tests that must each fail against the variant (run alone in its tree). Every variant named in
# GATE_COVERAGE has an entry; each goes through a public entry (install_files, resume, rollback) of its route.
KILLERS = {
    "gate never consulted": (G + "test_a_guard_file_known_locally_is_refused_before_any_fetch",),
    "agent may downgrade, resume or roll back": (G + "test_resume_of_a_guard_file_is_the_users_end_to_end",
                                                 G + "test_rollback_of_a_guard_file_is_the_users"),
    "install: no files reach the gate": (G + "test_a_guard_file_known_locally_is_refused_before_any_fetch",),
    "install: --allow-older not passed to the gate": (G + "test_a_downgrade_is_refused_even_with_stamp_and_receipt",),
    "install: ssh or a multiplexer always allowed": (G + "test_an_install_over_ssh_or_in_a_multiplexer_needs_the_users_flag",),
    "a dry run writes": (G + "test_an_agents_dry_run_of_a_guard_file_writes_nothing",),
    "resume ungated before the fetch": (G + "test_resume_of_a_guard_file_is_the_users_end_to_end",),
    "resume: no files reach the gate": (G + "test_a_record_that_names_no_guard_file_never_narrows_the_local_tree",),
    "resume gated as an install": (G + "test_resume_of_a_guard_file_is_the_users_end_to_end",),
    "resume ignores the recorded gate": (G + "test_resume_of_a_ref_only_guard_file_is_refused_before_the_fetch",
                                         G + "test_a_run_recorded_before_the_gate_is_gated_end_to_end"),
    "resume: ssh or a multiplexer always allowed": (G + "test_a_resume_over_ssh_or_in_a_multiplexer_needs_the_users_flag",),
    "rollback ungated": (G + "test_rollback_of_a_guard_file_is_the_users",),
    "rollback: no files reach the gate": (G + "test_a_record_that_names_no_guard_file_never_narrows_the_local_tree",),
    "rollback gated as an install": (G + "test_rollback_of_a_guard_file_is_the_users",),
    "rollback ignores the recorded gate": (G + "test_rollback_of_a_ref_only_guard_file_is_the_users",
                                           G + "test_a_run_recorded_before_the_gate_is_gated_end_to_end"),
    "rollback: ssh or a multiplexer always allowed": (G + "test_rollback_of_a_guard_file_is_the_users",),
    "pre-gate rows fail open": (G + "test_a_run_recorded_before_the_gate_is_gated_end_to_end",
                                G + "test_a_run_recorded_before_the_gate_counts_every_file_as_a_guard_file"),
    "ref tree not gated": (G + "test_a_file_that_is_a_guard_file_only_at_the_ref_is_gated",),
    "ref gate: no files reach it": (G + "test_main_installs_a_ref_only_guard_file_with_its_stamp",),
    "ref gate treats every run as an install": (G + "test_the_ref_gate_keeps_resume_the_users_when_the_record_names_none",),
    "ref gate: --allow-older not passed": (G + "test_a_ref_only_guard_file_downgrade_is_the_users",),
    "ref gate ignores the ref's guard files": (G + "test_a_file_that_is_a_guard_file_only_at_the_ref_is_gated",),
    "ref gate: ssh or a multiplexer always allowed": (G + "test_a_ref_only_install_over_ssh_needs_the_users_flag",),
    "ref-only guard files left out of the record": (G + "test_the_record_lists_the_refs_guard_files_too",),
    "stamp key ignores the host": (G + "test_a_stamp_covers_only_its_exact_command",),
    "stamp key ignores the ref": (G + "test_a_stamp_covers_only_its_exact_command",),
    "stamp key ignores the files": (G + "test_a_stamp_covers_only_its_exact_command",),
    "stamp key ignores the ticket": (G + "test_a_stamp_covers_only_its_exact_command",),
    "the refusal names the flag": ("LaunchCheck.test_ssh_or_a_multiplexer_refuses_unless_the_user_typed_the_flag",
                                   G + "test_an_install_over_ssh_or_in_a_multiplexer_needs_the_users_flag",
                                   G + "test_a_resume_over_ssh_or_in_a_multiplexer_needs_the_users_flag",
                                   G + "test_rollback_of_a_guard_file_is_the_users"),
}

# Every guard_gate call site in ah_install.py: (enclosing function, control) -> the variants that remove it. "call" is
# the call itself; an argument name is that gating argument set to the value that removes it (files [], kind_
# "install", allow_older False, forced (), allow_remote True); "skip: <condition>" is a condition that skips the call,
# mapped to the variants that remove what makes skipping safe. tests/test_guard_gate_coverage.py derives the keys from
# the source and fails on a missing or stale key.
GATE_COVERAGE = {
    ("install_files", "call"): ("gate never consulted",),
    ("install_files", "files"): ("install: no files reach the gate", "stamp key ignores the files"),  # also a stamp-key part
    ("install_files", "allow_older"): ("install: --allow-older not passed to the gate",),
    ("install_files", "allow_remote"): ("install: ssh or a multiplexer always allowed",),
    ("install_files", "skip: dry_run"): ("a dry run writes",),
    ("resume", "call"): ("resume ungated before the fetch",),
    ("resume", "files"): ("resume: no files reach the gate",),
    ("resume", "kind_"): ("resume gated as an install",),
    ("resume", "forced"): ("resume ignores the recorded gate", "pre-gate rows fail open"),
    ("resume", "allow_remote"): ("resume: ssh or a multiplexer always allowed",),
    ("rollback", "call"): ("rollback ungated",),
    ("rollback", "files"): ("rollback: no files reach the gate",),
    ("rollback", "kind_"): ("rollback gated as an install",),
    ("rollback", "forced"): ("rollback ignores the recorded gate", "pre-gate rows fail open"),
    ("rollback", "allow_remote"): ("rollback: ssh or a multiplexer always allowed",),
    ("_run", "call"): ("ref tree not gated",),
    ("_run", "files"): ("ref gate: no files reach it",),
    ("_run", "kind_"): ("ref gate treats every run as an install",),
    ("_run", "allow_older"): ("ref gate: --allow-older not passed",),
    ("_run", "forced"): ("ref gate ignores the ref's guard files",),
    ("_run", "allow_remote"): ("ref gate: ssh or a multiplexer always allowed",),
    ("_run", "skip: not dry_run and gate is None and ref_guard"): ("a dry run writes",
                                                                   "ref-only guard files left out of the record"),
}

# guard_gate's parameters that are not in the coverage test's GATING list: they name the command rather than lift or
# narrow the gate, so GATE_COVERAGE does not inventory them per call site. Each maps to the variants that drop it from
# main's stamp key (host, ref and ticket, like files, are parts of guard_files.install_stamp_parts), or to the reason it
# has none. tests/test_guard_gate_coverage.py fails on a guard_gate parameter, keyword-only included, in neither list.
NON_GATING = {
    "host": ("stamp key ignores the host",),
    "ref": ("stamp key ignores the ref",),  # also the release receipt's subject: test_main_installs_a_reviewed_merged_commit
    "ticket": ("stamp key ignores the ticket",),
    "home": "it only says where the stamp and the audit are read; every call site passes the installer's own home",
}

FAILED = re.compile(r"^(?:FAIL|ERROR): (\w+) \(([\w.]+)\)", re.M)


def failed_tests(output: str) -> list:
    """['Class.test_name'] of every FAIL or ERROR line (Python 3.9 prints (module.Class), 3.11+ (module.Class.test))."""
    out = []
    for method, dotted in FAILED.findall(output):
        parts = dotted.split(".")
        cls = parts[-2] if parts[-1] == method and len(parts) > 1 else parts[-1]
        if "%s.%s" % (cls, method) not in out:
            out.append("%s.%s" % (cls, method))
    return out


def run(tree: Path, tests=None, failfast=True):
    """(returncode, failed test ids) of the whole suite, or of TESTS (ids relative to the suite module)."""
    names = ["%s.%s" % (SUITES[0], t) for t in tests] if tests else list(SUITES)
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", *(["-f"] if failfast else []), *names], cwd=str(tree),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
    return done.returncode, failed_tests(done.stdout)


def copy_tree(dest: Path):
    for part in ("harness/hooks", "scripts", "tests", "templates"):
        if (ROOT / part).is_dir():
            shutil.copytree(ROOT / part, dest / part, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(ROOT / "install.py", dest / "install.py")


def measure(base: Path, tmp: Path, number: int, variant, full: bool):
    """(status, detail) for one variant: killed, SURVIVED, NOT KILLED BY ITS TEST, or NOT APPLIED."""
    name, rel, old, new = variant
    tree = tmp / ("v%02d" % number)
    shutil.copytree(base, tree)
    try:
        path = tree / rel
        text = path.read_text()
        if text.count(old) != 1:
            return "NOT APPLIED", ""
        path.write_text(text.replace(old, new))
        killers = None if full else KILLERS.get(name)
        if killers:
            rc, failed = run(tree, killers, failfast=False)
            missed = [k for k in killers if k not in failed]
            if rc == 0 or missed:
                return "NOT KILLED BY ITS TEST", ", ".join(missed)
            return "killed", "by " + ", ".join(killers)
        rc, failed = run(tree, failfast=not full)
        if rc == 0:
            return "SURVIVED", ""
        return "killed", ("by " if full else "first by ") + (", ".join(failed) or "exit %d" % rc)
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--jobs", type=int, default=1, help="variants measured at once (each in its own tree copy)")
    ap.add_argument("--full", action="store_true", help="run the whole suite for every variant; print every failing test")
    ap.add_argument("--only", action="append", default=[], help="measure only this variant (repeatable)")
    args = ap.parse_args(argv)
    unknown = [n for n in args.only if n not in {v[0] for v in VARIANTS}] + [n for n in KILLERS if n not in {v[0] for v in VARIANTS}]
    if unknown:
        print("unknown variant name(s): %s" % ", ".join(unknown))
        return 2
    chosen = [(i, v) for i, v in enumerate(VARIANTS) if not args.only or v[0] in args.only]
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "real"
        copy_tree(base)
        rc, failed = run(base)
        if rc != 0:
            print("the real tree fails its own tests (%s); nothing measured" % (", ".join(failed) or "exit %d" % rc))
            return 1
        named = sorted({k for _, v in chosen for k in KILLERS.get(v[0], ())})
        if named and not args.full:
            rc, failed = run(base, named, failfast=False)  # each named test exists and passes on the real tree
            if rc != 0:
                print("a named killer test fails or is missing on the real tree (%s); nothing measured" % ", ".join(failed))
                return 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            results = list(pool.map(lambda item: measure(base, Path(tmp), item[0], item[1], args.full), chosen))
    bad = {}
    for (_, (name, *_)), (status, detail) in zip(chosen, results):
        print("%-9s %s%s" % (status, name, ("  [%s]" % detail) if detail else ""))
        if status != "killed":
            bad.setdefault(status, []).append(name)
    print("%d variants, %s" % (len(chosen), "; ".join("%s: %s" % (k, ", ".join(v)) for k, v in sorted(bad.items()))
                                or "all killed"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
