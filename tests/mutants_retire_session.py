"""goodqa#17148 failing-first evidence for `ah task retire-session`: tests.test_retire_session must fail against each
controlled broken variant of ah.py or dropped_gate.py (each variant removes one control) and pass against the real files.

Run: python3 -B tests/mutants_retire_session.py   (copies harness/hooks into a temporary tree; changes nothing here).
Exit 0 only when the real files pass and every variant is killed."""
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# name: (file, [(old, new), ...])
MUTANTS = {
    "an unreadable process list reads as nothing running": (
        "ah.py", [("    if r.returncode != 0 or not lines or len(lines) > RETIRE_PS_MAX:", "    if False:")]),
    "a session named in a command line is not running": ("ah.py", [("        if named.search(cmd):\n            found.append(pid)", "        if False:\n            found.append(pid)")]),
    "any path that holds the id counts as the session": ("ah.py", [("        if named.search(cmd):", "        if session in cmd:")]),
    "a process environment is not probed": ("ah.py", [("            if _retire_env_of(pid) == session:", "            if False:")]),
    "an env probe that fails reads as not running": (
        "ah.py", [("    raise AhError(\"retire_unreadable\", f\"task.retire-session: pid {pid} exists", "    return None\n    raise AhError(\"retire_unreadable\", f\"task.retire-session: pid {pid} exists")]),
    "the shell that typed the command counts as the session": ("ah.py", [("        if pid in mine:\n            continue", "        if False:\n            continue")]),
    "recent transcripts are not checked": ("ah.py", [("    if now - tr[\"newest_at\"] < RETIRE_QUIET_S:", "    if False:")]),
    "recent owner activity is not checked": ("ah.py", [("        if now - max(last, sub_activity(home, session, r[\"agent_id\"])) < RETIRE_QUIET_S:", "        if False:")]),
    "a missing transcript is accepted": ("ah.py", [("    if not main_at:\n        raise AhError(\"retire_unreadable\"", "    if False:\n        raise AhError(\"retire_unreadable\"")]),
    "unread owner sources are accepted": ("ah.py", [(" or (data.get(\"read\") or {}).get(\"unread_total\"):", ":")]),
    "a live owner does not stop the retire": ("ah.py", [("raise AhError(\"retire_live_owner\"", "print(\"ignored\") or AhError(\"retire_live_owner\"")]),
    "the source is not checked": ("ah.py", [("    if not res[\"ok\"]:\n        first = res[\"problems\"][0] if res[\"problems\"] else {\"code\": \"rejected\", \"message\": \"rejected\"}\n        raise AhError(\"provenance\", f\"source rejected ({first['code']}): {first['message']}\"[:300], 3)\n    if parse_ts(args[\"ended\"])", "    if parse_ts(args[\"ended\"])")]),
    "a missing source is accepted": ("ah.py", [("        need(\"session\", \"ended\", \"at\", \"source\")", "        need(\"session\", \"ended\", \"at\")")]),
    "replaced-by may name the same session": ("ah.py", [("(not SESSION_RE.match(rb) or rb == args[\"session\"])", "(not SESSION_RE.match(rb))")]),
    "replaced-by may be unknown": ("ah.py", [("    if rb and not (_wal_path(home, rb, \"main\")).is_file():", "    if False:")]),
    "replaced-by and dropped may both be given": ("ah.py", [("if bool(rb) == bool(dropped) or dropped not in (None, True):", "if not (rb or dropped):")]),
    "a session may retire itself": ("ah.py", [("    if caller_session and caller_session == session:", "    if False:"),
                                              ("        if retiring and session and session == args.get(\"session\"):", "        if False:")]),
    "a retry is not a duplicate": ("ah.py", [("            if row.get(\"key\") == k0 and row.get(\"sha\") == sha0:", "            if False:")]),
    "a reused key with another body is not a conflict": ("ah.py", [("            if row.get(\"key\") == k0:\n                raise AhError(\"key_conflict\"", "            if False:\n                raise AhError(\"key_conflict\"")]),
    "the dry run writes the decision": ("ah.py", [("            if args.dry_run:\n                return retire_dry_run(home, args.session)\n", "")]),
    "a retired owner is excused for ever": ("ah.py", [("        if seen > float(d.get(\"at\") or 0.0):", "        if False:")]),
    "a subagent transcript write does not reopen": ("ah.py", [("        seen = max(parse_ts(r[\"last_activity\"]) or 0.0, sub_dirs.get(r[\"agent_id\"], 0.0))", "        seen = parse_ts(r[\"last_activity\"]) or 0.0")]),
    "a retired owner keeps its attention flags": ("ah.py", [("        r[\"decision_required\"], r[\"attention\"], r[\"wait_on\"] = False, [], None", "        r[\"decision_required\"], r[\"wait_on\"] = False, None")]),
    "a retired owner still needs a decision": ("ah.py", [("        r[\"decision_required\"], r[\"attention\"], r[\"wait_on\"] = False, [], None", "        r[\"attention\"], r[\"wait_on\"] = [], None")]),
    "owners get no per-owner disposition": ("ah.py", [("            for who in ((a.get(\"retire\") or {}).get(\"owners\") or []):", "            for who in []:")]),
    "the per-owner audit lines are not written": ("ah.py", [("            for who_id in args[\"retire\"][\"owners\"]:", "            for who_id in []:")]),
    "an owner may retire its own session": ("ah.py", [("        if not pinned or actor_id() in pinned:", "        if not pinned:")]),
    "a sub-agent may run it": ("dropped_gate.py", [("    if words[:2] == [\"task\", \"retire-session\"]:\n        return True", "    if False:\n        return True"),
                                                    ("    return \"retire-session\" in text or (\"dispose\" in text", "    return (\"dispose\" in text")]),
}


def run(tree):
    env = dict(os.environ, RETIRE_HOOKS=str(tree / "hooks"), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "unittest", "-f", "test_retire_session"], cwd=str(tree / "tests"),
                          capture_output=True, text=True, timeout=900, env=env)


def one(job):
    tmp, number, name, (fname, edits) = job
    tree = Path(tmp) / f"m{number}"
    shutil.copytree(ROOT / "harness" / "hooks", tree / "hooks", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (tree / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_retire_session.py", tree / "tests")
    path = tree / "hooks" / fname
    text = path.read_text()
    for old, new in edits:
        if text.count(old) != 1:
            return name, f"BAD VARIANT: pattern found {text.count(old)} times: {old[:60]!r}"
        text = text.replace(old, new)
    path.write_text(text)
    out = run(tree)
    return name, "killed" if out.returncode != 0 else "SURVIVED"


def main():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        shutil.copytree(ROOT / "harness" / "hooks", base / "hooks", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (base / "tests").mkdir()
        shutil.copy(ROOT / "tests" / "test_retire_session.py", base / "tests")
        real = run(base)
        print("real files:", "pass" if real.returncode == 0 else "FAIL\n" + real.stderr[-2000:])
        jobs = [(tmp, i, n, m) for i, (n, m) in enumerate(MUTANTS.items())]
        with ThreadPoolExecutor(4) as pool:
            results = list(pool.map(one, jobs))
    bad = [r for r in results if r[1] != "killed"]
    for name, verdict in results:
        print(f"{verdict:9} {name}" if not verdict.startswith("BAD") else f"{verdict} {name}")
    print(f"{len(results) - len(bad)}/{len(results)} variants killed")
    return 0 if real.returncode == 0 and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
