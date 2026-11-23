"""goodqa#16441 failing-first evidence: each guard of the takeover cleanup has a test that fails when the guard is dropped.

Run: python3 -B tests/mutants_takeover.py [name-substring]   (copies the hooks and the listed tests into a temporary tree,
changes nothing here, deletes the copy). Prints one line per mutant; exit 1 when a mutant survives or does not apply."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROC, TAKEOVER, RULES = "tests.test_ah_proc", "tests.test_takeover", "tests.test_takeover_rules"
VERIFIER, HOOKFORM = "tests.test_ah_worktree_remove.ForeignSession", "tests.test_command_guard_worktree_remove.ForeignSession"
TEST_FILES = ("test_ah_proc.py", "test_takeover.py", "test_takeover_rules.py", "test_ah_worktree_remove.py",
              "test_command_guard_worktree_remove.py", "test_takeover_notice.py")
# Tests written after the code get their red here: the file as it is on origin/main must fail the new tests.
BASELINES = {
    "origin/main ah_kill.py": ("harness/hooks/ah_kill.py", PROC),
    "origin/main command_guard.py (advice)": ("harness/hooks/command_guard.py", "tests.test_command_guard_worktree_remove.ShapeAdvice"),
    "origin/main command_guard.py (verifier)": ("harness/hooks/command_guard.py", VERIFIER),
    "origin/main guard for the takeover forms": ("harness/hooks/command_guard.py", RULES),
    "origin/main wal.py (Claude notice)": ("harness/hooks/wal.py", "tests.test_takeover_notice.ClaudeHook"),
    "origin/main wal.py (Codex notice)": ("codex/hooks/wal.py", "tests.test_takeover_notice.CodexHook"),
}

# name: (hook file, exact old text, new text, the test module or class that must fail)
MUTANTS = {
    "H1 comm bound to argv": ("ah_kill.py", 'if not comm.startswith("/") or not (command == comm or command.startswith(comm + " ")):  # H1', "if False:", PROC),
    "H3 lsof path agrees with comm": ("ah_kill.py", "if exe is not None and exe != comm:", "if False:", PROC),
    "H4 Current names another version": ("ah_kill.py", "if not VERSION_NAME.fullmatch(current) or current == ver:", "if False:", PROC),
    "H5 two second margin": ("ah_kill.py", "st_mtime - started < STALE_MARGIN_S", "st_mtime - started < -1e12", PROC),
    "H6 no bundle process before the helper": ("ah_kill.py", "if other_start is None or other_start <= started:", "if False:", PROC),
    "H7 no other user of the stale version (comm)": ("ah_kill.py", "        if stale_dir in other_comm:\n            return None", "        if False:\n            return None", PROC),
    "H7 no other user of the stale version (maps)": ("ah_kill.py", "        if any(stale_dir in path for path in paths):\n            return None", "        if False:\n            return None", PROC),
    "H8 parent is pid 1": ("ah_kill.py", 'if not m or info.get("ppid") != 1:  # H8', "if not m:", PROC),
    "K7 candidate start time recheck": ("ah_kill.py", 'if _epoch_lstart(info.get("start")) != want:', "if False:", PROC),
    "K6 agent host in session_ancestor": ("ah_kill.py", "if info and is_agent_host(info):", "if info and is_session_process(info):", PROC),
    "K5 exact identity pairs": ("ah_kill.py", 'all(r.get("owner_ids") == [session] for r in foreign_live)', 'all(session in (r.get("owner_ids") or []) for r in foreign_live)', PROC),
    "K2 desktop app refusal": ("ah_kill.py", "app_process = desktop_app(info) and not skip_approvable", "app_process = False", PROC),
    "R2 claim HMAC": ("takeover.py", 'return data if hmac.compare_digest(good, data["hmac"]) else None', "return data", TAKEOVER),
    "R3 transcript stamps": ("takeover.py", "            stamps += list(_last_stamp(transcript))", "            pass", TAKEOVER),
    "R3 last-line stamp": ("takeover.py", 'stamp = _epoch(row.get("at") or row.get("timestamp"))', "stamp = None", TAKEOVER),
    "R3 continuation mtime": ("takeover.py", "            stamps.append(cont_mtime)", "            pass", TAKEOVER),
    "R4 live marker process": ("takeover.py", '            if proc.get("agent_host"):\n                reasons.append("session_live")\n                break', '            if False:\n                reasons.append("session_live")\n                break', TAKEOVER),
    "R5 open work": ("takeover.py", 'if origin.get("open_asks") or open_tasks or origin.get("bg_live"):', "if False:", TAKEOVER),
    "R7 walless quiet window": ("takeover.py", 'if facts.get("exists") and facts.get("newest") is not None and now - facts["newest"] < WALLESS_QUIET_S:', "if False:", TAKEOVER),
    "foreign check in the verifier": ("command_guard.py", "foreign = foreign_session_refusal(path, caller_session, judge=session_judge) if _managed_copy is None else None", "foreign = None", VERIFIER),
    "foreign check in the hook lone form": ("command_guard.py", "if owner is not None and not (HOOK_SESSION and owner.casefold() == str(HOOK_SESSION).casefold()):", "if False:", HOOKFORM),
    "G2 caller session binding": ("takeover_rules.py", "            if any(w.startswith('--caller-session') for w in cmd):\n                return",
                                  "            if False:\n                return", RULES),
    "G3 identity assignment": ("takeover_rules.py", "if on('G3') and names_tool and ID_ASSIGN.search(flat):", "if False:", RULES),
    "G4 continuation binding": ("takeover_rules.py", "if not wals or any(DYNAMIC.search(w) or os.path.basename(os.path.dirname(w)) != own for w in wals):", "if False:", RULES),
    "text rules: unparsable text fails closed": ("takeover_rules.py", "'literal command') if names_tool else None", "'literal command') if False else None", RULES),
    "F1 caller: record start time must match": ("takeover.py", 'if not token or not recorded or recorded != " ".join(str(token).split()):', "if False:", TAKEOVER),
    "F1 caller: environment must agree with the record": ("takeover.py", "if claimed and claimed != sid:", "if False:", TAKEOVER),
    "F1 caller: a differing flag is a mismatch": ("takeover.py", 'if flag and found["caller"] and flag != found["caller"]:', "if False:", TAKEOVER),
    "F1 caller: the verifier CLI derives the caller": ("command_guard.py", "caller, problem = verifier_caller(args.path, args.caller_session)", "caller, problem = args.caller_session, None", VERIFIER),
    "F1 rules: a missing module fails closed": ("command_guard.py", "        if any(tool in flat for tool in TAKEOVER_TOOLS):\n            return ('the takeover command rules could not be loaded",
                                                "        if False:\n            return ('the takeover command rules could not be loaded", RULES),
    "G5 user only script": ("takeover_rules.py", "if on('G5') and SCRIPT in", "if False and SCRIPT in", RULES),
    "F2 owner needs a WAL of that name": ("command_guard.py", "        if os.path.lexists(os.path.join(root, *parent, name)):\n            return name",
                                          "        if True:\n            return name", "tests.test_command_guard_worktree_remove.TaskNamedWorkDir"),
    "F2 a recorded name stays under the rule": ("command_guard.py", "    for parent in (('.claude', 'wals'), ('.agent-harness', 'codex-wals')):",
                                                "    for parent in ():", "tests.test_ah_worktree_remove.RealJudge"),
}


BASELINES["origin/main kill_guard.py (flags, takeover form)"] = ("harness/hooks/kill_guard.py", RULES)


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    (tmp / "tests" / "__init__.py").write_text("")
    for name in TEST_FILES:
        shutil.copy(ROOT / "tests" / name, tmp / "tests")
    (tmp / "codex" / "hooks").mkdir(parents=True)
    shutil.copy(ROOT / "codex" / "hooks" / "wal.py", tmp / "codex" / "hooks" / "wal.py")
    return tmp


def survives(tmp, target):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", target], cwd=str(tmp), capture_output=True, text=True, timeout=900)
    return done.returncode == 0


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    bad = 0
    for name, (rel, target) in BASELINES.items():
        if only and only not in name:
            continue
        tmp = tree()
        try:
            base = subprocess.run(["git", "-C", str(ROOT), "show", "origin/main:" + rel], capture_output=True, check=True).stdout
            (tmp / rel).write_bytes(base)
            alive = survives(tmp, target)
            print("%-52s %s" % (name, "PASSES (the new tests are vacuous)" if alive else "FAILS (good)"), flush=True)
            bad += 1 if alive else 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    for name, (hook, old, new, target) in MUTANTS.items():
        if only and only not in name:
            continue
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / hook
            text = path.read_text()
            if old not in text:
                print("%-52s NOT APPLIED" % name, flush=True)
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            alive = survives(tmp, target)
            print("%-52s %s" % (name, "SURVIVES (a test is vacuous)" if alive else "FAILS (good)"), flush=True)
            bad += 1 if alive else 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
