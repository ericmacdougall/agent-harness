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
IDENTITY = "tests.test_takeover_identity"
TEST_FILES = ("test_ah_proc.py", "test_takeover.py", "test_takeover_rules.py", "test_ah_worktree_remove.py",
              "test_command_guard_worktree_remove.py", "test_takeover_notice.py", "test_takeover_identity.py")
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
    "foreign check in the verifier": ("command_guard.py", "foreign = foreign_session_refusal(path, judge=session_judge) if _managed_copy is None and not own else None", "foreign = None", VERIFIER),
    "foreign check in the hook lone form": ("command_guard.py", "if owner is not None and not (HOOK_SESSION and owner.casefold() == str(HOOK_SESSION).casefold()):", "if False:", HOOKFORM),
    "R4 record start time must match": ("takeover.py", 'if not token or not recorded or recorded != " ".join(str(token).split()):', "if False:", TAKEOVER),
    # the identity class fix (rescue after review rounds 1-2): identity only from the hook payload
    "ID a flag names the caller again": ("command_guard.py", "own=own_grant(args.path))", "own=True)", IDENTITY),
    "ID the grant HMAC": ("takeover.py", "    if not hmac.compare_digest(good, data[\"hmac\"]):\n        return False\n    now = time.time() if now is None else now\n    if data[\"v\"] != 1",
                          "    if False:\n        return False\n    now = time.time() if now is None else now\n    if data[\"v\"] != 1", IDENTITY),
    "ID the grant is bound to the HEAD": ("takeover.py", 'return bool(live) and live == data["head"]', "return True", IDENTITY),
    "ID the grant is bound to the owner": ("takeover.py", 'if data["path"] != path or not owner or str(data["session"]).casefold() != str(owner).casefold():',
                                           'if data["path"] != path:', IDENTITY),
    "ID the grant is single use": ("takeover.py", "        try:\n            os.unlink(taken)\n        except OSError:\n            pass\n    if not isinstance(data, dict)",
                                   "        try:\n            os.rename(taken, target)\n        except OSError:\n            pass\n    if not isinstance(data, dict)", IDENTITY),
    "ID grants only for the payload session's own dirs": ("command_guard.py", "if not owner or owner.casefold() != str(HOOK_SESSION).casefold():",
                                                          "if not owner:", IDENTITY),
    "ID a piped payload gets no grant": ("command_guard.py", "        if not cli or cli.casefold() != str(HOOK_SESSION).casefold():\n            return 0",
                                         "        if False:\n            return 0", IDENTITY),
    "ID the Mac verifier reads t2-dev too": ("command_guard.py", "            if here.get('state') not in ('retired', 'walless') or sys.platform.startswith('linux'):",
                                             "            if True:", IDENTITY),
    "m2 stale helpers keep their predicate": ("takeover.py", "                                     predicate=still_stale)", "                                     predicate=None)", IDENTITY),
    "m3 exact Claude executable": ("takeover.py", "CLAUDE_EXE = re.compile(", "CLAUDE_EXE = re.compile(r'claude') or re.compile(", IDENTITY),
    "M2 ah refuses abbreviations": ("ah.py", "    _no_abbrev(p)\n    return p", "    return p", IDENTITY),
    "M2 the verifier refuses abbreviations": ("command_guard.py", "        kwargs['allow_abbrev'] = False", "        pass", IDENTITY),
    "F1 rules: a missing module fails closed": ("command_guard.py", "        if any(tool in flat for tool in TAKEOVER_TOOLS):\n            return ('the takeover command rules could not be loaded",
                                                "        if False:\n            return ('the takeover command rules could not be loaded", RULES),
    "G5 user only entry points": ("takeover_rules.py", "if on('G5'):", "if False:", RULES),
    "F2 owner needs a WAL of that name": ("command_guard.py", "        if os.path.lexists(os.path.join(root, *parent, name)):\n            return name",
                                          "        if True:\n            return name", "tests.test_command_guard_worktree_remove.TaskNamedWorkDir"),
    "F2 a recorded name stays under the rule": ("command_guard.py", "    for parent in (('.claude', 'wals'), ('.agent-harness', 'codex-wals')):",
                                                "    for parent in ():", "tests.test_ah_worktree_remove.RealJudge"),
    "F3 a Linux caller judges this host": ("takeover.py", "    if local_is_remote:\n        return LOCAL_ONLY",
                                           "    if local_is_remote:\n        return None", "tests.test_takeover.LinuxCaller"),
    "F3 a Linux caller can claim": ("takeover.py", "    if remote == LOCAL_ONLY:\n        evs = [ev]", "    if False:\n        evs = [ev]",
                                    "tests.test_takeover.LinuxCaller"),
    "F3 R2 reads the origin claim": ("takeover.py", '    claim = origin.get("claim")', '    claim = ev.get("claim")',
                                     "tests.test_takeover.LinuxCaller"),
    "F3 R4 Claude session record": ("takeover.py", "    live += [proc for proc in _record_live(old, home, probe, table) if proc[\"pid\"] not in seen]",
                                    "    live += []", "tests.test_takeover.SessionRecordLiveness"),
    "F3 R4 records of exited pids are not counted": ("takeover.py", "    pids = sorted(pid for pid in pids if pid in table)",
                                                     "    pids = sorted(pids)", "tests.test_takeover.SessionRecordLiveness"),
    "F3 remote worktree paths": ("takeover.py", "        if 1 <= depth <= 2:", "        if True:", "tests.test_takeover.TombstoneAndRemotePaths"),
    "F3 an update keeps the claim time": ("takeover.py", '"claimed_at": _iso(now) if claimed else kept,', '"claimed_at": _iso(now),',
                                          "tests.test_takeover.TombstoneAndRemotePaths"),
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
    (tmp / "scripts").mkdir()
    for name in ("enable-takeover-cleanup.sh", "enable_takeover_cleanup.py"):
        shutil.copy2(ROOT / "scripts" / name, tmp / "scripts" / name)
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
