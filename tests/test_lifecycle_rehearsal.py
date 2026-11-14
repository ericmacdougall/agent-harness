"""Migration and rollback rehearsal (GoodQA goodqa#15952 AC-7, AC-8, the Rollback section, NEG-11, NEG-22).

Needs the pre-change hooks: LC_BASE_HOOKS=<a checkout of origin/main 98e33c5d>/harness/hooks (skipped without it).
  - Synthetic: a ledger holding legacy, pending, agreed and active goals plus edits made after migration. The
    pre-change readers (`mission_coverage.py verify|check|report`, `ah goals`) read it without exit 2, and the
    pre-change writer's `add` and `set` keep every lifecycle block, so the states resume under the new code.
  - Live copy: LC_REHEARSAL_SRC=<dir holding goals.json and the mission-goals-audit.* files> runs migrate-lifecycle on
    a temp copy of the real ledger and prints `LOSSLESS n/n` and `verify ok`, then the same old-reader and old-writer
    steps.
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import test_lifecycle as tl  # noqa: E402
import test_mission_coverage as tmc  # noqa: E402
import mission_coverage as mc  # noqa: E402
import goals_view  # noqa: E402

BASE = os.environ.get("LC_BASE_HOOKS", "")
SRC = os.environ.get("LC_REHEARSAL_SRC", "")
OLD_MAIN = r"""
import json, shlex, sys
hooks, session, transcript = sys.argv[1], sys.argv[2], sys.argv[3]
argv = json.loads(sys.argv[4])
sys.path.insert(0, hooks)
import mission_gate, mission_coverage as mc
if argv[0] in mc.MAIN_ONLY or argv[0] in getattr(mc, "OPTIONAL_MAIN", ()):
    mission_gate.cmd_pretool({"tool_name": "Bash", "session_id": session, "hook_event_name": "PreToolUse",
                              "tool_input": {"command": mc.SCRIPT + " " + " ".join(shlex.quote(a) for a in argv)},
                              "tool_use_id": "toolu_01OLDMAIN000000000000001", "transcript_path": transcript})
sys.exit(mc.main(argv))
"""


def canon(goal: dict) -> str:
    return json.dumps({k: v for k, v in goal.items() if k != "lifecycle"}, sort_keys=True, separators=(",", ":"))


@unittest.skipUnless(BASE and Path(BASE, "mission_coverage.py").is_file(), "LC_BASE_HOOKS (98e33c5d hooks) not set")
class Rehearsal(tl.LBase):
    def old(self, *argv, session=None, transcript=None):
        """The pre-change code, as a separate process (its own modules), against this temp home."""
        env = dict(os.environ, AH_HOME=str(self.home), HOME=str(self.home), CLAUDE_CONFIG_DIR=str(self.home / ".claude"))
        proc = subprocess.run([sys.executable, "-c", OLD_MAIN, BASE, session or tl.SESSION,
                               str(transcript or self.transcript), json.dumps(list(argv))],
                              capture_output=True, text=True, env=env, timeout=120)
        return proc.returncode, proc.stdout + proc.stderr

    def seed_main_wal(self, session):
        """The temp home's main WAL for the copied mission session (the old `check` reads owners from it)."""
        folder = self.home / ".claude" / "wals" / session
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / "main.jsonl", "a") as handle:
            handle.write(json.dumps({"at": tmc.iso(tmc.NOW - 60), "event": "intent", "id": "w0000000000a",
                                     "note": "rehearsal"}) + "\n")

    def old_ah_goals(self):
        env = dict(os.environ, AH_HOME=str(self.home), HOME=str(self.home), CLAUDE_CONFIG_DIR=str(self.home / ".claude"))
        proc = subprocess.run([sys.executable, str(Path(BASE, "ah.py")), "goals", "--session", tl.SESSION],
                              capture_output=True, text=True, env=env, timeout=120)
        return proc.returncode, proc.stdout + proc.stderr

    def states(self):
        rows = mc.read_audit_rows(self.home)
        ok = mc.verify_audit(self.home)["ok"]
        return {g["id"]: mc.lifecycle_state(self.home, g, rows, ok)[0] for g in mc.load_goals(self.home)["goals"]}

    def old_readers_pass(self, session=None, transcript=None):
        for cmd in ("verify", "check", "report"):
            rc, out = self.old(cmd, session=session, transcript=transcript)
            self.assertIn(rc, (0, 1), f"old {cmd}: {out[-400:]}")
            self.assertNotIn("unreadable", out.lower(), f"old {cmd}")
        rc, out = self.old_ah_goals()
        self.assertIn(rc, (0, 1), f"old ah goals: {out[-400:]}")

    def test_synthetic_old_readers_writer_and_resume(self):
        self.seed_old_goals(ids=("old-a", "old-b"))
        self.ok(["migrate-lifecycle"])
        self.to_active("act-goal")
        self.propose("agr-goal", ask=tl.ASK2)
        self.ok(["agree", "--goal", "agr-goal", "--user-source", self.agreed_answer("agr-goal", ask=tl.ASK2)])
        self.ok(["add", "--goal", "pen-goal", "--title", "Pending"])
        self.ok(["set", "--goal", "old-a", "--priority", "1"])  # an edit made after migration
        before = self.states()
        self.assertEqual(before, {"old-a": "legacy", "old-b": "legacy", "act-goal": "active", "agr-goal": "agreed",
                                  "pen-goal": "pending"})
        blocks = {g["id"]: g["lifecycle"] for g in mc.load_goals(self.home)["goals"]}
        self.old_readers_pass()
        # rollback: the pre-change writer works the migrated ledger
        rc, out = self.old("add", "--goal", "rb-new", "--title", "Added by the old code")
        self.assertEqual(rc, 0, out)
        rc, out = self.old("set", "--goal", "old-b", "--priority", "1")
        self.assertEqual(rc, 0, out)
        rc, out = self.old("set", "--goal", "act-goal", "--title", "Renamed by the old code")
        self.assertEqual(rc, 0, out)
        after = {g["id"]: g for g in mc.load_goals(self.home)["goals"]}
        for gid, block in blocks.items():
            self.assertEqual(after[gid].get("lifecycle"), block, f"old writer dropped or changed {gid}'s lifecycle")
        self.assertEqual(after["old-a"]["priority"], 1, "the post-migration edit survived")
        states = self.states()
        self.assertEqual({k: states[k] for k in before}, before, "states resume after reinstall")
        self.assertEqual(states["rb-new"], "pending", "a goal the old writer adds reads PENDING")
        self.assertTrue(mc.verify_audit(self.home)["ok"])

    @unittest.skipUnless(SRC and Path(SRC, "goals.json").is_file(), "LC_REHEARSAL_SRC (copy of the real ledger) not set")
    def test_live_copy_migrates_lossless_and_old_code_reads_it(self):
        mission = self.home / ".agent-harness" / "mission"
        state = self.home / ".agent-harness" / "state"
        shutil.rmtree(mission, ignore_errors=True)
        mission.mkdir(parents=True)
        state.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(SRC, "goals.json"), mission / "goals.json")
        for p in Path(SRC).glob("mission-goals-audit*"):
            shutil.copy2(p, state / p.name)
        self.assertTrue(mc.verify_audit(self.home)["ok"], "the copy must verify before migration")
        loaded = mc.load_goals(self.home)
        session = loaded["mission_session"]
        self.seed_main_wal(session)
        transcript = self.home / ".claude" / "projects" / "proj" / f"{session}.jsonl"
        transcript.write_text(json.dumps({"type": "user", "uuid": "eeeeeeee-1111-4222-8333-444444444444",
                                          "origin": {"kind": "human"}, "timestamp": tmc.iso(tmc.NOW - 60),
                                          "message": {"role": "user", "content": "rehearsal"}}) + "\n")
        pre = {g["id"]: canon(g) for g in loaded["goals"]}
        pre_ev = {g["id"]: g["state"] for g in goals_view.goals_report(self.home, scan_budget_s=0)["goals"]}
        rc, out = self.main_cli(["migrate-lifecycle"], session=session, transcript=transcript)
        self.assertEqual(rc, 0, out)
        result = json.loads(out)
        post_goals = mc.load_goals(self.home)["goals"]
        same = sum(1 for g in post_goals if pre.get(g["id"]) == canon(g))
        print(f"\nLOSSLESS {same}/{len(pre)}; migrated {len(result['migrated'])}; backup {result['backup']}")
        self.assertEqual(same, len(pre))
        self.assertEqual(len(post_goals), len(pre))
        ok = mc.verify_audit(self.home)["ok"]
        print("verify ok" if ok else "verify FAILED")
        self.assertTrue(ok)
        self.assertTrue(Path(result["backup"]).is_dir())
        post_ev = {g["id"]: g["state"] for g in goals_view.goals_report(self.home, scan_budget_s=0)["goals"]}
        self.assertEqual(post_ev, pre_ev, "evidence states unchanged by migration")
        self.assertTrue(all(s == "legacy" for s in self.states().values()))
        again = json.loads(self.main_cli(["migrate-lifecycle"], session=session, transcript=transcript)[1])
        self.assertEqual(again["migrated"], [])  # NEG-11: idempotent
        self.old_readers_pass(session=session, transcript=transcript)
        rc, out = self.old("add", "--goal", "rb-live", "--title", "old writer", session=session, transcript=transcript)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.states()["rb-live"], "pending")
        print("OLD READERS ok; OLD WRITER add keeps", len(pre), "legacy blocks")


if __name__ == "__main__":
    unittest.main()
