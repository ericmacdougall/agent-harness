"""S3b (GoodQA goodqa#14791): G3 deadlines, I9 handoff acknowledgement, G7 unpushed-unowned prune guard, P18 Codex Stop
gate. Fail on 60b9ff9: no deadline ops, handoffs were terminal forever, prune ignored unpushed commits, Codex Stop ran no gate.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ahd  # noqa: E402
import workdir  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "sess-s3b-00001"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        self.w = self.home / ".claude" / "wals" / SESSION
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 9000), "event": "subagent", "agent_id": "handoffowner", "agent_type": "task-owner"},
                                   {"at": iso(NOW - 3000), "event": "subagent_stop", "agent_id": "handoffowner", "agent_type": "task-owner"}])
        jl(self.w / "agent-handoffowner.jsonl", [{"at": iso(NOW - 4000), "event": "intent", "note": "work"},
                                                 {"at": iso(NOW - 3100), "event": "handoff", "note": "handed to main: PR #1"}])

    def owners(self, now=NOW):
        return ah.owners(self.home, SESSION, now=now)


class Deadlines(Base):
    def test_missed_deadline_is_gated_and_alerted_until_done_or_disposed(self):
        r = ah.write(self.home, "deadline.add", {"session": SESSION, "at": iso(NOW + 1800), "ref": "GoodQA goodqa#14791",
                                                 "owner": "handoffowner", "note": "cutover check"}, SESSION, "dl-key-000001")
        did = r["deadline"]
        self.assertTrue(did.startswith("dl"))
        doc = self.owners(now=NOW)
        self.assertEqual([d["state"] for d in doc["deadlines"]], ["due"])
        self.assertNotIn(did, doc["undisposed"])
        alerts = ahd.deadline_alerts({SESSION: doc}, NOW)
        self.assertEqual(alerts[f"deadline:{did}:due"]["severity"], "warning")
        doc = self.owners(now=NOW + 3600)
        self.assertEqual(doc["deadlines"][0]["state"], "missed")
        self.assertIn(did, doc["undisposed"])
        alerts = ahd.deadline_alerts({SESSION: doc}, NOW + 3600)
        self.assertTrue(alerts[f"deadline:{did}:missed"]["detail"]["stop_block"])
        ah.write(self.home, "deadline.done", {"session": SESSION, "id": did, "note": "checked"}, SESSION, "dl-done-000001")
        doc = self.owners(now=NOW + 3600)
        self.assertEqual(doc["deadlines"][0]["state"], "done")
        self.assertNotIn(did, doc["undisposed"])
        with self.assertRaises(ah.AhError):
            ah.write(self.home, "deadline.add", {"session": SESSION, "at": iso(NOW), "ref": "whatever", "owner": "x", "note": "n"},
                     SESSION, "dl-bad-000001")


class HandoffAck(Base):
    def test_unacked_handoff_needs_a_decision_and_an_ack_clears_it(self):
        by = {r["agent_id"]: r for r in self.owners(now=NOW - 3000)["owners"]}  # 100 s after the handoff: fine
        self.assertEqual(by["handoffowner"]["state"], "handoff")
        self.assertFalse(by["handoffowner"]["decision_required"])
        by = {r["agent_id"]: r for r in self.owners(now=NOW + 1000)["owners"]}  # 68 min later, nobody took it
        self.assertTrue(by["handoffowner"]["decision_required"])
        self.assertIn("handoff-unacked", by["handoffowner"]["flags"])
        ah.write(self.home, "task.dispose", {"agent": "handoffowner", "session": SESSION, "kind": "closed", "at": iso(NOW),
                                             "reason": "main merged the PR", "evidence": "GoodQA goodqa#14791"}, SESSION, "disp-ho-0001")
        by = {r["agent_id"]: r for r in self.owners(now=NOW + 1000)["owners"]}
        self.assertFalse(by["handoffowner"]["decision_required"])


class PruneGuard(unittest.TestCase):
    def test_a_directory_with_unpushed_commits_is_never_a_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with mock.patch.dict(os.environ, {"HOME": tmp}):
                root = workdir.work_root()
                task = root / "old-task"
                repo = task / "wt"
                bare = home / "origin.git"
                repo.mkdir(parents=True)
                env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t",
                       "GIT_COMMITTER_EMAIL": "t@x", "HOME": tmp}
                def git(*a, cwd=repo):
                    subprocess.run(["git", *a], cwd=cwd, env=env, check=True, capture_output=True)
                subprocess.run(["git", "init", "-q", "--bare", str(bare)], env=env, check=True, capture_output=True)
                git("init", "-q")
                git("remote", "add", "origin", str(bare))
                (repo / "f").write_text("1")
                git("add", "f")
                git("commit", "-q", "-m", "one")
                git("push", "-q", "origin", "HEAD:refs/heads/main")
                self.assertEqual(workdir._unpushed_repos(task), [])
                (repo / "f").write_text("2")
                git("commit", "-q", "-am", "two")
                found = workdir._unpushed_repos(task)
                self.assertEqual([f["reason"] for f in found], ["unpushed commits"])
                marker = task / workdir.MARKER
                marker.write_text("{}")
                old = time.time() - 400 * 86400
                os.utime(task, (old, old)); os.utime(marker, (old, old))
                names = [c.get("path") or c.get("name") for c in workdir.candidates()]
                self.assertFalse(any("old-task" in str(n) for n in names), names)
                git("push", "-q", "origin", "HEAD:refs/heads/main")
                self.assertEqual(workdir._unpushed_repos(task), [])


class CodexStopGate(Base):
    def test_codex_stop_blocks_on_an_undisposed_dropped_owner(self):
        real = time.time()  # the hook runs in a subprocess on the real clock, so this owner's rows use real time
        jl(self.w / "main.jsonl", [{"at": iso(real - 9000), "event": "subagent", "agent_id": "cxdrop000001", "agent_type": "task-owner"},
                                   {"at": iso(real - 100), "event": "subagent_stop", "agent_id": "cxdrop000001", "agent_type": "task-owner"}])
        jl(self.w / "agent-cxdrop000001.jsonl", [{"at": iso(real - 4000), "event": "intent", "note": "dropped"}])
        codex_home = self.home / ".codex" / "agent-harness"
        codex_home.mkdir(parents=True)
        for name in ("wal.py",):
            (codex_home / name).write_bytes((ROOT / "codex" / "hooks" / name).read_bytes())
        for name in ("dropped_gate.py", "ah.py", "liveness.py", "safe_input.py", "redact.py", "provenance.py", "provenance_policy.json",
                     "wal.py", "wal_note.py", "ticket_adapters.py"):
            src = HOOKS / name
            if src.exists() and name != "wal.py":
                (codex_home / name).write_bytes(src.read_bytes())
        env = dict(os.environ, HOME=str(self.home), AH_HOME=str(self.home))
        payload = {"hook_event_name": "Stop", "session_id": SESSION, "turn_id": "t1", "stop_hook_active": False}
        os.utime(self.w / "agent-cxdrop000001.jsonl", (real - 4000, real - 4000))
        r = subprocess.run([sys.executable, str(codex_home / "wal.py"), "hook"], input=json.dumps(payload), capture_output=True,
                           text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(out.get("decision"), "block", out)
        self.assertIn("cxdrop000001", out.get("reason", ""))


if __name__ == "__main__":
    unittest.main()
