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
        clock = mock.patch.object(ah, "server_now", side_effect=lambda: iso(NOW))  # the writer clock, pinned in-process only
        clock.start()
        self.addCleanup(clock.stop)
        p.start()
        self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID"):  # the runner may itself be a sub-agent;
            os.environ.pop(k, None)  # patch.dict restores them. Tests act as main unless they set an identity.
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


class ReviewRound1(Base):
    """S3b blind review findings B1, M2 (part), M3, M4 and the deadline.done minor; each fails on 0fd3857."""

    def test_codex_only_session_is_visible_gated_and_writable(self):
        """B1: a session whose WALs live only under ~/.agent-harness/codex-wals."""
        real = time.time()
        cw = self.home / ".agent-harness" / "codex-wals" / "sess-codex-only1"
        jl(cw / "main.jsonl", [{"at": iso(real - 9000), "event": "subagent", "agent_id": "cxonly000001", "agent_type": "task-owner"},
                               {"at": iso(real - 100), "event": "subagent_stop", "agent_id": "cxonly000001", "agent_type": "task-owner"}])
        jl(cw / "agent-cxonly000001.jsonl", [{"at": iso(real - 4000), "event": "intent", "note": "codex work"}])
        self.assertFalse((self.home / ".claude" / "wals" / "sess-codex-only1").exists())
        with mock.patch.object(ah, "server_now", side_effect=lambda: iso(real)):
            doc = ah.owners(self.home, "sess-codex-only1", now=real)
            self.assertEqual(doc["undisposed"], ["cxonly000001"])
            import dropped_gate
            out = dropped_gate.cmd_stop({"session_id": "sess-codex-only1", "stop_hook_active": False}, now=real)
            self.assertEqual(out.get("decision"), "block")
            r = ah.write(self.home, "task.dispose", {"agent": "cxonly000001", "session": "sess-codex-only1", "kind": "closed",
                                                     "at": iso(real), "reason": "superseded in test", "evidence": "GoodQA goodqa#14791"},
                         "sess-codex-only1", "disp-codex-0001")
            self.assertEqual(r["result"], "applied")
            rows = [json.loads(l) for l in (cw / "main.jsonl").read_text().splitlines()]
            self.assertEqual(rows[-1]["event"], "disposition")  # written into the Codex root, not ~/.claude/wals
            self.assertEqual(ah.owners(self.home, "sess-codex-only1", now=real)["undisposed"], [])

    def test_owner_cannot_dispose_itself_and_stamps_are_server_side(self):
        """M4: the I9 ack is not forgeable by the owner; `at` is the writer's clock, never the caller's."""
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "handoffowner"}):
            with self.assertRaises(ah.AhError) as cm:
                ah.write(self.home, "task.dispose", {"agent": "handoffowner", "session": SESSION, "kind": "closed", "at": iso(NOW),
                                                     "reason": "I say I am done", "evidence": "GoodQA goodqa#14791"}, SESSION, "self-ack-01")
            self.assertEqual(cm.exception.code, "forbidden")
            ok = ah.write(self.home, "task.dispose", {"agent": "handoffowner", "session": SESSION, "kind": "waiting", "at": iso(NOW - 99999),
                                                      "ref": "GoodQA goodqa#14791", "until": iso(NOW + 600)}, SESSION, "self-wait-01")
            self.assertEqual(ok["result"], "applied")  # an owner may name what it waits on
        rows = [json.loads(l) for l in (self.w / "main.jsonl").read_text().splitlines()]
        self.assertEqual(rows[-1]["event"], "disposition")
        disp = ah.dispositions(self.home, SESSION)["handoffowner"]
        self.assertEqual(int(disp["at"]), int(NOW))  # the caller's backdated `at` was ignored

    def test_env_clock_is_not_a_bypass_and_child_sessions_cannot_ack(self):
        """Round 2 blocker and M1: no caller-chosen stamp; a sub-agent shell cannot acknowledge a handoff."""
        with mock.patch.dict(os.environ, {"AH_NOW": str(NOW + 10 * 365 * 86400)}):
            self.assertNotIn("AH_NOW", ah.server_now.__doc__ or "")
            self.assertEqual(int(ah.parse_ts(ah.server_now())), int(NOW))  # the patched writer clock, not the env
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_CHILD_SESSION": "1"}, clear=False):
            os.environ.pop("AH_AGENT_ID", None)
            with self.assertRaises(ah.AhError) as cm:
                ah.write(self.home, "task.dispose", {"agent": "handoffowner", "session": SESSION, "kind": "resumed", "at": iso(NOW)},
                         SESSION, "child-ack-01")
            self.assertEqual(cm.exception.code, "forbidden")
        self.assertEqual(ah.actor_id(), "unknown") if not os.environ.get("AGENT_ID") else None

    def test_unknown_deadline_id_is_refused(self):
        with self.assertRaises(ah.AhError) as cm:
            ah.write(self.home, "deadline.done", {"session": SESSION, "id": "dl0123456789", "note": "x"}, SESSION, "dl-done-bad")
        self.assertEqual(cm.exception.code, "unknown_deadline")

    def test_gate_advice_fits_the_subject(self):
        """M3: a missed deadline names `ah deadline done`; an unacked handoff names the acknowledging kinds, not waiting."""
        import dropped_gate
        text = dropped_gate.message(["dl0123456789", "handoffowner"], {"handoffowner": {"idle_s": 4000, "flags": ["handoff-unacked"]}})
        self.assertIn("ah deadline done --id dl0123456789", text)
        ho = text.split("handoffowner", 1)[1]
        self.assertIn("--kind resumed", ho)
        self.assertNotIn("--kind waiting", ho.split("\n  - ")[0])


class PruneGuardDepth(unittest.TestCase):
    """M2: the guard examines `.git` before truncating, counts a depth overrun as unpushed, and sees detached and worktree commits."""

    def git(self, *a, cwd, env):
        return subprocess.run(["git", *a], cwd=cwd, env=env, check=True, capture_output=True, text=True)

    def test_depth_three_clone_detached_head_and_worktree_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x", "HOME": tmp}
            bare = home / "origin.git"
            subprocess.run(["git", "init", "-q", "--bare", str(bare)], env=env, check=True)
            task = home / "task"
            deep = task / "a" / "b" / "repo"  # exactly three levels under the task dir
            deep.mkdir(parents=True)
            self.git("init", "-q", cwd=deep, env=env)
            self.git("remote", "add", "origin", str(bare), cwd=deep, env=env)
            (deep / "f").write_text("1")
            self.git("add", "f", cwd=deep, env=env)
            self.git("commit", "-q", "-m", "one", cwd=deep, env=env)
            self.git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=deep, env=env)
            self.assertEqual(workdir._unpushed_repos(task), [])
            (deep / "f").write_text("2")
            self.git("commit", "-q", "-am", "two", cwd=deep, env=env)
            self.assertEqual([f["reason"] for f in workdir._unpushed_repos(task)], ["unpushed commits"])  # depth 3 is examined
            self.git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=deep, env=env)
            self.git("checkout", "-q", "--detach", cwd=deep, env=env)
            (deep / "f").write_text("3")
            self.git("commit", "-q", "-am", "detached", cwd=deep, env=env)
            self.assertEqual([f["reason"] for f in workdir._unpushed_repos(task)], ["unpushed commits"])  # detached HEAD counts
            self.git("push", "-q", "origin", "HEAD:refs/heads/detached-saved", cwd=deep, env=env)
            self.assertEqual(workdir._unpushed_repos(task), [])
            wt = task / "wt"
            self.git("worktree", "add", "-q", str(wt), "-b", "wtbranch", cwd=deep, env=env)
            (wt / "g").write_text("w")
            self.git("add", "g", cwd=wt, env=env)
            self.git("commit", "-q", "-m", "wt", cwd=wt, env=env)
            self.assertTrue(any(f["repo"] == str(wt) for f in workdir._unpushed_repos(task)))  # a .git file is a repo too
            deeper = task / "x" / "y" / "z" / "w"
            deeper.mkdir(parents=True)
            found = workdir._unpushed_repos(task / "x", max_depth=2)
            self.assertTrue(any("depth overrun" in f["reason"] for f in found))  # unexamined subtree is never pruned
            # M2: a pushed checkout with deep source dirs is not "unexamined": git answered for it
            (deep / "src" / "pkg" / "mod" / "sub").mkdir(parents=True)
            self.git("push", "-q", "origin", "HEAD:refs/heads/wtbranch", cwd=wt, env=env)
            overrun = [f for f in workdir._unpushed_repos(task) if "depth overrun" in f["reason"]]
        self.assertEqual([f for f in overrun if f["repo"].startswith(str(deep))], [])  # nothing inside the checkout
        self.assertEqual([f["repo"] for f in overrun], [str(task / "x" / "y" / "z")])  # the plain deep dir still is


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
