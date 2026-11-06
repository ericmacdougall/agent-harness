"""Dispose guard (goodqa#14791; user requests relayed by main, main WAL w3dcbe6b8ffa and w07450081c12).

- `closed` means done, and done means deployed to live and tested: it needs a deploy record and a REALLY_TESTED run
  against the live target, both about that owner. A merge sha, a plain WAL note or a ticket alone is refused.
- Work that will not ship is `superseded` or `wontdo`, with a ticket, and never counts as done.
- One evidence entry per owner unless it names each owner; a burst of closes from one actor is refused and alerted;
  reasons are specific; `legacy` exists only for owners that went quiet before the gate was installed.

Fails on 36feecd: main closed 19 owners in a loop with one reason and one old WAL id, and every call was accepted.
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
import dropped_gate  # noqa: E402
import ops_watch  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "sess-dispguard-01"
OLD_WAL_ID = "we3351cead78"  # the id main cited 19 times: an old routing note that names none of the owners
LOOP_REASON = "cleared to unblock the stop gate; work superseded"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def agent(i):
    return f"a{0xd15e0000 + i:016x}"


class Base(unittest.TestCase):
    N = 19

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID"):  # the runner may itself be a sub-agent
            os.environ.pop(k, None)
        self.clock = NOW
        c = mock.patch.object(ah, "server_now", side_effect=lambda: iso(self.clock))
        c.start()
        self.addCleanup(c.stop)
        t = mock.patch.object(ah.time, "time", side_effect=lambda: self.clock)  # burst windows and audit stamps
        t.start()
        self.addCleanup(t.stop)
        self.w = self.home / ".claude" / "wals" / SESSION
        rows = [{"at": iso(NOW - 90000), "event": "decision", "id": OLD_WAL_ID, "note": "route reviews through the reviewer agent"}]
        for i in range(self.N):
            rows += [{"at": iso(NOW - 30000), "event": "subagent", "agent_id": agent(i), "agent_type": "task-owner"},
                     {"at": iso(NOW - 24000), "event": "subagent_stop", "agent_id": agent(i), "agent_type": "task-owner"}]
        jl(self.w / "main.jsonl", rows)
        for i in range(self.N):
            jl(self.w / f"agent-{agent(i)}.jsonl", [{"at": iso(NOW - 25000), "event": "intent", "note": f"slice {i} work"}])
        self.n = 0

    def dispose(self, who, kind="closed", **extra):
        args = {"agent": who, "session": SESSION, "kind": kind, "at": iso(self.clock)}
        args.update(extra)
        return ah.write(self.home, "task.dispose", args, SESSION)

    def entry(self, event, text, at=None):
        self.n += 1
        wid = f"w{0xabc00000000 + self.n:011x}"
        jl(self.w / "main.jsonl", [{"at": iso(at if at is not None else self.clock - 600 + self.n), "event": event,
                                    "id": wid, "note": text}])
        return wid

    def deploy(self, who, sha="1a2b3c4d5e6f", at=None):
        return self.entry("deploy", f"DEPLOYED goodqa-web {sha} to production for {who}", at)

    def live(self, who, tid, target="https://app.goodqa.example/health", at=None):
        self.entry("check", f"REALLY_TESTED {tid}: {who} checked live at {target}: pass", at)
        return tid

    def ring(self):
        return ops_watch.read_ring(self.home / ".agent-harness" / "state" / "alerts.jsonl")

    def audit(self):
        return [json.loads(x) for x in (ah.store_dir(self.home) / "audit.jsonl").read_text().splitlines()]

    def owners(self):
        return ah.owners(self.home, SESSION, now=self.clock)

    def epoch(self, ts):
        p = self.home / ".agent-harness" / "state" / "dropped-gate" / "installed_at.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"at": iso(ts)}))


class ReplayOfTheLoop(Base):
    def test_nineteen_closes_with_one_reason_and_one_old_wal_id_are_all_refused(self):
        self.assertEqual(len(self.owners()["undisposed"]), self.N)
        codes = []
        for i in range(self.N):
            self.clock = NOW + i * 5  # the loop ran in seconds
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(agent(i), reason=LOOP_REASON, evidence=OLD_WAL_ID)
            codes.append(cm.exception.code)
        self.assertEqual(codes[:3], ["evidence"] * 3, codes)  # no deploy record, no live test, names none of them
        self.assertEqual(set(codes[3:]), {"bulk_close"}, codes)  # a 4th distinct owner inside 10 min is a bulk close
        self.assertEqual(len(self.owners()["undisposed"]), self.N)  # nothing was cleared
        bulk = [e for e in self.ring() if e.get("key", "").startswith("bulk-close:")]
        self.assertTrue(bulk and bulk[-1]["severity"] == "high" and bulk[-1]["event"] == "raise", bulk)
        self.assertIn("possible bulk-close", bulk[-1]["message"])
        refused = [a for a in self.audit() if a.get("op") == "task.dispose" and a.get("result") == "rejected"]
        self.assertEqual(len(refused), self.N)  # every attempt is on the record, with its owner and kind
        self.assertTrue(all(a.get("kind") == "closed" and a.get("agent") for a in refused))


class DoneMeansLive(Base):
    N = 4
    REASON = "verified the {} deploy is serving and its health check passes live"

    def test_deploy_and_live_test_about_this_owner_close_it(self):
        a0 = agent(0)
        dep = self.deploy(a0)
        lt = self.live(a0, "LIVE-0")
        r = self.dispose(a0, reason=self.REASON.format(a0), deployed=dep, live_test=lt)
        self.assertEqual(r["result"], "applied")
        self.assertNotIn(a0, self.owners()["undisposed"])

    def test_merge_sha_or_a_plain_note_alone_is_not_done(self):
        a0 = agent(0)
        note = self.entry("result", f"{a0} merged in PR #9 at 1a2b3c4d5e6f")
        for extra in ({"evidence": "1a2b3c4d5e6f"}, {"evidence": note}, {"deployed": note, "live_test": "LIVE-X"},
                      {"deployed": "1a2b3c4d5e6f", "live_test": self.live(a0, "LIVE-1")}):
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(a0, reason=self.REASON.format(a0), **extra)
            self.assertIn(cm.exception.code, ("evidence", "bad_request"), extra)
        self.assertIn(a0, self.owners()["undisposed"])

    def test_live_test_must_hit_the_live_target_after_the_deploy(self):
        a0 = agent(0)
        dep = self.deploy(a0, at=self.clock - 300)
        early = self.live(a0, "LIVE-EARLY", at=self.clock - 400)  # before the deploy: tested something else
        local = self.live(a0, "LIVE-LOCAL", target="http://localhost:3000/health")
        for lt in (early, local, "LIVE-MISSING"):
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(a0, reason=self.REASON.format(a0), deployed=dep, live_test=lt)
            self.assertEqual(cm.exception.code, "evidence", lt)

    def test_a_note_that_says_it_was_not_live_is_refused(self):
        a0 = agent(0)
        dep = self.deploy(a0, at=self.clock - 300)
        notes = ("not live yet; {} checked the build at https://ci.goodqa.example/run/1: pass",
                 "{} checked on staging at https://staging.goodqa.example/health: pass",
                 "{} tested locally, will check production after the release: pass",
                 "{} verified pre-prod https://app.goodqa.example/health: pass")
        for i, text in enumerate(notes):
            self.entry("check", f"REALLY_TESTED NL-{i}: " + text.format(a0), at=self.clock - 100 + i)  # after the deploy
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(a0, reason=self.REASON.format(a0), deployed=dep, live_test=f"NL-{i}")
            self.assertEqual(cm.exception.code, "evidence", text)
        self.assertIn(a0, self.owners()["undisposed"])
        self.entry("check", f"REALLY_TESTED NL-OK: {a0} checked production at https://app.goodqa.example/health: pass",
                   at=self.clock - 50)  # the same deploy with a live run closes it: the refusals were about the wording
        self.assertEqual(self.dispose(a0, reason=self.REASON.format(a0), deployed=dep, live_test="NL-OK")["result"], "applied")

    def test_deploy_record_must_name_the_owner(self):
        a0, a1 = agent(0), agent(1)
        dep = self.deploy(a1)
        lt = self.live(a0, "LIVE-2")
        with self.assertRaises(ah.AhError) as cm:
            self.dispose(a0, reason=self.REASON.format(a0), deployed=dep, live_test=lt)
        self.assertEqual(cm.exception.code, "evidence")

    def test_shared_deploy_covers_only_owners_it_names_by_id(self):
        a0, a1, a2 = agent(0), agent(1), agent(2)
        dep = self.entry("deploy", f"DEPLOYED harness v3.4.0 1a2b3c4d5e6f to all hosts for {a0} and {a1}")
        lt = self.entry("check", f"REALLY_TESTED LIVE-S: {a0} and {a1} verified on the live hosts via https://dev2.example: pass") and "LIVE-S"
        self.dispose(a0, reason=self.REASON.format(a0), deployed=dep, live_test=lt)
        self.dispose(a1, reason=f"confirmed {a1} runs the v3.4.0 install and its live probe is green", deployed=dep, live_test=lt)
        tdep = self.entry("deploy", "DEPLOYED harness v3.4.1 abcdef1234 for GoodQA goodqa#14791")
        tlt = self.entry("check", "REALLY_TESTED LIVE-T: goodqa#14791 live check on https://dev2.example: pass") and "LIVE-T"
        reg = {"ok": True, "problems": []}
        with mock.patch("provenance.resolve", return_value=reg):
            for who in (a2, agent(3)):
                ah.write(self.home, "task.register", {"task": f"t-{who}", "owner_agent": who, "session": SESSION,
                                                      "ticket": "GoodQA goodqa#14791", "scope": "s", "source": "ticket:GoodQA goodqa#14791"}, SESSION)
        self.clock += 700
        self.dispose(a2, reason=f"checked the v3.4.1 rollout carries the {a2} slice and passes live", deployed=tdep, live_test=tlt)
        with self.assertRaises(ah.AhError) as cm:  # names only the shared ticket: one owner, not every owner of the ticket
            self.dispose(agent(3), reason="confirmed the fourth slice rides the same rollout and is healthy", deployed=tdep,
                         live_test=tlt)
        self.assertEqual(cm.exception.code, "evidence_reused")


class DeployedShaCoversTheBranch(Base):
    N = 2

    def git(self, *a, cwd):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@x", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run(["git", *a], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()

    def test_a_registered_owner_needs_a_deployed_sha_that_contains_its_branch(self):
        repo = self.home / "repo"
        repo.mkdir()
        self.git("init", "-q", "-b", "main", cwd=repo)
        (repo / "f").write_text("0")
        self.git("add", "f", cwd=repo)
        self.git("commit", "-q", "-m", "base", cwd=repo)
        base = self.git("rev-parse", "HEAD", cwd=repo)
        self.git("checkout", "-q", "-b", "b0", cwd=repo)
        (repo / "g").write_text("1")
        self.git("add", "g", cwd=repo)
        self.git("commit", "-q", "-m", "work", cwd=repo)
        self.git("checkout", "-q", "main", cwd=repo)
        self.git("merge", "-q", "--no-ff", "-m", "m", "b0", cwd=repo)
        merged = self.git("rev-parse", "HEAD", cwd=repo)
        a0 = agent(0)
        with mock.patch("provenance.resolve", return_value={"ok": True, "problems": []}):
            ah.write(self.home, "task.register", {"task": "t0", "owner_agent": a0, "session": SESSION, "ticket": "GoodQA goodqa#7",
                                                  "scope": "s", "source": "ticket:GoodQA goodqa#7", "branch": "b0",
                                                  "worktree": str(repo)}, SESSION)
        stale = self.deploy(a0, sha=base)  # what is live predates the owner's work
        lt = self.live(a0, "LIVE-B")
        with self.assertRaises(ah.AhError) as cm:
            self.dispose(a0, reason="verified the production build serves the b0 change correctly", deployed=stale, live_test=lt)
        self.assertEqual(cm.exception.code, "evidence")
        good = self.deploy(a0, sha=merged[:12])
        lt2 = self.live(a0, "LIVE-C")
        r = self.dispose(a0, reason="verified the production build serves the b0 change correctly", deployed=good, live_test=lt2)
        self.assertEqual(r["result"], "applied")


class SupersededAndWontdo(Base):
    N = 3

    def test_need_an_existing_ticket_and_never_count_as_done(self):
        a0, a1, a2 = agent(0), agent(1), agent(2)
        with self.assertRaises(ah.AhError):  # no ticket
            self.dispose(a0, kind="superseded", reason="replaced by the S3 slice which owns the same scope")
        with mock.patch.object(ah, "_ticket_exists", return_value=False):
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(a0, kind="superseded", ref="GoodQA goodqa#99999999",
                             reason="replaced by the S3 slice which owns the same scope")
            self.assertEqual(cm.exception.code, "evidence")
        with mock.patch.object(ah, "_ticket_exists", return_value=None):  # cannot confirm: no closure
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(a0, kind="superseded", ref="GoodQA goodqa#14791",
                             reason="replaced by the S3 slice which owns the same scope")
            self.assertEqual(cm.exception.code, "evidence_unverifiable")
        with mock.patch.object(ah, "_ticket_exists", return_value=True):
            self.dispose(a0, kind="superseded", ref="GoodQA goodqa#14791",
                         reason="replaced by the S3 slice which owns the same scope")
            self.dispose(a1, kind="wontdo", ref="GoodQA goodqa#14800",
                         reason="the user dropped the console export feature from the plan")
            with self.assertRaises(ah.AhError) as cm:  # a template is still a template
                self.dispose(a2, kind="wontdo", ref="GoodQA goodqa#14801",
                             reason="the user dropped the console export feature from the plan")
            self.assertEqual(cm.exception.code, "reason")
        doc = self.owners()
        states = {o["agent_id"]: o["state"] for o in doc["owners"]}
        self.assertEqual((states[a0], states[a1]), ("superseded", "wontdo"))
        self.assertNotIn(a0, doc["undisposed"])
        self.assertNotIn("done", (states[a0], states[a1]))
        self.assertEqual(doc["counts"].get("done", 0), 0)


class TaskDoneNeedsLive(Base):
    N = 1

    def register(self):
        with mock.patch("provenance.resolve", return_value={"ok": True, "problems": []}):
            ah.write(self.home, "task.register", {"task": "t-live", "owner_agent": agent(0), "session": SESSION,
                                                  "ticket": "GoodQA goodqa#7", "scope": "s", "source": "ticket:GoodQA goodqa#7"}, SESSION)

    def test_task_done_refuses_tests_without_a_deploy_and_tests_that_are_not_live(self):
        self.register()
        self.clock += 60
        wal = str(self.w / "main.jsonl")
        local = self.live("t-live", "T-LOCAL", target="http://127.0.0.1:8000", at=self.clock + 1)  # after registration
        with self.assertRaises(ah.AhError) as cm:  # a passing test with nothing deployed is not done
            ah.write(self.home, "task.done", {"task": "t-live", "evidence": [{"really_tested": local, "wal": wal}]}, SESSION)
        self.assertEqual(cm.exception.code, "evidence")
        dep = self.deploy("t-live", at=self.clock + 2)
        with self.assertRaises(ah.AhError) as cm:  # deployed, but tested only locally
            ah.write(self.home, "task.done", {"task": "t-live", "evidence": [{"deployed": dep}, {"really_tested": local, "wal": wal}]},
                     SESSION)
        self.assertEqual(cm.exception.code, "evidence")
        lt = self.live("t-live", "T-LIVE", at=self.clock + 3)
        r = ah.write(self.home, "task.done", {"task": "t-live", "evidence": [{"deployed": dep}, {"really_tested": lt, "wal": wal}]},
                     SESSION)
        self.assertEqual(r["result"], "applied")


class Legacy(Base):
    N = 3

    def test_legacy_only_before_the_gate_epoch_stays_visible_and_unverified(self):
        a0 = agent(0)
        with self.assertRaises(ah.AhError) as cm:  # no install marker: the epoch is unknown, so no legacy
            self.dispose(a0, kind="legacy")
        self.assertEqual(cm.exception.code, "legacy")
        self.epoch(NOW - 26000)  # installed before these owners' last activity (NOW - 25000)
        with self.assertRaises(ah.AhError) as cm:
            self.dispose(a0, kind="legacy")
        self.assertEqual(cm.exception.code, "legacy")
        self.epoch(NOW - 1000)
        r = self.dispose(a0, kind="legacy")
        self.assertEqual(r["result"], "applied")
        doc = self.owners()
        self.assertNotIn(a0, doc["undisposed"])  # it no longer blocks the gate
        self.assertIn(a0, doc["legacy_unverified"])  # but it is listed until someone follows up
        row = next(o for o in doc["owners"] if o["agent_id"] == a0)
        self.assertEqual(row["state"], "unverified-legacy")
        self.assertIn("unverified-legacy", row["flags"])
        self.assertEqual(doc["counts"].get("done", 0), 0)
        self.epoch(NOW + 99999)  # moving the marker later cannot widen legacy: the first epoch ah used is pinned
        jl(self.w / f"agent-{agent(1)}.jsonl", [{"at": iso(NOW - 500), "event": "intent", "note": "late"}])
        with self.assertRaises(ah.AhError) as cm:
            self.dispose(agent(1), kind="legacy")
        self.assertEqual(cm.exception.code, "legacy")
        with mock.patch.object(ah, "_ticket_exists", return_value=True):  # the follow-up audit row
            self.dispose(a0, kind="superseded", ref="GoodQA goodqa#14791",
                         reason="audited the legacy owner: the S3 slice replaced its scope entirely")
        doc = self.owners()
        self.assertNotIn(a0, doc["legacy_unverified"])

    def test_a_sub_agent_cannot_legacy_itself(self):
        self.epoch(NOW - 1000)
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": agent(0)}):  # the owner, by its declared id
            with self.assertRaises(ah.AhError) as cm:
                self.dispose(agent(0), kind="legacy")
        self.assertEqual(cm.exception.code, "forbidden")
        for kind in ("legacy", "superseded", "wontdo"):
            out = dropped_gate.cmd_pretool({"tool_name": "Bash", "agent_id": agent(1), "tool_input": {
                "command": f"ah task dispose --agent {agent(0)} --kind {kind} --ref 'GoodQA goodqa#1'"}})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", kind)


class Grandfather(Base):
    N = 4

    def test_stop_gate_records_pre_gate_owners_as_legacy_once_and_still_blocks_on_new_drops(self):
        self.epoch(NOW - 20000)  # after the others went quiet (NOW - 25000)
        late = agent(3)  # stopped without a handoff after the gate was installed: still a real drop
        jl(self.w / f"agent-{late}.jsonl", [{"at": iso(NOW - 3700), "event": "intent", "note": "late work"}])
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3600), "event": "subagent_stop", "agent_id": late, "agent_type": "task-owner"}])
        out = dropped_gate.cmd_stop({"session_id": SESSION, "hook_event_name": "Stop"}, now=self.clock)
        self.assertEqual(out.get("decision"), "block")
        self.assertIn(late, out.get("reason", ""))
        for i in range(3):
            self.assertNotIn(agent(i), out.get("reason", ""))
        doc = self.owners()
        self.assertEqual(sorted(doc["legacy_unverified"]), sorted(agent(i) for i in range(3)))
        self.assertEqual(doc["undisposed"], [late])
        self.assertEqual(sum(1 for a in self.audit() if a.get("kind") == "legacy" and a.get("result") == "applied"), 3)
        dropped_gate.cmd_stop({"session_id": SESSION, "hook_event_name": "Stop"}, now=self.clock)
        self.assertEqual(sum(1 for a in self.audit() if a.get("kind") == "legacy" and a.get("result") == "applied"), 3)  # once

    def test_grandfathering_many_owners_reads_the_owner_view_a_bounded_number_of_times(self):
        self.epoch(NOW - 20000)  # all four went quiet before it
        with mock.patch.object(ah, "owners", wraps=ah.owners) as spy:
            dropped_gate.cmd_stop({"session_id": SESSION, "hook_event_name": "Stop"}, now=self.clock)
        self.assertEqual(len(self.owners()["legacy_unverified"]), self.N)
        self.assertLessEqual(spy.call_count, 3, spy.call_count)  # one per owner risks the 15 s Stop timeout at 50 owners

    def test_a_cached_view_never_grandfathers_an_owner_that_has_since_woken(self):
        self.epoch(NOW - 20000)
        a0 = agent(0)
        ah._dispose_preflight(self.home, {"agent": agent(1), "session": SESSION, "kind": "legacy", "at": iso(self.clock)})
        p = self.w / f"agent-{a0}.jsonl"
        jl(p, [{"at": iso(self.clock - 5), "event": "intent", "note": "resumed and working again"}])
        with self.assertRaises(ah.AhError) as cm:  # the view cached a moment ago still shows a0 quiet since NOW - 25000
            ah._dispose_preflight(self.home, {"agent": a0, "session": SESSION, "kind": "legacy", "at": iso(self.clock)})
        self.assertEqual(cm.exception.code, "legacy")

    def test_no_marker_means_no_grandfather(self):
        out = dropped_gate.cmd_stop({"session_id": SESSION, "hook_event_name": "Stop"}, now=self.clock)
        self.assertEqual(out.get("decision"), "block")
        self.assertEqual(self.owners()["legacy_unverified"], [])


class ReassignedToAReturnedParent(Base):
    N = 2

    def test_a_returned_replacement_with_live_children_keeps_the_reassignment_live(self):
        """Main's finding: a4720127 had returned while 7 reviewer children did the work; the reassignment to it still
        flagged as DROPPED."""
        a0, parent = agent(0), "a4720127aaaabbbbc"
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3000), "event": "subagent", "agent_id": parent, "agent_type": "task-owner"},
                                   {"at": iso(NOW - 2000), "event": "subagent_stop", "agent_id": parent, "agent_type": "task-owner"}])
        jl(self.w / f"agent-{parent}.jsonl", [{"at": iso(NOW - 2100), "event": "handoff", "note": "returned to main; reviewers running"}])
        self.dispose(a0, kind="reassigned", ref=parent)
        self.assertIn(a0, self.owners()["undisposed"])  # the parent returned and nothing of it runs: not live
        child = "a4720127child0001"
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 1000), "event": "subagent", "agent_id": child, "agent_type": "red-team"}])
        jl(self.w / f"agent-{child}.jsonl", [{"at": iso(NOW - 20), "event": "intent", "note": "reviewing"}])
        with mock.patch.object(ah, "discover_agents", return_value={child: {"type": "red-team", "parent": parent}}):
            doc = self.owners()
        self.assertNotIn(a0, doc["undisposed"])  # a live child keeps its returned parent live for the reassignment


class S3ReviewFindings(Base):
    """PR review of 24a786c (Opus high, run 817deffc; goodqa#14791). F1: a reassignment onto a closed, legacy, superseded
    or wontdo owner was excused for good, with none of the dispose guard's checks, so a loop of reassignments onto one
    legacy owner cleared every drop. F3: a stale child (idle-helper, SILENT) kept its returned parent live."""
    N = 19

    def test_f1_reassign_loop_onto_a_legacy_owner_clears_nothing(self):
        self.epoch(NOW - 1000)
        self.dispose(agent(0), kind="legacy")
        for i in range(1, self.N):
            self.clock = NOW + i * 5  # the loop shape: seconds apart, one target
            self.dispose(agent(i), kind="reassigned", ref=agent(0))
        doc = self.owners()
        self.assertNotIn(agent(0), doc["undisposed"])  # the legacy owner itself stays excused (and listed)
        self.assertEqual(sorted(doc["undisposed"]), sorted(agent(i) for i in range(1, self.N)))

    def test_f1_superseded_wontdo_and_closed_targets_do_not_cover(self):
        with mock.patch.object(ah, "_ticket_exists", return_value=True):
            self.dispose(agent(0), kind="superseded", ref="GoodQA goodqa#14791",
                         reason="replaced by the S3 slice which owns the same scope")
            self.dispose(agent(1), kind="wontdo", ref="GoodQA goodqa#14800",
                         reason="the user dropped the console export feature from the plan")
        dep = self.deploy(agent(2))
        lt = self.live(agent(2), "LIVE-A2")
        self.dispose(agent(2), deployed=dep, live_test=lt, reason=f"{agent(2)} shipped slice two; production health passed")
        for i, target in ((3, agent(0)), (4, agent(1)), (5, agent(2))):
            self.clock += 5
            self.dispose(agent(i), kind="reassigned", ref=target)
        undisposed = self.owners()["undisposed"]
        for i in (3, 4, 5):
            self.assertIn(agent(i), undisposed)
        for i in (0, 1, 2):
            self.assertNotIn(agent(i), undisposed)

    def test_f1_neg_reassign_onto_a_live_owner_still_covers(self):
        jl(self.w / f"agent-{agent(0)}.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": "working again"}])
        self.dispose(agent(1), kind="reassigned", ref=agent(0))
        self.assertNotIn(agent(1), self.owners()["undisposed"])

    def _returned_parent_with_child(self, child_last):
        a0, parent, child = agent(0), "a4720127aaaabbbbc", "a4720127child0001"
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 9000), "event": "subagent", "agent_id": parent, "agent_type": "task-owner"},
                                   {"at": iso(NOW - 2000), "event": "subagent_stop", "agent_id": parent, "agent_type": "task-owner"},
                                   {"at": iso(NOW - 8000), "event": "subagent", "agent_id": child, "agent_type": "red-team"}])
        jl(self.w / f"agent-{parent}.jsonl", [{"at": iso(NOW - 2100), "event": "handoff", "note": "returned to main"}])
        jl(self.w / f"agent-{child}.jsonl", [{"at": iso(child_last), "event": "intent", "note": "reviewing"}])
        self.dispose(a0, kind="reassigned", ref=parent)
        with mock.patch.object(ah, "discover_agents", return_value={child: {"type": "red-team", "parent": parent}}):
            doc = self.owners()
        return doc, a0, child

    def test_f3_a_stale_child_does_not_keep_its_returned_parent_live(self):
        doc, a0, child = self._returned_parent_with_child(NOW - 7000)  # crashed, no subagent_stop, quiet for ~2 h
        state = next(o["state"] for o in doc["owners"] if o["agent_id"] == child)
        self.assertNotEqual(state, "live")  # the fixture really is a stale child
        self.assertIn(a0, doc["undisposed"])

    def test_f3_neg_a_live_child_still_keeps_its_parent_live(self):
        doc, a0, _child = self._returned_parent_with_child(NOW - 20)
        self.assertNotIn(a0, doc["undisposed"])


class InstallMarker(unittest.TestCase):
    def test_marker_is_written_once_with_the_earlier_install_time(self):
        import importlib
        sys.path.insert(0, str(ROOT))
        install = importlib.import_module("install")
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            install.record_gate_epoch(home, prior_mtime=NOW - 5000, now=NOW)
            p = home / ".agent-harness" / "state" / "dropped-gate" / "installed_at.json"
            self.assertEqual(ah.parse_ts(json.loads(p.read_text())["at"]), NOW - 5000)
            install.record_gate_epoch(home, prior_mtime=None, now=NOW + 999)  # never moved by a later install
            self.assertEqual(ah.parse_ts(json.loads(p.read_text())["at"]), NOW - 5000)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
