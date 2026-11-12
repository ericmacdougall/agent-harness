"""The "Needs you" sweeper (GoodQA #15585, spec rev 3: AC-11..AC-15, NEG-24..NEG-31). It hides settled asks with an
audit row, moves stale ones to their own section, flags untraceable ones, and never resolves anything."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import mc_chat  # noqa: E402
import needs_sweep as ns  # noqa: E402

SID = "baab765b-d85c-46b4-b7b9-588eb912c770"
NOW = 1_800_000_000.0


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def ask(ident, note="Ship the redesign behind a flag? (demo#101)", age_h=1.0, owner="main", **extra):
    return {"id": ident, "kind": "traced", "at": iso(NOW - age_h * 3600), "note": note, "reason": "why",
            "owner": owner, **extra}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-sweep-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "mc"
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        mc_chat.ensure_dirs()

    def sweep(self, items=(), resolved=(), blocked=(), **kw):
        data = {"items": list(items), "resolved": list(resolved), "blocked": list(blocked)}
        return ns.sweep(self.root, SID, data, now=kw.pop("now", NOW), **kw)

    def audit(self):
        path = self.root / "needs" / "audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class Settled(Base):
    def test_a_resolved_ask_is_cleared_once_with_its_evidence(self):  # AC-11
        first = self.sweep([ask("wopen0000001")])
        self.assertEqual(first["status"]["wopen0000001"]["state"], "active")
        done = {"id": "wopen0000001", "note": "Ship?", "owner": "main", "resolved_at": iso(NOW), "resolved_by": "wres00000001",
                "decision": "approved"}
        view = self.sweep([], [done], now=NOW + 300)
        self.assertEqual([c["id"] for c in view["cleared"]], ["wopen0000001"])
        self.assertEqual((view["cleared"][0]["reason"], view["cleared"][0]["evidence"]), ("resolved", "wal:wres00000001"))
        self.sweep([], [done], now=NOW + 600)  # idempotent: no second row
        rows = [r for r in self.audit() if r["action"] == "cleared"]
        self.assertEqual([(r["ask_id"], r["reason"], r["evidence"]) for r in rows],
                         [("wopen0000001", "resolved", "wal:wres00000001")])

    def test_closed_ticket_hides_the_ask_and_an_open_or_unknown_one_does_not(self):  # AC-11, NEG-26
        lookups = []

        def status(ref):
            lookups.append(ref)
            return {"demo#101": "closed", "demo#102": "open"}.get(ref)  # demo#103: lookup failed -> None

        items = [ask("wticket00001", "[ticket:demo#101] Ship the redesign behind a flag?"),
                 ask("wticket00002", "[ticket:demo#102] Keep the window?"),
                 ask("wticket00003", "[ticket:demo#103] Other?")]
        view = self.sweep(items, ticket_status=status)
        self.assertEqual(view["status"]["wticket00001"], {"state": "cleared", "reason": "ticket-closed",
                                                          "evidence": "ticket:demo#101"})
        self.assertEqual(view["status"]["wticket00002"]["state"], "active")
        self.assertEqual(view["status"]["wticket00003"]["state"], "active", "an unknown ticket state never hides an ask")
        self.sweep(items, ticket_status=status, now=NOW + 300)
        self.assertEqual(lookups.count("demo#101"), 1, "a closed ticket is remembered")

    def test_ticket_lookups_are_budgeted_per_sweep(self):  # NEG-30
        calls = []
        items = [ask(f"wbulk{i:07d}", f"[ticket:demo#{200 + i}] q{i}") for i in range(40)]
        self.sweep(items, ticket_status=lambda ref: calls.append(ref) or "open")
        self.assertLessEqual(len(calls), ns.TICKET_LOOKUPS_PER_SWEEP)

    def test_owner_gone_and_reassigned_hides_its_asks_only(self):  # AC-11, NEG-27
        owners = [{"agent_id": "a1b2c3", "state": "DROPPED", "disposition": {"kind": "reassigned", "live": True, "ref": "a9z"}},
                  {"agent_id": "d4e5f6", "state": "DROPPED", "disposition": None},
                  {"agent_id": "g7h8i9", "state": "working", "disposition": {"kind": "reassigned", "live": True}}]
        items = [ask("wowner000001", "q1", owner="agent-a1b2c3"), ask("wowner000002", "q2", owner="agent-d4e5f6"),
                 ask("wowner000003", "q3", owner="agent-g7h8i9"), ask("wowner000004", "q4")]
        view = self.sweep(items, owners=owners)
        self.assertEqual(view["status"]["wowner000001"],
                         {"state": "cleared", "reason": "owner-reassigned", "evidence": "owner:a1b2c3 reassigned a9z"})
        for ident in ("wowner000002", "wowner000003", "wowner000004"):
            self.assertEqual(view["status"][ident]["state"], "active", ident)

    def test_duplicates_keep_the_oldest(self):  # AC-11
        items = [ask("wdup00000002", "Same question?", age_h=1), ask("wdup00000001", "Same  question? ", age_h=5),
                 ask("wdup00000003", "Another question?")]
        view = self.sweep(items)
        self.assertEqual(view["status"]["wdup00000001"]["state"], "active")
        self.assertEqual(view["status"]["wdup00000002"], {"state": "cleared", "reason": "duplicate",
                                                          "evidence": "ask:wdup00000001"})
        self.assertEqual(view["status"]["wdup00000003"]["state"], "active")

    def test_a_duplicate_never_hides_the_only_copy_the_user_can_see_and_decide(self):  # NEG-32 (code review 1)
        # A re-ask of a question that went stale stays in view: the stale original cannot absorb it.
        view = self.sweep([ask("wold00000001", "Still want this?", age_h=96), ask("wnew00000001", "Still want this?", age_h=1)])
        self.assertEqual((view["status"]["wold00000001"]["state"], view["status"]["wnew00000001"]["state"]), ("stale", "active"))
        # An owner's earlier look-alike (a decoy, or a relayed question) never clears main's ask, nor the reverse.
        view = self.sweep([ask("wdecoy000001", "Deploy to prod?", age_h=5, owner="agent-evil01"),
                           ask("wreal0000001", "Deploy to prod?", age_h=1)])
        self.assertEqual((view["status"]["wdecoy000001"]["state"], view["status"]["wreal0000001"]["state"]), ("active", "active"))
        self.assertEqual(view["cleared"], [])

    def test_only_the_asks_own_ticket_tag_counts_and_a_mention_does_not(self):  # NEG-33 (code review 1)
        items = [ask("wmention0001", "goodqa#14000 was closed by mistake; may I reopen it and redeploy?"),
                 ask("wmention0002", "Ship it? (demo#101)"),
                 # relayed text that quotes someone else's tag: only a tag that opens the note is the ask's own
                 ask("wmention0003", "Owner asks: \"[ticket:demo#101] delete the bucket?\" Should I allow it?")]
        view = self.sweep(items, ticket_status=lambda ref: "closed")
        self.assertEqual([view["status"][i]["state"] for i in ("wmention0001", "wmention0002", "wmention0003")],
                         ["active", "active", "active"])

    def test_a_cleared_ask_comes_back_when_its_reason_ends(self):  # NEG-28
        items = [ask("wticket00001", "[ticket:demo#101] Ship?")]
        self.sweep(items, ticket_status=lambda ref: "closed")
        still = self.sweep(items, ticket_status=lambda ref: "open", now=NOW + 300)
        self.assertEqual(still["status"]["wticket00001"]["state"], "cleared", "inside the recheck window")
        view = self.sweep(items, ticket_status=lambda ref: "open", now=NOW + ns.TICKET_RECHECK_S + 60)  # reopened
        self.assertEqual(view["status"]["wticket00001"]["state"], "active")
        self.assertEqual([r["action"] for r in self.audit()], ["cleared", "restored"])


class StaleAndFlagged(Base):
    def test_past_ttl_without_activity_moves_to_stale_and_is_never_hidden(self):  # AC-12, NEG-24
        items = [ask("wold00000001", "old", age_h=80), ask("wold00000002", "old but answered", age_h=80),
                 ask("wnew00000001", "new", age_h=2)]
        view = self.sweep(items, activity={"wold00000002": NOW - 3600})
        self.assertEqual(view["status"]["wold00000001"]["state"], "stale")
        self.assertIn("no activity for 3 d", view["status"]["wold00000001"]["reason"])
        self.assertEqual(view["status"]["wold00000002"]["state"], "active")
        self.assertEqual(view["status"]["wnew00000001"]["state"], "active")
        self.assertEqual(view["cleared"], [])
        self.assertEqual([(r["action"], r["ask_id"]) for r in self.audit()], [("stale", "wold00000001")])

    def test_until_overrides_the_ttl_both_ways(self):
        items = [ask("wuntil000001", "short", age_h=1, until=iso(NOW - 60)),
                 ask("wuntil000002", "long", age_h=200, until=iso(NOW + 3600))]
        view = self.sweep(items)
        self.assertEqual(view["status"]["wuntil000001"]["state"], "stale")
        self.assertEqual(view["status"]["wuntil000002"]["state"], "active")

    def test_untraceable_asks_are_flagged_not_listed_as_valid(self):  # AC-13
        blocked = [{"id": "wbad00000001", "note": "Do the thing?", "owner": "main", "at": iso(NOW - 60),
                    "problem": "source rejected (message-not-found)"}]
        view = self.sweep([ask("wgood0000001")], blocked=blocked)
        self.assertEqual(view["status"]["wbad00000001"]["state"], "flagged")
        self.assertIn("message-not-found", view["status"]["wbad00000001"]["reason"])
        self.assertEqual([(r["action"], r["ask_id"]) for r in self.audit()], [("flagged", "wbad00000001")])


    def test_a_source_check_that_timed_out_is_not_called_untraceable(self):  # found live, 2026-11-11
        blocked = [{"id": "wslow0000001", "note": "Refund policy for packs?", "owner": "main", "at": iso(NOW - 60),
                    "problem": "scan-timeout: scan of session.jsonl exceeded 3s"},
                   {"id": "wslow0000002", "note": "Old and slow?", "owner": "main", "at": iso(NOW - 90 * 3600),
                    "problem": "internal: resolver error KeyError"}]
        view = self.sweep([], blocked=blocked)
        self.assertEqual(view["status"]["wslow0000001"]["state"], "active")
        self.assertEqual(view["status"]["wslow0000002"]["state"], "stale")
        self.assertEqual([r["action"] for r in self.audit()], ["stale"])

    def test_too_many_sources_stays_flagged_as_untraceable(self):  # r1 F1: a caller error, never "not checked"
        blocked = [{"id": "wmany0000001", "note": "Ship it?", "owner": "main", "at": iso(NOW - 60),
                    "problem": "too-many-sources: more than 40 sources to resolve"}]
        view = self.sweep([], blocked=blocked)
        self.assertEqual(view["status"]["wmany0000001"]["state"], "flagged")
        self.assertIn("too-many-sources", view["status"]["wmany0000001"]["reason"])
        self.assertFalse(ns.unchecked(blocked[0]))


class Safety(Base):
    def test_it_never_writes_a_wal_or_an_answer(self):  # AC-14, NEG-25
        wals = Path(self.tmp.name) / "wals" / SID
        wals.mkdir(parents=True)
        (wals / "main.jsonl").write_text(json.dumps({"event": "ask", "id": "wopen0000001", "note": "q"}) + "\n")
        before = (wals / "main.jsonl").read_bytes()
        with mock.patch.dict(os.environ, {"HOME": self.tmp.name}):
            self.sweep([ask("wopen0000001", "[ticket:demo#101] Ship?", age_h=500)], ticket_status=lambda ref: "closed")
        self.assertEqual((wals / "main.jsonl").read_bytes(), before)
        self.assertEqual(mc_chat.inbox(self.root), [])
        self.assertEqual(mc_chat.outbox(self.root), [])
        written = {p.relative_to(self.root).parts[0] for p in self.root.rglob("*") if p.is_file()}
        self.assertLessEqual(written, {"needs", "chat", "secret"})

    def test_two_sweeps_at_once_write_each_transition_once(self):  # AC-15
        items = [ask(f"wrace{i:07d}", f"q{i}", age_h=100) for i in range(30)]
        threads = [threading.Thread(target=self.sweep, args=(items,)) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        rows = self.audit()
        self.assertEqual(len(rows), 30)
        self.assertEqual(len({r["ask_id"] for r in rows}), 30)

    def test_two_processes_at_once(self):  # AC-15
        code = ("import sys,json;sys.path[:0]=[%r,%r];import needs_sweep as ns;from pathlib import Path;"
                "ns.sweep(Path(%r),%r,json.loads(sys.stdin.read()),now=%r)"
                % (str(REPO / "harness" / "hooks"), str(REPO / "harness" / "mission_control"), str(self.root), SID, NOW))
        data = json.dumps({"items": [ask(f"wproc{i:07d}", f"q{i}", age_h=100) for i in range(20)], "resolved": [], "blocked": []})
        procs = [subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, text=True, env=dict(os.environ))
                 for _ in range(4)]
        for proc in procs:
            proc.communicate(data)
        self.assertEqual([p.returncode for p in procs], [0, 0, 0, 0])
        self.assertEqual(len(self.audit()), 20)

    def test_heartbeat_and_bounded_files(self):  # AC-15, NEG-29
        self.sweep([ask("wopen0000001")])
        beat = json.loads((self.root / "needs" / "heartbeat.json").read_text())
        self.assertEqual((beat["at"], beat["session"], beat["active"]), (NOW, SID, 1))
        for name in ("heartbeat.json", "audit.jsonl", f"{SID}.json"):
            self.assertEqual((self.root / "needs" / name).stat().st_mode & 0o777, 0o600, name)
        self.assertEqual(ns.heartbeat_age(self.root, now=NOW + 42), 42)
        self.assertIsNone(ns.heartbeat_age(Path(self.tmp.name) / "nowhere"))

    def test_audit_text_is_redacted_and_ids_are_validated(self):  # NEG-31
        secret = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6"
        view = self.sweep([ask("../../etc/x", "bad id"), ask("wsecret00001", f"token {secret}?", age_h=100)])
        self.assertNotIn("../../etc/x", view["status"])
        self.assertNotIn(secret, (self.root / "needs" / "audit.jsonl").read_text())


class Collector(Base):
    """The asks collector publishes the swept view: active, stale, flagged and cleared-recently."""

    def collector(self, payload, owners=()):
        class Runner:
            calls = []

            def run(self, kind, *args, timeout=20.0, limit=0):
                self.calls.append(kind)
                if kind == "ah-ticket-get":
                    return 0, json.dumps({"issue": {"closedAt": "2026-11-11T00:00:00Z" if "101" in args[0] else None}})
                return 0, json.dumps(payload)
        hub = ev.Hub()
        asks = col.Asks(hub, col.Health(hub), Runner(), lambda: SID, root=self.root, owners_fn=lambda: list(owners))
        return asks

    def test_snapshot_sections(self):
        now = time.time()
        payload = {"items": [{"id": "wkeep0000001", "kind": "traced", "at": iso(now - 60), "note": "Keep? (demo#102)", "owner": "main"},
                             {"id": "wclosed00001", "kind": "traced", "at": iso(now - 60), "note": "[ticket:demo#101] Closed?", "owner": "main"},
                             {"id": "wstale000001", "kind": "traced", "at": iso(now - 90 * 3600), "note": "Old? (demo#102)", "owner": "main"}],
                   "blocked": [{"id": "wbad00000001", "note": "No source?", "owner": "main", "at": iso(now - 60), "problem": "no source"}],
                   "resolved": []}
        asks = self.collector(payload)
        asks.run(now)
        snap = asks.snapshot()
        self.assertEqual([a["id"] for a in snap["items"]], ["wkeep0000001"])
        self.assertEqual([a["id"] for a in snap["stale"]], ["wstale000001"])
        self.assertTrue(snap["stale"][0]["approvable"], "a stale ask can still be answered")
        self.assertEqual([(a["id"], a["approvable"]) for a in snap["flagged"]], [("wbad00000001", False)])
        self.assertEqual([(c["id"], c["reason"]) for c in snap["cleared"]], [("wclosed00001", "ticket-closed")])
        self.assertIsInstance(snap["swept_at"], str)

    def test_an_unchecked_ask_is_listed_as_an_ask_with_a_note(self):
        now = time.time()
        payload = {"items": [], "resolved": [], "blocked": [
            {"id": "wslow0000001", "note": "Refund policy for packs?", "owner": "main", "at": iso(now - 60),
             "problem": "scan-timeout: scan of session.jsonl exceeded 3s"}]}
        asks = self.collector(payload)
        asks.run(now)
        snap = asks.snapshot()
        self.assertEqual(snap["flagged"], [])
        # r1 F1: listed so the user sees it, but its source was never verified: answer by reply only
        self.assertEqual([(a["id"], a["approvable"], a["digest"]) for a in snap["items"]], [("wslow0000001", False, "")])
        self.assertIn("could not be checked", snap["items"][0]["unchecked"])
        self.assertIn("reply", snap["items"][0]["blocked"])

    def test_unchecked_asks_are_never_approvable(self):  # r1 F1: scan-timeout and internal, active or stale
        now = time.time()
        payload = {"items": [], "resolved": [], "blocked": [
            {"id": "wslow0000001", "note": "Refund policy?", "owner": "main", "at": iso(now - 60),
             "problem": "scan-timeout: scan of session.jsonl exceeded 3s"},
            {"id": "wint00000001", "note": "Delete bucket?", "owner": "main", "at": iso(now - 60),
             "problem": "internal: resolver error KeyError"},
            {"id": "wint00000002", "note": "Old one?", "owner": "main", "at": iso(now - 90 * 3600),
             "problem": "internal: resolver error KeyError"}]}
        asks = self.collector(payload)
        asks.run(now)
        snap = asks.snapshot()
        shown = {a["id"]: a for a in snap["items"] + snap["stale"]}
        self.assertEqual(sorted(shown), ["wint00000001", "wint00000002", "wslow0000001"])
        for ident, row in shown.items():
            with self.subTest(ident):
                self.assertEqual((row["approvable"], row["digest"]), (False, ""))
                self.assertTrue(row["blocked"])

    def test_too_many_sources_is_flagged_in_the_snapshot(self):  # r1 F1
        now = time.time()
        payload = {"items": [], "resolved": [], "blocked": [
            {"id": "wmany0000001", "note": "Ship it?", "owner": "main", "at": iso(now - 60),
             "problem": "too-many-sources: more than 40 sources to resolve"}]}
        asks = self.collector(payload)
        asks.run(now)
        snap = asks.snapshot()
        self.assertEqual(snap["items"], [])
        self.assertEqual([(a["id"], a["approvable"], a["digest"]) for a in snap["flagged"]], [("wmany0000001", False, "")])

    def test_ticket_shape_is_allowlisted(self):
        import safeio
        runner = safeio.Runner(python="/usr/bin/python3", ah="/h/hooks/ah.py")
        self.assertEqual(runner.argv("ah-ticket-get", "demo#101"),
                         ["/usr/bin/python3", "-I", "/h/hooks/ah.py", "ticket", "get", "demo#101"])
        with self.assertRaises(safeio.Refused):
            runner.argv("ah-ticket-get", "demo#101; rm -rf /")


class OpsWatch(Base):
    """A dead sweeper is an alert: ops_watch reads the heartbeat the sweep leaves."""

    def check(self, now):
        import ops_watch
        home = Path(self.tmp.name) / "home"
        cfg = ops_watch.load_config(home, host="testhost", overrides={})
        cfg["_home"] = str(home)
        return home, ops_watch.check_mc_sweeper(cfg, now), ops_watch

    def test_silent_when_never_installed_and_when_fresh_and_raises_when_old(self):
        home, alerts, ops_watch = self.check(NOW)
        self.assertEqual(alerts, [], "no heartbeat file: Mission Control is not installed here")
        ns.sweep(home / ".agent-harness" / "mission-control", SID, {"items": []}, now=NOW)
        self.assertEqual(self.check(NOW + 600)[1], [])
        late = self.check(NOW + ops_watch.MC_SWEEP_STALE_S + 60)[1]
        self.assertEqual([(a["key"], a["severity"]) for a in late], [("mc:needs-sweeper", "high")])
        self.assertIn("has not run for 16 min", late[0]["message"])
        self.assertIn("mission-control", ops_watch.DEFAULT_CHECKS)

    def test_unreadable_heartbeat_raises(self):
        home, _, ops_watch = self.check(NOW)
        folder = home / ".agent-harness" / "mission-control" / "needs"
        folder.mkdir(parents=True)
        (folder / "heartbeat.json").write_text("not json")
        self.assertEqual(len(self.check(NOW)[1]), 1)


if __name__ == "__main__":
    unittest.main()
