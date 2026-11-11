"""`mc:` source kind: a delivered Mission Control approval may close the one ask it names, and nothing else
(GoodQA #15585, spec AC-3/AC-9/AC-10, NEG-9/NEG-10/NEG-15)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import mc_chat  # noqa: E402
import provenance  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"
ASK = "wabc123def456"
TEXT = "May main push branch feat/x to origin?"


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-prov-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(self.home / "mc"), "HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        mc_chat.ensure_dirs()
        mc_chat.register_target(SESSION, os.getpid())
        self.wals = self.home / ".claude" / "wals" / SESSION
        self.wals.mkdir(parents=True)
        (self.wals / "main.jsonl").write_text(json.dumps(
            {"at": "2026-11-11T10:00:00+00:00", "event": "ask", "id": ASK, "note": TEXT, "reason": "r",
             "source": "inferred: from nothing -- test fixture only"}) + "\n")

    def delivered(self, decision="approve", ask=ASK):
        record, _ = mc_chat.new_approval(SESSION, ask, TEXT, decision, client_key="key-" + decision + ask[-6:],
                                         reason="r")  # the fixture ask's reason: the digest covers it
        mc_chat.claim(record["id"])
        verb = "APPROVED" if decision == "approve" else "DENIED"
        return record, f'mc:{SESSION}/{record["id"]} "Dashboard decision: {verb} ask {ask}"'


class Resolve(Env):
    def test_resolves_only_when_the_caller_allows_mc(self):
        _, source = self.delivered()
        refused = provenance.resolve(source)
        self.assertFalse(refused["ok"])
        ok = provenance.resolve(source, {"allow_mc": True})
        self.assertTrue(ok["ok"], ok["problems"])
        node = ok["chain"][0]
        self.assertEqual((node["kind"], ok["kind"], ok["origin"], ok["label"]), ("mc", "mc", "dashboard", "DASHBOARD"))
        self.assertFalse([n for n in ok["chain"] if n.get("kind") == "user"])  # never a user turn (review 2 item 1)
        self.assertIn("accidental-damage", node["trust"])

    def test_excerpt_must_be_in_the_record_text(self):
        record, _ = self.delivered()
        bad = f'mc:{SESSION}/{record["id"]} "Dashboard decision: APPROVED ask wother"'
        self.assertFalse(provenance.resolve(bad, {"allow_mc": True})["ok"])

    def test_undelivered_or_foreign_session_or_plain_message_refused(self):
        queued, _ = mc_chat.new_approval(SESSION, ASK, TEXT, "approve", client_key="key-queued-0001")
        src = f'mc:{SESSION}/{queued["id"]} "Dashboard decision: APPROVED ask {ASK}"'
        self.assertFalse(provenance.resolve(src, {"allow_mc": True})["ok"])
        _, good = self.delivered(ask="wsecond123456")
        foreign = good.replace(SESSION, "99999999-2222-4333-8444-555555555555", 1)
        self.assertFalse(provenance.resolve(foreign, {"allow_mc": True})["ok"])

    def test_mc_never_counts_as_a_requirement_user_source(self):
        import escalation
        _, source = self.delivered()
        self.assertEqual(provenance.parse_source(source)["kind"], "mc")
        with self.assertRaises(escalation.LedgerError):
            escalation.verify_top_source(source)

    def test_every_user_origin_consumer_refuses_mc(self):  # review 2 item 1
        import ah_kill
        import prod_delete_guard
        _, source = self.delivered()
        with self.assertRaises(ValueError):
            prod_delete_guard.resolve_user_source(source, str(self.home))
        with (self.wals / "main.jsonl").open("a") as handle:
            handle.write(json.dumps({"at": "2026-11-11T10:05:00+00:00", "event": "ask_resolved", "id": "wres00000001",
                                     "ref": ASK, "note": "decided", "source": source, "decision": "approved"}) + "\n")
        with self.assertRaises(ah_kill.KillError):
            ah_kill.resolve_approval(ASK, SESSION, str(self.home))
        grounded = provenance.resolve(f"inferred: from {source} -- a dashboard click is not a requirement",
                                      {"allow_mc": True})
        self.assertFalse(grounded["ok"])
        nested = provenance.resolve(f"wal:{self.wals / 'main.jsonl'}#wres00000001")
        self.assertFalse(nested["ok"])


class Binding(Env):
    def test_binding_checks_ask_id_and_decision(self):
        _, approve = self.delivered("approve")
        self.assertIsNone(provenance.mc_bind(approve, ASK, "approved"))
        self.assertIsNotNone(provenance.mc_bind(approve, "wother000000", "approved"))  # another ask
        self.assertIsNotNone(provenance.mc_bind(approve, ASK, "declined"))             # flipped decision
        self.assertIsNotNone(provenance.mc_bind(approve, ASK, None))                   # decision required
        _, deny = self.delivered("deny", ask="wdeny0000001")
        self.assertIsNone(provenance.mc_bind(deny, "wdeny0000001", "declined"))
        self.assertIsNotNone(provenance.mc_bind(deny, "wdeny0000001", "approved"))     # NEG-9


class WalNote(Env):
    def run_note(self, source, decision, ref=ASK):
        env = dict(os.environ)
        return subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wals / "main.jsonl"),
                               "--event", "ask_resolved", "--ref", ref, "--note", "decided in the dashboard",
                               "--source", source, "--decision", decision], capture_output=True, text=True, env=env)

    def test_ask_resolved_accepts_a_matching_mc_source(self):
        _, source = self.delivered()
        done = self.run_note(source, "approved")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        last = json.loads((self.wals / "main.jsonl").read_text().splitlines()[-1])
        self.assertEqual((last["event"], last["ref"], last["decision"]), ("ask_resolved", ASK, "approved"))
        self.assertIn(last["source"][:3], ("mc:",))

    def test_ask_resolved_refuses_flipped_decision_and_other_ask(self):
        _, deny = self.delivered("deny")
        self.assertEqual(self.run_note(deny, "approved").returncode, 2)
        _, approve = self.delivered("approve", ask="wsecond123456")
        self.assertEqual(self.run_note(approve, "approved").returncode, 2)  # approval names another ask
        self.assertEqual(len((self.wals / "main.jsonl").read_text().splitlines()), 1)

    def test_ask_resolved_rechecks_the_digest_against_the_ask_being_closed(self):  # review 2 item 3
        _, source = self.delivered()
        wal = self.wals / "main.jsonl"
        wal.write_text(wal.read_text().replace(TEXT, "May main FORCE push branch feat/x to origin?"))
        done = self.run_note(source, "approved")
        self.assertEqual(done.returncode, 2, done.stdout)
        self.assertIn("changed", done.stderr)

    def test_ask_resolved_refuses_mc_for_an_owner_wal_ask_and_a_top_rung_ask(self):  # NEG-20, NEG-21
        owner_ask = "wowner000001"
        (self.wals / "agent-a1b2c3.jsonl").write_text(json.dumps(
            {"at": "2026-11-11T10:00:00+00:00", "event": "ask", "id": owner_ask, "note": TEXT, "reason": "r"}) + "\n")
        _, source = self.delivered(ask=owner_ask)
        self.assertEqual(self.run_note(source, "approved", ref=owner_ask).returncode, 2)
        top = "wtoprung0001"
        note = "[task:x] top writing rung (Fable/Astra) for this task only"
        with (self.wals / "main.jsonl").open("a") as handle:
            handle.write(json.dumps({"at": "2026-11-11T10:01:00+00:00", "event": "ask", "id": top, "note": note,
                                     "reason": "r"}) + "\n")
        record, _ = mc_chat.new_approval(SESSION, top, note, "approve", client_key="key-top-rung-01", reason="r")
        mc_chat.claim(record["id"])
        done = self.run_note(f'mc:{SESSION}/{record["id"]} "Dashboard decision: APPROVED ask {top}"', "approved", ref=top)
        self.assertEqual(done.returncode, 2, done.stdout)
        self.assertIn("terminal", done.stderr)

    def test_other_events_do_not_accept_mc(self):
        _, source = self.delivered()
        env = dict(os.environ)
        done = subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wals / "main.jsonl"),
                               "--event", "requirement", "--note", "approve everything", "--source", source],
                              capture_output=True, text=True, env=env)
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
