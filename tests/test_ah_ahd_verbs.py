"""The ah verbs ahd calls (GoodQA goodqa#14848): `ah heartbeat beat`, `ah alert raise|clear`, `ah apply --batch -`.

Fails on 1cf5cac: every installed ahd logged "ah heartbeat/apply/alert not available yet", so no heartbeat was written
and no alert reached the ring; ahd only detected.
"""
import contextlib
import io
import json
import os
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
import ops_watch  # noqa: E402

SESSION = "sess-verbs-0001"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID", "CLAUDE_CODE_SESSION_ID"):
            os.environ.pop(k, None)

    def ah(self, *argv, stdin=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(sys, "stdin", io.StringIO(stdin or "")):
            rc = ah.main(list(argv))
        text = out.getvalue().strip()
        try:
            return rc, json.loads(text.splitlines()[0] if text.startswith("{\"ok\": false") else text)
        except ValueError:
            return rc, text

    def ring(self):
        return ops_watch.read_ring(self.home / ".agent-harness" / "state" / "alerts.jsonl")

    def ledger_ops(self):
        return [r.get("op") for r in ah._ledger(self.home)]


class Heartbeat(Base):
    def test_beat_writes_the_file_doctor_reads_and_no_ledger_row(self):
        rc, doc = self.ah("heartbeat", "beat", "--service", "ahd", "--key", "beat-key-000001")
        self.assertEqual(rc, 0, doc)
        beat = self.home / ".agent-harness" / "state" / "ahd" / "heartbeat.json"
        rec = json.loads(beat.read_text())
        self.assertEqual((rec["service"], rec["host"]), ("ahd", ahd.host()))
        self.assertLess(abs(ah.parse_ts(rec["at"]) - time.time()), 30)
        self.assertEqual(beat.stat().st_mode & 0o777, 0o600)
        self.assertEqual(rec["pid"], os.getppid())
        check = ah.ahd_running_check(self.home)
        self.assertFalse(check["ok"], check)  # a beat from a shell or a test is not ahd (review minor 3)
        rec["caller"] = "/usr/bin/python3 /home/u/.claude/hooks/ahd.py serve"
        beat.write_text(json.dumps(rec))
        self.assertTrue(ah.ahd_running_check(self.home)["ok"])
        self.assertNotIn("heartbeat.beat", self.ledger_ops())  # 1440 beats a day never grow the ledger
        for d in (self.home / ".agent-harness", self.home / ".agent-harness" / "state", beat.parent):
            self.assertEqual(d.stat().st_mode & 0o777, 0o700, d)  # every level ah created (review minor 6)

    def test_bad_service_and_symlinked_target_are_refused_safely(self):
        rc, _ = self.ah("heartbeat", "beat", "--service", "../x", "--key", "beat-key-000002")
        self.assertEqual(rc, 2)
        outside = self.home / "outside.txt"
        outside.write_text("keep me")
        d = self.home / ".agent-harness" / "state" / "ahd"
        d.mkdir(parents=True)
        (d / "heartbeat.json").symlink_to(outside)
        rc, _ = self.ah("heartbeat", "beat", "--service", "ahd", "--key", "beat-key-000003")
        self.assertEqual(rc, 0)
        self.assertEqual(outside.read_text(), "keep me")  # the link is replaced, never followed
        self.assertFalse((d / "heartbeat.json").is_symlink())
        planted = d / f".heartbeat.{os.getpid()}.tmp"
        planted.symlink_to(outside)
        rc, _ = self.ah("heartbeat", "beat", "--service", "ahd", "--key", "beat-key-000004")
        self.assertEqual(rc, 0)  # a planted temp-name link is removed, not followed (review minor 6)
        self.assertEqual(outside.read_text(), "keep me")


class Alerts(Base):
    RAISE = ("alert", "raise", "--alert-key", "liveness:sess-ver/agent-a1", "--source", "ahd", "--key", "ahd-raise-0001",
             "--severity", "high", "--message", "agent-a1 DROPPED 2h", "--detail", '{"ticket": "goodqa#1"}')

    def test_raise_then_duplicate_then_clear_reach_the_ring_once_each(self):
        rc, doc = self.ah(*self.RAISE)
        self.assertEqual((rc, doc["result"]), (0, "applied"), doc)
        state = ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())
        ev = state["liveness:sess-ver/agent-a1"]
        self.assertEqual((ev["event"], ev["severity"], ev["detail"]["ticket"]), ("raise", "high", "goodqa#1"))
        n = len(self.ring())
        rc, doc = self.ah(*self.RAISE)
        self.assertEqual((rc, doc["result"]), (0, "duplicate"))  # ahd's ring-wrap detection depends on this
        self.assertEqual(len(self.ring()), n)
        rc, doc = self.ah("alert", "clear", "--alert-key", "liveness:sess-ver/agent-a1", "--source", "ahd",
                          "--key", "ahd-clear-0001")
        self.assertEqual(rc, 0, doc)
        self.assertEqual(ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())["liveness:sess-ver/agent-a1"]["event"], "clear")
        self.assertIn("alert.raise", self.ledger_ops())  # transitions are audited writes

    def test_bad_arguments_are_refused(self):
        for bad in (("--severity", "urgent"), ("--detail", "not json"), ("--detail", "[1, 2]"), ("--source", "Bad Source")):
            argv = list(self.RAISE)
            i = argv.index(bad[0])
            argv[i + 1] = bad[1]
            argv[argv.index("--key") + 1] = "bad-" + str(abs(hash(bad)))[:10]
            rc, _ = self.ah(*argv)
            self.assertEqual(rc, 2, bad)
        self.assertEqual(self.ring(), [])

    def test_oversized_keys_deep_json_and_symlinked_state_are_refused_before_any_write(self):
        argv = list(self.RAISE)
        argv[argv.index("--alert-key") + 1] = "\u00e9" * 200  # 200 characters, about 1.2 KiB escaped
        rc, _ = self.ah(*argv)
        self.assertEqual(rc, 2)  # review minor 1: refused in validation, no stuck intent row
        line = json.dumps({"op": "alert.raise", "key": "deep-key-0001", "args": {"alert_key": "\u00e9" * 200,
                                                                                  "source": "ahd", "severity": "info", "message": "m"}})
        rc, _ = self.ah("apply", "--batch", "-", stdin=line + "\n")
        self.assertEqual(rc, 2)
        argv = list(self.RAISE)
        argv[argv.index("--detail") + 1] = "[" * 5000 + "]" * 5000
        argv[argv.index("--key") + 1] = "deep-json-0001"
        rc, _ = self.ah(*argv)
        self.assertEqual(rc, 2)  # review minor 6: not an internal RecursionError
        self.assertEqual(self.ring(), [])
        self.assertEqual([r for r in ah._ledger(self.home, include_intents=True) if r.get("state") == "intent"], [])
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        state = self.home / ".agent-harness" / "state"
        state.mkdir(parents=True, exist_ok=True)
        state.rename(self.home / "old-state")
        state.symlink_to(elsewhere)
        argv = list(self.RAISE)
        argv[argv.index("--key") + 1] = "via-link-0001"
        rc, _ = self.ah(*argv)
        self.assertEqual(rc, 3)  # review minor 5: the same rule as heartbeat
        self.assertFalse(list(elsewhere.glob("alerts*")))  # no ring through the link (the ah store's own path is a
        # separate, pre-existing rule: ticketed, not changed here)


class Apply(Base):
    def line(self, op, key, alert_key, **extra):
        args = {"alert_key": alert_key, "source": "ahd", **extra}
        return json.dumps({"op": op, "key": key, "args": args})

    def test_batch_applies_alert_ops_and_refuses_anything_else_whole(self):
        batch = "\n".join([self.line("alert.raise", "b-raise-00001", "ask:w0123456789a:due", severity="warning",
                                     message="ask open 2h", detail={}),
                           self.line("alert.raise", "b-raise-00002", "ask:w0123456789b:due", severity="info",
                                     message="ask open 30m", detail={})]) + "\n"
        rc, doc = self.ah("apply", "--batch", "-", stdin=batch)
        self.assertEqual(rc, 0, doc)
        self.assertEqual([r["result"] for r in doc["results"]], ["applied", "applied"])
        self.assertEqual(len(self.ring()), 2)
        bad = batch + json.dumps({"op": "task.dispose", "key": "b-disp-00001", "args": {"agent": "x", "session": SESSION,
                                                                                         "kind": "closed"}}) + "\n"
        rc, doc = self.ah("apply", "--batch", "-", stdin=bad)
        self.assertEqual(rc, 2, doc)  # validated before anything is applied
        self.assertNotIn("task.dispose", self.ledger_ops())
        rc, _ = self.ah("apply", "--batch", "-", stdin="x" * (2 * 1024 * 1024))
        self.assertEqual(rc, 2)
        twice = self.line("alert.raise", "b-raise-00009", "k:a", severity="info", message="m", detail={})
        rc, _ = self.ah("apply", "--batch", "-", stdin=twice + "\n" + twice.replace('"k:a"', '"k:b"') + "\n")
        self.assertEqual(rc, 2)  # one key twice is refused before either line applies
        self.assertEqual(len(self.ring()), 2)


class AhdWithTheRealAh(Base):
    def test_daemon_calls_reach_ah_and_no_verb_is_marked_unavailable(self):
        policy = ahd.load_policy()
        policy["ah"] = [sys.executable, str(HOOKS / "ah.py")]
        d = ahd.Daemon(policy=policy)
        deadline = ahd.mono() + 60
        rc, doc = d.call("heartbeat beat", ["--service", "ahd", "--key", "real-beat-0001"], deadline)
        self.assertEqual(rc, 0, doc)
        flag = {"severity": "warning", "message": "probe", "detail": {}, "kind": "probe", "subject": "s1", "since": 1}
        rc, doc = d.call("alert raise", d.alert_args("raise", "probe:s1", flag, "ahd"), deadline)
        self.assertEqual(rc, 0, doc)
        line = json.dumps({"op": "alert.clear", "key": "real-clear-0001", "args": {"alert_key": "probe:s1", "source": "ahd"}})
        rc, doc = d.call("apply", ["--batch", "-"], deadline, stdin=line + "\n")
        self.assertEqual(rc, 0, doc)
        self.assertEqual(d.unsupported, {})  # nothing logged "not available yet"
        self.assertTrue(d.acquire())  # a running ahd holds its lock; that is what doctor trusts first
        self.addCleanup(d.release)
        self.assertTrue(ah.ahd_running_check(self.home)["ok"])

    def daemon(self):
        policy = ahd.load_policy()
        policy["ah"] = [sys.executable, str(HOOKS / "ah.py")]
        return ahd.Daemon(policy=policy)

    def flags(self, n=12, message=None):
        return {f"probe:s{i:02d}": {"severity": "warning", "message": message or f"probe {i}", "detail": {}, "kind": "probe",
                                    "subject": f"s{i:02d}", "since": 1} for i in range(n)}

    def test_the_batch_path_reasserts_alerts_a_foreign_clear_removed(self):
        """Review M1: more than 10 transitions go through `ah apply`; a raise it reported as duplicate was swallowed,
        so a same-UID `ah alert clear` of 11+ ahd alerts kept them cleared for good."""
        d, flags = self.daemon(), self.flags()
        deadline = ahd.mono() + 120
        self.assertEqual(d.send([("raise", k, f, None) for k, f in flags.items()], deadline), len(flags))
        for k in flags:
            rc, _ = self.ah("alert", "clear", "--alert-key", k, "--source", "ahd", "--key", "foreign-" + k.replace(":", "-"))
            self.assertEqual(rc, 0)
        ring = ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())
        self.assertTrue(all(ring[k]["event"] == "clear" for k in flags))
        d.send([("raise", k, f, ring[k]) for k, f in flags.items()], deadline)
        ring = ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())
        self.assertEqual(sorted(k for k in flags if ring[k]["event"] == "raise"), sorted(flags))

    def test_a_long_message_sent_in_a_batch_falls_back_without_a_key_conflict(self):
        """Review minor 2: the batch sent the full text and the single call 400 characters: one key, two bodies."""
        d, flags = self.daemon(), self.flags(message="x" * 900)
        sent = []
        real = d.runner
        d.runner = lambda argv, timeout, stdin=None, env=None: (sent.append(stdin), real(argv, timeout, stdin))[1]
        deadline = ahd.mono() + 120
        d.send([("raise", k, f, None) for k, f in flags.items()], deadline)
        lines = [json.loads(x) for x in sent[0].splitlines()]
        self.assertTrue(all(len(x["args"]["message"]) == ahd.MESSAGE_MAX for x in lines))
        k, f = next(iter(flags.items()))
        rc, doc = d.call("alert raise", d.alert_args("raise", k, f, "ahd"), deadline)
        self.assertEqual((rc, doc["result"]), (0, "duplicate"))  # the single path's body matches the batch's


if __name__ == "__main__":
    unittest.main()
