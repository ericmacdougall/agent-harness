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
        check = ah.ahd_running_check(self.home)
        self.assertTrue(check["ok"], check)
        self.assertNotIn("heartbeat.beat", self.ledger_ops())  # 1440 beats a day never grow the ledger

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
        self.assertTrue(ah.ahd_running_check(self.home)["ok"])


if __name__ == "__main__":
    unittest.main()
