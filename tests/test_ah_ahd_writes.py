"""goodqa#14848: the `ah` subcommands ahd calls (heartbeat beat, alert raise|clear, apply --batch).

ahd runs on every host but skipped these for 10 min at a time ("ah X not available yet"), so it never wrote a
heartbeat and never raised an alert. The arguments here are exactly the ones ahd.py builds."""
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ahd  # noqa: E402
import ops_watch  # noqa: E402


class AhdWrites(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)

    def ah(self, argv, stdin=None):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stdin", io.StringIO(stdin or "")):
            rc = ah.main(argv)
        text = out.getvalue().strip()
        return rc, (json.loads(text) if text else None)

    def ring(self):
        return ops_watch.read_ring(ops_watch.ring_path(self.home))

    def raise_args(self, key="ahd:owner:x", ikey="ahd-raise-0001", severity="high"):
        return ["alert", "raise", "--alert-key", key, "--source", "ahd", "--key", ikey, "--severity", severity,
                "--message", "owner x is DROPPED", "--detail", json.dumps({"session": "abcd1234"})]

    def test_heartbeat_beat_writes_the_file_doctor_reads(self):
        rc, doc = self.ah(["heartbeat", "beat", "--service", "ahd", "--key", "mac:beat:ahd:t1"])
        self.assertEqual((rc, doc["ok"]), (0, True))
        beat = self.home / ".agent-harness" / "state" / "ahd" / "heartbeat.json"
        data = json.loads(beat.read_text())
        self.assertEqual(data["service"], "ahd")
        self.assertEqual(oct(beat.stat().st_mode & 0o777), "0o600")
        check = ah.ahd_running_check(self.home)
        self.assertTrue(check["ok"])
        self.assertLessEqual(check["heartbeat_age_s"], 5)
        ledger = ah.store_dir(self.home) / "ledger.jsonl"
        self.assertFalse(ledger.exists() and "beat" in ledger.read_text())  # never ledgered: once a minute per host

    def test_heartbeat_rejects_a_service_name_that_is_a_path(self):
        for bad in ("../x", "a/b", "", "UPPER"):
            with self.subTest(bad=bad):
                rc, doc = self.ah(["heartbeat", "beat", "--service", bad])
                self.assertEqual(rc, 2)
                self.assertEqual(doc["code"], "bad_request")
        self.assertFalse((self.home / ".agent-harness" / "state" / "x").exists())

    def test_alert_raise_then_clear_reaches_the_ring_once_per_key(self):
        rc, doc = self.ah(self.raise_args())
        self.assertEqual((rc, doc["result"]), (0, "applied"))
        rc, doc = self.ah(self.raise_args())  # ahd re-issues the same key after a restart
        self.assertEqual((rc, doc["result"]), (0, "duplicate"))
        events = self.ring()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual((ev["event"], ev["source"], ev["key"], ev["severity"], ev["host"]),
                         ("raise", "ahd", "ahd:owner:x", "high", ahd.host()))
        self.assertEqual(ev["detail"], {"session": "abcd1234"})
        self.assertIn("ahd:owner:x", ahd.ring_state(self.ring(), "ahd", ahd.host()))  # what ahd diffs against
        rc, doc = self.ah(["alert", "clear", "--alert-key", "ahd:owner:x", "--source", "ahd", "--key", "ahd-clear-0001"])
        self.assertEqual(rc, 0)
        self.assertEqual(ahd.ring_state(self.ring(), "ahd", ahd.host())["ahd:owner:x"]["event"], "clear")

    def test_alert_raise_rejects_bad_input_without_a_ring_event(self):
        bad = [self.raise_args(severity="urgent"),
               ["alert", "raise", "--alert-key", "", "--source", "ahd", "--key", "ahd-bad-00002", "--severity", "high",
                "--message", "m"],
               ["alert", "raise", "--alert-key", "k", "--source", "ahd", "--key", "ahd-bad-00003", "--severity", "high",
                "--message", "m", "--detail", "not json"]]
        for argv in bad:
            with self.subTest(argv=argv):
                rc, doc = self.ah(argv)
                self.assertEqual(rc, 2, doc)
        self.assertEqual(self.ring(), [])

    def test_alert_message_is_redacted(self):
        args = self.raise_args(ikey="ahd-raise-sec01")
        args[args.index("--message") + 1] = "token ghp_" + "a" * 36
        self.assertEqual(self.ah(args)[0], 0)
        self.assertNotIn("ghp_" + "a" * 36, json.dumps(self.ring()))

    def test_apply_batch_runs_the_lines_ahd_builds(self):
        lines = []
        for i in range(12):
            lines.append(json.dumps({"op": "alert.raise", "key": "ahd-batch-%04d" % i, "args": {
                "alert_key": "ahd:k%d" % i, "source": "ahd", "severity": "warning", "message": "m%d" % i,
                "detail": {}}}, sort_keys=True))
        rc, doc = self.ah(["apply", "--batch", "-"], "\n".join(lines) + "\n")
        self.assertEqual(rc, 0, doc)
        self.assertEqual(doc["applied"], 12)
        self.assertEqual(len(self.ring()), 12)
        rc, doc = self.ah(["apply", "--batch", "-"], "\n".join(lines) + "\n")  # replay after a kill mid-tick
        self.assertEqual((rc, doc["applied"], doc["duplicate"]), (0, 0, 12))
        self.assertEqual(len(self.ring()), 12)

    def test_apply_batch_refuses_other_ops_and_bad_lines_before_writing(self):
        good = json.dumps({"op": "alert.raise", "key": "ahd-batch-good1", "args": {
            "alert_key": "k", "source": "ahd", "severity": "info", "message": "m"}})
        for bad in (json.dumps({"op": "task.dispose", "key": "ahd-batch-bad01", "args": {}}), "{not json"):
            with self.subTest(bad=bad):
                rc, doc = self.ah(["apply", "--batch", "-"], good + "\n" + bad + "\n")
                self.assertEqual(rc, 2, doc)
                self.assertEqual(self.ring(), [])  # validated as a whole first: no partial batch

    def test_apply_batch_is_bounded(self):
        line = json.dumps({"op": "alert.clear", "key": "ahd-batch-x0001", "args": {"alert_key": "k", "source": "ahd"}})
        rc, doc = self.ah(["apply", "--batch", "-"], (line + "\n") * (ah.APPLY_MAX_LINES + 1))
        self.assertEqual(rc, 2)

    def test_ahd_calls_succeed_through_its_own_runner(self):
        """End to end: ahd.Daemon.call runs this ah.py as a child; none of the verbs comes back unsupported."""
        d = ahd.Daemon(policy={"ah": [sys.executable, str(HOOKS / "ah.py")], "ah_timeout_seconds": 30})
        deadline = ahd.mono() + 60
        rc, _ = d.call("heartbeat beat", ["--service", "ahd", "--key", "mac:beat:ahd:t1"], deadline)
        self.assertEqual(rc, 0)
        rc, _ = d.call("alert raise", d.alert_args("raise", "ahd:k", {"severity": "high", "message": "m"}, "ahd"),
                       deadline)
        self.assertEqual(rc, 0)
        self.assertEqual(d.unsupported, {})
        self.assertTrue((self.home / ".agent-harness" / "state" / "ahd" / "heartbeat.json").is_file())
