"""GoodQA #15565 (never-drop 16.2): successor kit and `ah task succeed`, cap-safe default."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import successor as sc  # noqa: E402

SESSION = "baab765b-d85c-46b4-b7b9-588eb912c770"
AGENT = "adrop00000001"


def doc(required=True, state="DROPPED"):
    return {"owners": [{"agent_id": AGENT, "state": state, "idle_s": 7200, "ticket": "GoodQA goodqa#15100",
                        "task": "private lessons stage B", "decision_required": required},
                       {"agent_id": "alive", "state": "live", "idle_s": 5, "decision_required": False}]}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.alerts = []
        self.alert = lambda kind, agent, request: self.alerts.append((kind, agent, request["status"]))

    def kit(self, **kw):
        args = dict(ticket="GoodQA goodqa#15100", worktree="/work/tree", branch="feat/lessons", evidence="RT4",
                    next_step="finish dd07 then run the live check")
        args.update(kw)
        return sc.write_kit(self.home, SESSION, AGENT, **args)

    def succeed(self, live=2, cap=8, **kw):
        return sc.succeed(self.home, SESSION, AGENT, owners_doc=kw.pop("doc", doc()), live_count=live, cap=cap,
                          alert=self.alert, now=kw.pop("now", 1000.0), **kw)


class Kit(Case):
    def test_kit_round_trips_and_replaces_atomically(self):
        self.kit()
        self.kit(next_step="second checkpoint")
        got = sc.read_kit(self.home, SESSION, AGENT)
        self.assertEqual(got["next_step"], "second checkpoint")
        self.assertEqual(got["last_evidence_id"], "RT4")
        self.assertFalse(got["derived"])
        mode = (self.home / ".agent-harness/state/successor" / SESSION / "kits" / f"{AGENT}.json").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_bad_input_and_secrets_are_refused(self):
        for kw in ({"ticket": "not a ticket"}, {"branch": "../x"}, {"worktree": "relative/path"}, {"evidence": "a b"},
                   {"next_step": "x" * 700}, {"next_step": "use token ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}):
            with self.subTest(kw=list(kw)):
                with self.assertRaises(sc.SuccessorError):
                    self.kit(**kw)
        self.assertIsNone(sc.read_kit(self.home, SESSION, AGENT))
        with self.assertRaises(sc.SuccessorError):
            sc.write_kit(self.home, "../escape", AGENT, ticket="goodqa#1", worktree="/w", branch="b", evidence="", next_step="x")


class Succeed(Case):
    def test_only_an_undisposed_dropped_owner_gets_a_successor(self):
        with self.assertRaises(sc.SuccessorError) as cm:
            self.succeed(doc=doc(required=False))
        self.assertEqual(cm.exception.code, "not_dropped")
        with self.assertRaises(sc.SuccessorError) as cm:
            sc.succeed(self.home, SESSION, "nobody", owners_doc=doc(), live_count=0, cap=8)
        self.assertEqual(cm.exception.code, "unknown_agent")
        self.assertEqual(sc.read_requests(self.home, SESSION), [])

    def test_cap_full_records_a_wait_alerts_main_and_spawns_nothing(self):
        self.kit()
        launched = []
        out = self.succeed(live=8, cap=8, runner=lambda *a, **k: launched.append(a))
        self.assertEqual(out["status"], "cap_wait")
        self.assertEqual(self.alerts, [("raise", AGENT, "cap_wait")])
        self.assertEqual(launched, [])
        self.assertFalse((self.home / ".agent-harness/state/successor" / SESSION / "prompts").exists())
        again = self.succeed(live=9, cap=8, now=1010.0)  # over the cap too: still one request, no spam
        self.assertTrue(again["deduplicated"])
        self.assertEqual(len(sc.read_requests(self.home, SESSION)), 1)
        self.assertEqual(len(self.alerts), 1)

    def test_a_cap_wait_becomes_a_ready_request_when_a_slot_frees(self):
        self.kit()
        self.succeed(live=8, cap=8)
        out = self.succeed(live=7, cap=8, now=2000.0)
        self.assertEqual(out["status"], "ready")
        text = Path(out["prompt_file"]).read_text()
        self.assertIn("RT4", text)
        self.assertIn("feat/lessons", text)
        self.assertIn("finish dd07", text)
        self.assertEqual([r["status"] for r in sc.read_requests(self.home, SESSION)], ["cap_wait", "ready"])

    def test_one_successor_per_stream_even_with_a_launcher_and_repeat_calls(self):
        self.kit()
        (self.home / ".agent-harness").mkdir(parents=True, exist_ok=True)
        (self.home / ".agent-harness" / "successor.json").write_text(json.dumps({"launcher": ["claude-x", "{prompt_file}", "{worktree}"]}))
        calls = []
        runner = lambda cmd, **kw: calls.append((cmd, kw)) or mock.Mock(pid=4242)  # noqa: E731
        first = self.succeed(runner=runner)
        second = self.succeed(runner=runner, now=1500.0)
        self.assertEqual(first["status"], "launched")
        self.assertEqual(first["pid"], 4242)
        self.assertTrue(second["deduplicated"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1]["start_new_session"])
        self.assertEqual(calls[0][0][0], "claude-x")
        self.assertEqual(calls[0][0][2], "/work/tree")

    def test_no_launcher_means_ready_plus_an_alert_not_a_spawn(self):
        self.kit()
        out = self.succeed()
        self.assertEqual(out["status"], "ready")
        self.assertEqual(self.alerts, [("raise", AGENT, "ready")])

    def test_dry_run_writes_nothing(self):
        out = self.succeed(dry_run=True)
        self.assertEqual(out["status"], "dry_run")
        self.assertEqual(sc.read_requests(self.home, SESSION), [])
        self.assertIn("SUCCESSOR", out["prompt"])

    def test_a_missing_kit_is_derived_from_the_row_and_says_so(self):
        out = self.succeed(dry_run=True)
        self.assertEqual(out["kit"], "derived")
        self.assertIn("derived from the WAL view", out["prompt"])
        self.assertIn("private lessons stage B", out["prompt"])

    def test_a_failed_launch_is_recorded_not_swallowed(self):
        self.kit()
        (self.home / ".agent-harness").mkdir(parents=True, exist_ok=True)
        (self.home / ".agent-harness" / "successor.json").write_text(json.dumps({"launcher": ["nope"]}))
        def boom(*a, **k):
            raise FileNotFoundError("nope")
        out = self.succeed(runner=boom)
        self.assertEqual(out["status"], "launch_failed")
        self.assertIsNone(sc.open_request(sc.read_requests(self.home, SESSION), AGENT))  # may be retried


class Chain(Case):
    def test_the_request_log_is_hash_chained_and_tamper_evident(self):
        self.kit()
        self.succeed(live=8, cap=8)
        self.succeed(live=0, cap=8, now=3000.0)
        rows = sc.read_requests(self.home, SESSION)
        self.assertTrue(sc.verify_chain(rows))
        rows[0] = dict(rows[0], cap=99)
        self.assertFalse(sc.verify_chain(rows))
        self.assertFalse(sc.verify_chain(rows[1:]))  # truncated head


class Hardening(Case):
    """Red-team a6022953 findings F1 to F3, F7, F8, F10, F11."""

    def launcher(self):
        (self.home / ".agent-harness").mkdir(parents=True, exist_ok=True)
        (self.home / ".agent-harness" / "successor.json").write_text(json.dumps({"launcher": ["claude-x", "{prompt_file}"]}))

    def test_eight_concurrent_callers_launch_exactly_one_successor_for_one_stream(self):
        import threading
        self.kit()
        self.launcher()
        calls, results = [], []

        def run():
            results.append(self.succeed(runner=lambda cmd, **kw: calls.append(cmd) or mock.Mock(pid=7)))
        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(calls), 1)
        statuses = [r["status"] for r in sc.read_requests(self.home, SESSION)]
        self.assertEqual(statuses.count("ready"), 1)
        self.assertEqual(statuses.count("launched"), 1)

    def test_pending_requests_count_against_the_cap(self):
        self.launcher()
        owners = {"owners": [{"agent_id": f"s{i}", "state": "DROPPED", "idle_s": 9000, "decision_required": True}
                             for i in range(4)]}
        launched = []
        for i in range(4):  # cap 4, 3 live: only ONE of the four dropped streams may get a successor
            sc.succeed(self.home, SESSION, f"s{i}", owners_doc=owners, live_count=3, cap=4, alert=self.alert,
                       now=1000.0 + i, runner=lambda cmd, **kw: launched.append(cmd) or mock.Mock(pid=1))
        self.assertEqual(len(launched), 1)
        self.assertEqual([r["status"] for r in sc.read_requests(self.home, SESSION)].count("cap_wait"), 3)

    def test_every_kit_field_is_checked_for_secrets(self):
        token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        for kw in ({"branch": token}, {"worktree": "/tmp/" + token}, {"ticket": "goodqa#1 " + token}):
            with self.subTest(field=list(kw)):
                with self.assertRaises(sc.SuccessorError):
                    self.kit(**kw)
        self.assertIsNone(sc.read_kit(self.home, SESSION, AGENT))

    def test_a_failed_launch_backs_off_and_an_old_ready_request_expires(self):
        self.kit()
        self.launcher()

        def boom(*a, **k):
            raise FileNotFoundError("nope")
        first = self.succeed(runner=boom, now=1000.0)
        self.assertEqual(first["status"], "launch_failed")
        self.assertTrue(self.succeed(runner=boom, now=1100.0).get("deduplicated"))  # inside the 10 minute backoff
        ok = self.succeed(runner=lambda cmd, **kw: mock.Mock(pid=5), now=1000.0 + sc.LAUNCH_BACKOFF_S + 1)
        self.assertEqual(ok["status"], "launched")
        later = self.succeed(runner=lambda cmd, **kw: mock.Mock(pid=6), now=1000.0 + sc.LIVE_TTL_S + 1000)
        self.assertEqual(later["status"], "launched")  # the first successor never appeared: a new request is allowed
        self.assertFalse(later.get("deduplicated"))

    def test_a_stale_cap_wait_is_refreshed_while_the_cap_stays_full(self):
        # acceptance review a3318610 N1: the Stop gate trusts only a recent wait, so succeed must be able to renew it
        self.kit()
        first = self.succeed(live=8, cap=8, now=1000.0)
        young = self.succeed(live=8, cap=8, now=1000.0 + sc.CAP_REFRESH_S - 5)
        self.assertTrue(young.get("deduplicated"))
        later = self.succeed(live=8, cap=8, now=1000.0 + sc.CAP_REFRESH_S + 5)
        self.assertFalse(later.get("deduplicated"))
        self.assertEqual(later["status"], "cap_wait")
        self.assertGreater(later["at"], first["at"])
        rows = sc.read_requests(self.home, SESSION)
        self.assertEqual([r["status"] for r in rows], ["cap_wait", "cap_wait"])
        self.assertEqual(sc.open_request(rows, AGENT, later["at"])["at"], later["at"])  # still one live request

    def test_pending_agents_is_the_shared_cap_count(self):
        rows = [{"agent": "a", "status": "ready", "at": 1000.0}, {"agent": "b", "status": "launched", "at": 1000.0},
                {"agent": "c", "status": "cap_wait", "at": 1000.0}, {"agent": "d", "status": "ready", "at": -30000.0}]
        self.assertEqual(sc.pending_agents(rows, 2000.0), {"a", "b"})  # d expired, c is a wait
        self.assertEqual(sc.pending_agents(rows, 2000.0, exclude="a"), {"b"})

    def test_a_truncated_tail_or_deleted_log_fails_verification(self):
        self.kit()
        self.succeed(live=8, cap=8)
        self.succeed(live=0, cap=8, now=3000.0)
        self.assertTrue(sc.verify_log(self.home, SESSION))
        log = self.home / ".agent-harness/state/successor" / SESSION / "requests.jsonl"
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:-1]) + "\n")  # drop the last row
        self.assertFalse(sc.verify_log(self.home, SESSION))
        log.write_text("")
        self.assertFalse(sc.verify_log(self.home, SESSION))

    def test_the_prompt_marks_kit_text_as_untrusted(self):
        out = self.succeed(dry_run=True)
        self.assertIn("untrusted data", out["prompt"])


class Cli(Case):
    """AC-1 and AC-2 through the real `ah task kit` and `ah task succeed` commands (acceptance review a3318610 F5)."""

    def test_kit_then_succeed_through_ah_main_and_the_cap_path_exits_3(self):
        import io
        import ah
        import model_tiers
        import tier_gate
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}), mock.patch("sys.stdout", out):
            code = ah.main(["task", "kit", "--agent", AGENT, "--session", SESSION, "--ticket", "goodqa#1",
                            "--worktree", "/w", "--branch", "feat/x", "--next", "finish it"])
            self.assertEqual(code, 0, out.getvalue())
        self.assertTrue((self.home / ".agent-harness/state/successor" / SESSION / "kits" / f"{AGENT}.json").is_file())
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}), mock.patch("sys.stdout", out), \
                mock.patch.object(ah, "owners", lambda home, session, **k: doc()), \
                mock.patch.object(tier_gate, "live_owner_ids", lambda session, policy: ["o"] * 4), \
                mock.patch.object(model_tiers, "load_policy", lambda: {"caps": {"session_owner_agents": 4}}), \
                mock.patch.object(sc, "ring_alert", lambda home: (lambda *a: None)):
            code = ah.main(["task", "succeed", "--agent", AGENT, "--session", SESSION])
        self.assertEqual(code, 3, out.getvalue())
        rows = sc.read_requests(self.home, SESSION)
        self.assertEqual([r["status"] for r in rows], ["cap_wait"])
        self.assertTrue(sc.verify_log(self.home, SESSION))

    def test_a_malformed_agent_id_is_refused_by_the_command(self):
        import io
        import ah
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}), mock.patch("sys.stdout", out), \
                mock.patch.object(ah, "owners", lambda home, session, **k: doc()):
            code = ah.main(["task", "succeed", "--agent", "../x", "--session", SESSION])
        self.assertEqual(code, 3, out.getvalue())
        self.assertEqual(sc.read_requests(self.home, SESSION), [])


class AhdStep(Case):
    """ahd asks `ah task succeed` only while main is absent, only for undisposed idle owners, a few per tick."""

    def daemon(self, calls, per_tick=10):
        import ahd

        def runner(argv, timeout, stdin=None):
            calls.append(argv)
            return 0, "{}", ""
        patch = mock.patch.object(ahd, "home", lambda: self.home)
        patch.start()
        self.addCleanup(patch.stop)
        policy = {"successor_main_idle_s": 1800, "ah": ["ah"]}
        if per_tick is not None:
            policy["successor_per_tick"] = per_tick  # None: the shipped default of 3
        return ahd.Daemon(policy=policy, runner=runner)

    def main_wal(self, age):
        wal = self.home / ".claude" / "wals" / SESSION
        wal.mkdir(parents=True, exist_ok=True)
        (wal / "main.jsonl").write_text("{}\n")
        stamp = 10_000 - age
        os.utime(wal / "main.jsonl", (stamp, stamp))

    def rows(self, n=3):
        # the fresh and the disposed owner come FIRST, so a missing idle or decision check shows up as a call for them
        return {SESSION: {"owners": [{"agent_id": "fresh", "decision_required": True, "idle_s": 60},
                                     {"agent_id": "disposed", "decision_required": False, "idle_s": 99999}]
                          + [{"agent_id": f"a{i}", "decision_required": True, "idle_s": 3600} for i in range(n)]}}

    def test_requests_for_idle_undisposed_owners_only_when_main_is_absent(self):
        calls = []
        daemon = self.daemon(calls)
        self.main_wal(age=3600)
        done = daemon.request_successors(self.rows(), 10_000.0, 1e12)
        self.assertEqual(len(done), 3)
        self.assertTrue(all(c[1:3] == ["task", "succeed"] for c in calls))
        self.assertEqual(sorted(c[4] for c in calls), ["a0", "a1", "a2"])  # never fresh, never disposed

    def test_the_shipped_default_is_three_requests_per_tick(self):
        calls = []
        daemon = self.daemon(calls, per_tick=None)
        self.main_wal(age=3600)
        self.assertEqual(len(daemon.request_successors(self.rows(n=6), 10_000.0, 1e12)), 3)
        self.assertEqual(len(calls), 3)

    def test_a_stream_that_already_has_a_live_request_does_not_spend_the_budget(self):
        calls = []
        daemon = self.daemon(calls, per_tick=None)
        self.main_wal(age=3600)
        for agent in ("a0", "a1", "a2"):  # three streams waiting on the cap
            sc._append(self.home, SESSION, {"schema": 1, "at": 10_000.0 - 60, "agent": agent, "session": SESSION,
                                            "status": "cap_wait"})
        done = daemon.request_successors(self.rows(n=5), 10_000.0, 1e12)
        self.assertEqual(sorted(c[4] for c in calls), ["a3", "a4"])
        self.assertEqual(len(done), 2)

    def test_nothing_while_main_is_active(self):
        calls = []
        daemon = self.daemon(calls)
        self.main_wal(age=60)
        self.assertEqual(daemon.request_successors(self.rows(), 10_000.0, 1e12), [])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
