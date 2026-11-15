"""Drive loop (owner-runtime-drive, goodqa#15968). These fail against origin/main 98e33c5d: there is no drive module,
no per-initiative conditions, no response ledger and no drive Stop gate."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import drive  # noqa: E402
import owner_rt as ort  # noqa: E402
import authority_fixture as fx  # noqa: E402

NOW = 1_800_000_000.0
MISSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"



class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        (self.home / ".agent-harness" / "mission").mkdir(parents=True)
        self.goals = [
            {"id": "solve", "title": "Solve", "status": "active", "ticket": "goodqa#11", "priority": 1},
            {"id": "leads", "title": "Leads", "status": "imported", "ticket": "goodqa#12"},
            {"id": "old", "title": "Old", "status": "done"},
            {"id": "pp", "title": "ParentProof", "status": "deferred", "deferral": {"by": "user", "ref": "x"}},
        ]
        self.write_goals()
        self.repo = self.home / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.commit("init")
        for g in self.goals:
            g.setdefault("repos", [str(self.repo)])
        self.write_goals()
        p2 = mock.patch.object(drive, "mission_session", return_value=MISSION)
        p2.start()
        self.addCleanup(p2.stop)
        p3 = mock.patch.object(drive, "owner_rows_of", return_value=[])  # a fresh, empty signed owner list
        p3.start()
        self.addCleanup(p3.stop)

    def commit(self, msg):
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                        "--allow-empty", "-m", msg], check=True)
        return subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip()

    def write_goals(self):
        (self.home / ".agent-harness" / "mission" / "goals.json").write_text(
            json.dumps({"mission_session": MISSION, "goals": self.goals}))

    def row(self, a, goal):
        return next(r for r in a["rows"] if r["goal"] == goal)

    def conds(self, a, goal):
        return [x["cond"] for x in self.row(a, goal)["actions"]]

    def owner(self, goal="solve"):
        st = ort.init_owner(self.home, goal, str(self.repo), "ticket:goodqa#11")
        return st


class TableTests(Base):
    def test_table_lists_every_goal_whatever_status(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(sorted(r["goal"] for r in a["rows"]), ["leads", "old", "pp", "solve"])
        self.assertEqual(self.conds(a, "old"), [])
        self.assertEqual(self.row(a, "old")["distance"], "done")

    def test_table_render_and_cli_json(self):
        with mock.patch("sys.stdout") as out:
            self.assertEqual(drive.main(["table", "--json"]), 0)
        snap = drive.load_snapshot(self.home)
        self.assertEqual(len(snap["rows"]), 4)
        text = drive.render(snap, [], NOW)
        self.assertIn("REQUIRED UNOWNED", text)


class ConditionTests(Base):
    def test_condition_imported_and_unowned(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "leads"), ["IMPORTED", "UNOWNED"])
        self.assertEqual(self.conds(a, "solve"), ["UNOWNED"])

    def test_condition_user_deferral_suppresses(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "pp"), [])

    def test_condition_legacy_owner_counts(self):
        rows = [{"agent_id": "a1234567890abcdef0", "ticket": "goodqa#11", "state": "live", "owner": True,
                 "agent_type": "task-owner"}]
        with mock.patch.object(drive, "legacy_owners", side_effect=lambda h, s, g, r: ["a1234567890abcdef0"]
                               if g["id"] == "solve" else []):
            a = drive.assess(self.home, MISSION, NOW, owner_rows=rows, with_git=False)
        self.assertNotIn("UNOWNED", self.conds(a, "solve"))

    def test_condition_stalled_proof_29_vs_31(self):
        self.owner()
        st = ort.load_state(self.home, "solve")
        st["last_beat"] = {"ts": NOW - 29 * 60}
        ort.save_state(self.home, "solve", st)
        self.assertEqual(self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), "solve"), [])
        st["last_beat"] = {"ts": NOW - 31 * 60}
        ort.save_state(self.home, "solve", st)
        self.assertEqual(self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), "solve"), ["STALLED"])

    def test_condition_stuck_help_and_loop(self):
        self.owner()
        st = ort.load_state(self.home, "solve")
        st["last_beat"], st["stuck"] = {"ts": NOW}, True
        ort.save_state(self.home, "solve", st)
        ort.add_task(self.home, "solve", "a", "ticket:goodqa#11")
        ort.add_task(self.home, "solve", "b", "ticket:goodqa#11")
        ort.move_task(self.home, "solve", "t1", "blocked", help_text="need grant")
        ac = self.home / "ac.md"
        ac.write_text("AC-1 x\nVerify by: pytest x\nNEG-1 y\n")
        ort.move_task(self.home, "solve", "t2", "planned", ac_file=str(ac))
        ort.review_round(self.home, "solve", "t2", "a1234567890abcdef", "REJECT")
        ort.review_round(self.home, "solve", "t2", "a1234567890abcdef", "REJECT")
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "solve"), ["STUCK", "HELP_OPEN", "REVIEW_LOOP"])
        keys = [x["key"] for x in self.row(a, "solve")["actions"]]
        self.assertIn("solve:HELP_OPEN:t1", keys)
        self.assertIn("solve:REVIEW_LOOP:t2", keys)

    def test_condition_merged_not_released(self):
        self.goals[0]["repos"] = [str(self.repo)]
        self.write_goals()
        self.commit("fix(x): thing\n\nRefs: GoodQA goodqa#11")
        subprocess.run(["git", "-C", str(self.repo), "update-ref", "refs/remotes/origin/main", "HEAD"], check=True)
        a = drive.assess(self.home, MISSION, time.time(), owner_rows=[])
        self.assertIn("MERGED_NOT_RELEASED", self.conds(a, "solve"))
        self.goals[0]["evidence"] = [{"kind": "deploy", "at": time.time(), "row_at": time.time() + 60}]
        self.write_goals()
        self.assertNotIn("MERGED_NOT_RELEASED", self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[]), "solve"))

    def test_condition_pending_gates_never_replaces_owner(self):
        with mock.patch.object(drive, "lifecycle_state", return_value="pending"):
            a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "solve"), ["UNOWNED", "PENDING_GATES"])

    def test_condition_no_capacity_action_exists(self):
        for text in drive.ACTIONS.values():
            self.assertNotRegex(text.lower(), r"\bqueue\b|\bcapacity\b|\bwait for a slot\b")


class ResponseTests(Base):
    def setUp(self):
        super().setUp()
        self.wal = self.home / ".claude" / "wals" / MISSION / "main.jsonl"
        self.wal.parent.mkdir(parents=True)
        self.asks = []

    def ask(self, wid, note, resolved=False):
        rows = [{"event": "ask", "id": wid, "note": note}]
        if resolved:
            rows.append({"event": "ask_resolved", "ref": wid})
        with open(self.wal, "a") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def patch_asks(self):
        import mission_coverage as mc
        return mock.patch.object(mc, "ask_states", lambda h, s: {
            json.loads(l)["id"]: {"state": "open", "note": json.loads(l)["note"]}
            for l in self.wal.read_text().splitlines() if json.loads(l)["event"] == "ask"} | {
            json.loads(l)["ref"]: {"state": "resolved", "note": ""}
            for l in self.wal.read_text().splitlines() if json.loads(l)["event"] == "ask_resolved"})

    def test_response_ask_must_be_open_and_name_goal(self):
        self.ask("w00000000001", "Agree gates for goal solve")
        self.ask("w00000000002", "Agree gates for goal leads")
        self.ask("w00000000003", "goal solve old question", resolved=True)
        with self.patch_asks():
            drive.respond(self.home, "solve", "PENDING_GATES", "ask", "w00000000001", now=NOW)
            for ref in ("w00000000002", "w00000000003", "w0000000000f"):
                with self.assertRaises(drive.DriveError, msg=ref):
                    drive.respond(self.home, "solve", "PENDING_GATES", "ask", ref, now=NOW)

    def test_response_kind_must_fit_condition(self):
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "UNOWNED", "ticket", "goodqa#5", now=NOW)

    def test_response_raw_append_and_forged_snapshot_ignored(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl", {"key": key, "ts": NOW + 2})  # unsigned
        self.assertEqual(drive.read_responses(self.home), [])
        (drive._safe_dir(self.home) / "snapshot.json").write_text(json.dumps({"at": NOW, "rows": []}))
        self.assertIsNone(drive.load_snapshot(self.home))
        out = drive.stop_decision(self.home, {"session_id": MISSION}, now=NOW + 3, is_main=True)
        self.assertEqual(out.get("decision"), "block")

    def test_response_owner_needs_successful_launch(self):
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)  # no owner
        self.owner()
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)  # no launch
        st = ort.load_state(self.home, "solve")
        st["launches"] = [{"ts": NOW - 3 * 86400, "code": 0}]  # an old launch (r1 M5)
        ort.save_state(self.home, "solve", st)
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)
        st["launches"].append({"ts": NOW, "code": 0})
        ort.save_state(self.home, "solve", st)
        drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)

    def test_release_uses_deploy_event_time_not_attach_time(self):
        """Receipt v3 F2: an older deploy attached after the merge is not a newer release."""
        import datetime as dt
        iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat()  # noqa: E731
        g = {"evidence": [{"kind": "deploy", "at": iso(NOW), "row_at": iso(NOW - 86400)}]}
        self.assertEqual(drive.deploy_ts(g, NOW), NOW - 86400)
        self.assertEqual(drive.deploy_ts({"evidence": [{"kind": "deploy", "at": iso(NOW)}]}, NOW), 0.0)  # no row_at
        self.assertEqual(drive.deploy_ts({"evidence": [{"kind": "deploy", "row_at": iso(NOW + 3600)}]}, NOW), 0.0)
        with mock.patch.object(drive, "merged_commit", return_value=(NOW - 3600, "0123456789ab")):
            self.goals[0]["evidence"] = g["evidence"]
            self.goals[0]["repos"] = [str(self.repo)]
            self.write_goals()
            self.assertIn("MERGED_NOT_RELEASED",
                          self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[]), "solve"))

    def test_response_stale_episode_not_counted(self):
        snap = drive.with_episodes(self.home, drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), prev={})
        ort._append(drive._safe_dir(self.home) / "responses.jsonl",
                    drive._sign(self.home, {"key": "solve:UNOWNED", "ts": NOW - 10}))  # recorded before the episode began
        todo = [t["key"] for t in drive.unanswered(snap, drive.read_responses(self.home), NOW + 5)]
        self.assertIn("solve:UNOWNED", todo)
        ort._append(drive._safe_dir(self.home) / "responses.jsonl",
                    drive._sign(self.home, {"key": "solve:UNOWNED", "ts": NOW + 1}))
        todo = [t["key"] for t in drive.unanswered(snap, drive.read_responses(self.home), NOW + 5)]
        self.assertNotIn("solve:UNOWNED", todo)
        todo = [t["key"] for t in drive.unanswered(snap, drive.read_responses(self.home),
                                                   NOW + drive.RESPONSE_TTL_S + 10)]
        self.assertIn("solve:UNOWNED", todo)  # expired


# Every park phrase the earlier review rounds used (receipts v2-v5): none may park, whatever form it arrives in. The
# last group were positives under the text parser; they are refusals now.
PARK_PHRASES = (
    "keep solve moving; never park solve", "never park solve", "do not defer solve", "don't pause solve",  # v2
    "solve is the top priority", "solve: keep going, no hold",
    "keep solve moving; park leads until Monday", "solve is fine, park leads", "park leads until solve ships",  # v3
    "park leads and keep pushing solve", "let's solve the bug later", "hold on, solve is broken",
    "park everything except solve",
    "Should we park solve?", "If the release fails we should park solve", "park solve?",  # v4
    "Should we park solve", "do we park solve", "solve parked", "keep leads moving; park solve until Monday",
    "when leads ships, park solve", "maybe park solve", "we could defer solve", "unless it lands today, park solve",
    "Please don't park solve today.", "Never park solve for the rest of today.",  # v5 (quoted in part below)
    "Please don't park solve.",
    "Keep going. If the build breaks, park solve today.", "No. park solve today.", "Yes, park solve today. Wait, don't.",
    "Thanks for the update. Yes, park solve today.", "park solve until Monday", "defer solve", "put solve on hold",
    "yes, park solve",
)


class ParkAuthorityTests(Base):
    """Receipt v6 F1: a goal is parked only by the user's structured answer to the exact park question."""

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        p.start()
        self.addCleanup(p.stop)
        import mission_coverage
        p = mock.patch.object(mission_coverage, "mission_session_of", return_value=MISSION)
        p.start()
        self.addCleanup(p.stop)
        import command_guard
        p = mock.patch.object(command_guard, "_pinned_home", return_value=str(self.home))  # v7 F4: answers home
        p.start()
        self.addCleanup(p.stop)
        self.until = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 86400))

    def park_answer(self, goal="solve", until=None, chosen=None, **kw):
        until = until or self.until
        q = kw.pop("question", None) or ort.park_question(goal, until)
        chosen = ort.park_label(goal, until) if chosen is None else chosen
        session = kw.pop("session", MISSION)
        options = kw.pop("options", ort.park_options(goal, until))
        uid = fx.answer(self.home, session, q, chosen, options=options, **kw)
        return f"answer:{session}/{uid}"

    def required(self, goal="solve"):
        out = drive.stop_decision(self.home, {"session_id": MISSION}, now=time.time(), is_main=True)
        return goal + " " in out.get("reason", "") + out.get("systemMessage", "")

    def test_park_no_text_ever_parks(self):
        self.assertEqual(fx.MISSION, MISSION)
        for words in PARK_PHRASES:
            uid = fx.human_turn(self.home, MISSION, words)
            for quote in (words, "park solve", "park solve today", "park solve for the rest of today"):
                if quote not in words:
                    continue
                src = f'user:{MISSION}/{uid} "{quote}"'
                # 1. the old path: a park response citing the user's words
                with self.assertRaises(drive.DriveError, msg=words):
                    drive.respond(self.home, "solve", "UNOWNED", "park", source=src, now=time.time())
                # 2. the words cited to the park command
                with self.assertRaisesRegex(ort.OwnerError, "must be exactly answer:", msg=words):
                    ort.park_goal(self.home, "solve", self.until, src)
            for src in ("inferred:from x -- y", "wal:w123", f'queue:{MISSION}/2026-11-14T10:00:00Z#0123456789ab "{words}"',
                        ""):
                with self.assertRaises(drive.DriveError, msg=src):
                    drive.respond(self.home, "solve", "UNOWNED", "park", source=src, now=time.time())
                with self.assertRaisesRegex(ort.OwnerError, "must be exactly answer:", msg=src):
                    ort.park_goal(self.home, "solve", self.until, src)
            # 3. typed as the free-text reply to the exact park question; 4. as the question itself
            with self.assertRaisesRegex(ort.OwnerError, "did not choose", msg=words):
                ort.park_goal(self.home, "solve", self.until, self.park_answer(chosen=words))
            with self.assertRaisesRegex(ort.OwnerError, "different question", msg=words):
                ort.park_goal(self.home, "solve", self.until, self.park_answer(question=words))
        self.assertTrue(self.required("solve"))
        self.assertIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[],
                                                         with_git=False), "solve"))
        # positive control on the same fixture home
        ort.park_goal(self.home, "solve", self.until, self.park_answer())
        a = drive.assess(self.home, MISSION, time.time(), owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "solve"), [])
        self.assertIn("parked by the user's answer", self.row(a, "solve")["blocker"])
        self.assertIn("UNOWNED", self.conds(a, "leads"))  # only the named goal
        self.assertFalse(self.required("solve"))
        ort.unpark_goal(self.home, "solve")
        self.assertIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[],
                                                         with_git=False), "solve"))

    def test_park_answer_must_fit_goal_date_and_shape(self):
        other = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 5 * 86400))
        far = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 40 * 86400))
        past = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 2 * 86400))
        cases = [("declined", dict(chosen="Keep solve active"), "did not choose"),
                 ("other goal", dict(question=ort.park_question("leads", self.until)), "different question"),
                 ("other date", dict(question=ort.park_question("solve", other)), "different question"),
                 ("sub-agent", dict(sidechain=True), "resolve"),
                 ("stale", dict(ts=time.time() - 25 * 3600), "older than"),
                 ("other session", dict(session="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"), "mission session")]
        for name, kw, why in cases:
            with self.assertRaisesRegex(ort.OwnerError, why, msg=name):
                ort.park_goal(self.home, "solve", self.until, self.park_answer(**kw))
        with self.assertRaisesRegex(ort.OwnerError, "at most 30 days"):
            ort.park_goal(self.home, "solve", far, self.park_answer(until=far))
        with self.assertRaisesRegex(ort.OwnerError, "past"):
            ort.park_goal(self.home, "solve", past, self.park_answer(until=past))
        for bad in ("Monday", "2026-13-40", ""):
            with self.assertRaises(ort.OwnerError, msg=bad):
                ort.park_goal(self.home, "solve", bad, self.park_answer())
        self.assertEqual(ort.load_authority(self.home)["parks"], [])
        ort.park_goal(self.home, "solve", self.until, self.park_answer())  # control
        self.assertEqual(len(ort.load_authority(self.home)["parks"]), 1)

    def test_park_ends_on_its_date_and_record_alone_parks_nothing(self):
        ort.park_goal(self.home, "solve", self.until, self.park_answer())
        self.assertIsNotNone(ort.active_park(self.home, "solve", time.time()))
        self.assertIsNone(ort.active_park(self.home, "solve", time.time() + 5 * 86400))
        human = fx.human_turn(self.home, MISSION, "Park solve until next week.")
        root = self.home / ".agent-harness" / "owners"
        for answer in (f"answer:{MISSION}/{human}", self.park_answer(chosen="Keep solve active"),
                       self.park_answer(goal="leads"), "",
                       self.park_answer(session="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee")):  # session binds at use
            (root / "authority.json").write_text(json.dumps({"parks": [{"goal": "solve", "until": self.until,
                                                                         "answer": answer}]}))
            self.assertIsNone(ort.active_park(self.home, "solve", time.time()), answer)
            self.assertIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[],
                                                             with_git=False), "solve"))

    def test_park_ledger_user_deferral_honours_until(self):
        import datetime as dt
        iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat()  # noqa: E731
        pp = self.goals[3]
        pp["deferral"]["until"] = iso(time.time() - 60)
        self.write_goals()
        self.assertIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[],
                                                         with_git=False), "pp"))
        pp["deferral"]["until"] = iso(time.time() + 3600)
        self.write_goals()
        self.assertEqual(self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[], with_git=False),
                                    "pp"), [])

    def test_park_response_kind_is_gone(self):
        self.assertNotIn("park", [k for kinds in drive.RESPONSE_KINDS.values() for k in kinds])
        for name in ("park_binds", "PARK_LEAD", "PARK_INTENT"):
            self.assertFalse(hasattr(drive, name), name)
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            drive.build_parser().parse_args(["respond", "--goal", "solve", "--cond", "UNOWNED", "--kind", "park"])


class TicketAssociationTests(Base):
    """Receipt v6 F3: a ticket answers an action only when it is durably about that goal and task or commit."""

    def setUp(self):
        super().setUp()
        self.owner()
        ac = self.home / "ac.md"
        ac.write_text("AC-1 x\nVerify by: pytest x\nNEG-1 y\n")
        ort.add_task(self.home, "solve", "a", "ticket:goodqa#11")
        ort.add_task(self.home, "solve", "b", "ticket:goodqa#11")
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(ac))
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "REJECT")
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "REJECT")
        ort.move_task(self.home, "solve", "t2", "blocked", help_text="need a grant")
        self.tickets = {}

    def lookup(self, ref):
        return self.tickets.get(ref, {"state": "missing"})

    def respond(self, cond, ref, detail):
        return drive.respond(self.home, "solve", cond, "ticket", ref, detail=detail, now=NOW, ticket_check=self.lookup)

    def test_ticket_open_but_unrelated_never_answers(self):
        self.tickets = {"goodqa#21": {"state": "open", "title": "[drive:leads:t1] another goal's loop"},
                        "goodqa#22": {"state": "open", "title": "[drive:solve:t2] the other task of this goal"},
                        "goodqa#23": {"state": "open", "title": "solve: misc cleanup"},
                        "goodqa#11": {"state": "open", "title": "Solve working live"},  # the goal's own ticket
                        "goodqa#24": {"state": "open", "title": "[drive:solve:t11] a task id that only starts alike"},
                        "goodqa#25": {"state": "closed", "title": "[drive:solve:t1] closed"}}
        for ref in sorted(self.tickets):
            with self.assertRaises(drive.DriveError, msg=ref):
                self.respond("REVIEW_LOOP", ref, "t1")
        for ref in ("goodqa#21", "goodqa#23", "goodqa#11"):
            with self.assertRaises(drive.DriveError, msg=ref):
                self.respond("HELP_OPEN", ref, "t2")
        self.assertEqual(drive.read_responses(self.home), [])
        self.tickets["goodqa#30"] = {"state": "open", "title": "[drive:solve:t1] redesign the login flow"}
        self.tickets["goodqa#31"] = {"state": "open", "title": "[drive:solve:t2] grant for the deploy key"}
        self.respond("REVIEW_LOOP", "goodqa#30", "t1")  # controls: the associated tickets do answer
        self.respond("HELP_OPEN", "goodqa#31", "t2")
        with self.assertRaises(drive.DriveError):
            self.respond("HELP_OPEN", "goodqa#30", "t1")  # t1 is not blocked: the condition is not about it
        with self.assertRaises(drive.DriveError):
            self.respond("REVIEW_LOOP", "goodqa#31", "t2")  # t2 is not in a loop

    def test_ticket_unknown_state_never_answers(self):
        self.tickets = {"goodqa#30": {"state": None, "title": "[drive:solve:t1] x"}}
        with self.assertRaises(drive.DriveError):
            self.respond("REVIEW_LOOP", "goodqa#30", "t1")
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "REVIEW_LOOP", "ticket", "goodqa#30", detail="t1", now=NOW,
                          ticket_check=lambda ref: "open")  # the old string-only answer carries no title

    def test_ticket_release_bound_to_the_commit(self):
        self.goals[0]["repos"] = [str(self.repo)]
        self.write_goals()
        first = self.commit("fix(x): one\n\nRefs: GoodQA goodqa#11")
        subprocess.run(["git", "-C", str(self.repo), "update-ref", "refs/remotes/origin/main", "HEAD"], check=True)
        a = drive.assess(self.home, MISSION, time.time(), owner_rows=[])
        act = next(x for x in self.row(a, "solve")["actions"] if x["cond"] == "MERGED_NOT_RELEASED")
        self.assertEqual((act["detail"], act["key"]), (first[:12], f"solve:MERGED_NOT_RELEASED:{first[:12]}"))
        self.tickets = {"goodqa#40": {"state": "open", "title": "release solve"},
                        "goodqa#41": {"state": "open", "title": "[drive:leads:release:%s]" % first[:12]},
                        "goodqa#42": {"state": "open", "title": "[drive:solve:release:0123456789ab]"},
                        "goodqa#43": {"state": "open", "title": "[drive:solve:release:%s] ship it" % first[:12]}}
        for ref in ("goodqa#40", "goodqa#41", "goodqa#42"):
            with self.assertRaises(drive.DriveError, msg=ref):
                self.respond("MERGED_NOT_RELEASED", ref, first[:12])
        with self.assertRaises(drive.DriveError):
            self.respond("MERGED_NOT_RELEASED", "goodqa#42", "0123456789ab")  # not the newest commit
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "MERGED_NOT_RELEASED", "ticket", "goodqa#43", now=NOW,
                          ticket_check=self.lookup)  # no --detail
        import mission_coverage as mc
        with mock.patch.object(mc, "ask_states", lambda h, sess: {"w00000000001": {"state": "open",
                                                                                   "note": "release solve when?"}}):
            with self.assertRaises(drive.DriveError):  # an ask must name the commit too: the key carries it
                drive.respond(self.home, "solve", "MERGED_NOT_RELEASED", "ask", "w00000000001", now=NOW)
            with self.assertRaises(drive.DriveError):
                drive.respond(self.home, "solve", "MERGED_NOT_RELEASED", "ask", "w00000000001",
                              detail="0123456789ab", now=NOW)
            asked = drive.respond(self.home, "solve", "MERGED_NOT_RELEASED", "ask", "w00000000001",
                                  detail=first[:12], now=NOW)
        snap = {"at": NOW - 10, "rows": [{"goal": "solve", "actions": [dict(act, since=NOW - 10)]}]}
        self.assertEqual(drive.unanswered(snap, [asked], NOW + 5), [])  # the accepted ask clears the action
        self.assertEqual(len(drive.unanswered(snap, [], NOW + 5)), 1)
        row = self.respond("MERGED_NOT_RELEASED", "goodqa#43", first[:12])  # control
        self.assertEqual(row["key"], f"solve:MERGED_NOT_RELEASED:{first[:12]}")
        second = self.commit("fix(x): two\n\nRefs: GoodQA goodqa#11")
        subprocess.run(["git", "-C", str(self.repo), "update-ref", "refs/remotes/origin/main", "HEAD"], check=True)
        a = drive.assess(self.home, MISSION, time.time(), owner_rows=[])
        keys = [x["key"] for x in self.row(a, "solve")["actions"]]
        self.assertIn(f"solve:MERGED_NOT_RELEASED:{second[:12]}", keys)  # a newer merge is a new, unanswered action
        with self.assertRaises(drive.DriveError):
            self.respond("MERGED_NOT_RELEASED", "goodqa#43", second[:12])


    def test_response_lapse_voids_ticket_at_next_full_tick(self):
        """Receipt v7 F1 (class): a ticket that answered an action and is later closed, retitled, missing or
        unknown no longer answers it; the full tick voids the response and the action is required again."""
        self.tickets["goodqa#30"] = {"state": "open", "title": "[drive:solve:t1] redesign the login flow"}
        now = time.time()
        row = drive.respond(self.home, "solve", "REVIEW_LOOP", "ticket", "goodqa#30", detail="t1", now=now,
                            ticket_check=self.lookup)
        snap = drive.tick(self.home, MISSION, now=now + 5, owner_rows=[], ticket_check=self.lookup)
        keys = {a["key"] for r in snap["rows"] for a in r["actions"]}
        self.assertIn("solve:REVIEW_LOOP:t1", keys)
        self.assertEqual(snap["void"], [])  # still open with its marker: still answers
        self.assertNotIn("solve:REVIEW_LOOP:t1", {a["key"] for a in drive.unanswered(snap, [row], now + 6)})
        for i, lapsed in enumerate(({"state": "closed", "title": "[drive:solve:t1] redesign the login flow"},
                                    {"state": "open", "title": "redesign the login flow"},
                                    {"state": "missing"}, {"state": None, "title": "[drive:solve:t1] x"})):
            self.tickets["goodqa#30"] = lapsed
            snap = drive.tick(self.home, MISSION, now=now + 10 + i, owner_rows=[], ticket_check=self.lookup)
            self.assertEqual(snap["void"], [[row["key"], row["ts"]]], lapsed)
            self.assertTrue(drive._signed_ok(self.home, snap))  # the void list is inside the signature
            self.assertIn("solve:REVIEW_LOOP:t1",
                          {a["key"] for a in drive.unanswered(snap, drive.read_responses(self.home), now + 20)})

    def test_response_lapse_voids_ask_no_longer_open(self):
        import mission_coverage as mc
        asks = {"w00000000001": {"state": "open", "note": "solve: grant for the deploy key"}}
        now = time.time()
        with mock.patch.object(mc, "ask_states", lambda h, s: asks):
            row = drive.respond(self.home, "solve", "HELP_OPEN", "ask", "w00000000001", detail="t2", now=now)
            snap = {"at": now, "rows": [{"goal": "solve", "actions": [
                {"key": row["key"], "cond": "HELP_OPEN", "since": now - 5, "action": "x"}]}]}
            self.assertEqual(drive.lapsed_responses(self.home, snap, [row], now + 5, MISSION), [])
            asks["w00000000001"] = {"state": "resolved", "note": ""}
            void = drive.lapsed_responses(self.home, snap, [row], now + 5, MISSION)
        self.assertEqual(void, [[row["key"], row["ts"]]])
        self.assertEqual(len(drive.unanswered(dict(snap, void=void), [row], now + 6)), 1)
        with mock.patch.object(mc, "ask_states", side_effect=RuntimeError("wal unreadable")):  # unknown: lapsed
            self.assertEqual(drive.lapsed_responses(self.home, snap, [row], now + 5, MISSION), void)

    def test_partial_view_keeps_the_last_void(self):
        prev = {"void": [["solve:REVIEW_LOOP:t1", 1.0]], "rows": []}
        a = drive.with_episodes(self.home, {"at": NOW, "rows": []}, prev=prev, responses=[])
        self.assertEqual(a["void"], [["solve:REVIEW_LOOP:t1", 1.0]])

class NewConditionTests(Base):
    def test_condition_owners_unknown_never_claims_unowned(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=None, with_git=False)
        self.assertNotIn("UNOWNED", self.conds(a, "solve"))
        self.assertIn("unknown", self.row(a, "solve")["owner"])

    def test_condition_blocked_user_and_release_check_off(self):
        self.goals[0]["deferral"] = {"by": "ask", "ref": "w00000000001"}
        self.goals[0]["repos"] = []
        self.write_goals()
        conds = self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), "solve")
        self.assertIn("BLOCKED_USER", conds)
        self.assertIn("RELEASE_CHECK_OFF", conds)
        self.assertIn("UNOWNED", conds)  # blocked on the user never excuses an ownerless goal

    def test_condition_legacy_owner_stalled(self):
        with mock.patch.object(drive, "legacy_owners", side_effect=lambda h, s, g, r: ["a1234567890abcdef0"]
                               if g["id"] == "solve" else []), \
                mock.patch.object(drive, "legacy_progress", return_value=NOW - 31 * 60):
            self.assertEqual(self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False),
                                        "solve"), ["STALLED"])

    def test_condition_full_cap_names_a_lane_owner(self):
        import mission_coverage as mc
        rows = [{"agent_id": "a1234567890abcdef0"}]
        with mock.patch.object(mc, "owner_cap", return_value=1), mock.patch.object(mc, "live_owner",
                                                                                   return_value=True):
            text = drive.unowned_action("solve", rows)
        self.assertIn("add a lane to live owner a1234567890abcdef", text)


class LegacyOwnerTests(Base):
    """The real matcher (mission_coverage.live_owner + _matches), not a mock (red-team r1 m7)."""

    def rows(self, **over):
        row = {"agent_id": "a1234567890abcdef0", "type": "task-owner", "state": "live", "ticket": "GoodQA goodqa#11"}
        row.update(over)
        return [row]

    def test_legacy_live_owner_by_ticket_counts(self):
        self.assertNotIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=self.rows(),
                                                            with_git=False), "solve"))

    def test_legacy_dead_helper_or_other_ticket_does_not_count(self):
        for over in ({"state": "DROPPED"}, {"type": "red-team"}, {"ticket": "GoodQA goodqa#999"}):
            conds = self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=self.rows(**over), with_git=False),
                               "solve")
            self.assertIn("UNOWNED", conds, over)

    def test_legacy_bound_agent_counts(self):
        self.goals[0]["bound"] = ["a1234567890abcdef0"]
        self.write_goals()
        rows = self.rows(ticket="")
        self.assertNotIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=rows,
                                                            with_git=False), "solve"))


class StopTests(Base):
    def payload(self, sid=MISSION):
        return {"session_id": sid, "hook_event_name": "Stop"}

    def test_stop_blocks_main_then_allows_after_response(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        out = drive.stop_decision(self.home, self.payload(), now=NOW + 1, is_main=True)
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("solve UNOWNED", out["reason"])
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl", drive._sign(self.home, {"key": key, "ts": NOW + 2}))
        self.assertEqual(drive.stop_decision(self.home, self.payload(), now=NOW + 3, is_main=True), {})

    def test_stop_non_main_or_other_session_never_blocked(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        self.assertEqual(drive.stop_decision(self.home, self.payload(), now=NOW, is_main=False), {})
        self.assertEqual(drive.stop_decision(self.home, self.payload("ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"),
                                             now=NOW, is_main=True), {})

    def test_stop_bounded_valve_keeps_action_open(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        with mock.patch.object(drive, "_ring") as ring:
            outs = [drive.stop_decision(self.home, self.payload(), now=NOW + i, is_main=True) for i in range(5)]
        self.assertEqual([o.get("decision") for o in outs].count("block"), drive.MAX_STOP_BLOCKS)
        self.assertIn("block budget spent", outs[-1]["systemMessage"])
        self.assertTrue(any(c.args[1] == "raise" for c in ring.call_args_list))

    def test_stop_stale_path_keeps_episode_so_responses_count(self):
        out = drive.stop_decision(self.home, {"session_id": MISSION}, now=NOW, is_main=True)  # no tick snapshot
        self.assertEqual(out.get("decision"), "block")
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl", drive._sign(self.home, {"key": key, "ts": NOW + 1}))
        for t in (2, 60, 600):  # r1 M6: before the fix the episode restarted on every Stop
            self.assertEqual(drive.stop_decision(self.home, {"session_id": MISSION}, now=NOW + t, is_main=True), {},
                             t)

    def test_stop_stale_full_snapshot_keeps_new_episodes(self):
        """Delta D2: once a full tick snapshot goes stale, a new action's episode still persists across Stops."""
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        later = NOW + drive.SNAPSHOT_MAX_S + 60
        self.goals[0]["repos"] = []  # same goal set; a new RELEASE_CHECK_OFF action appears after the tick
        self.write_goals()
        self.assertIsNotNone(drive.load_snapshot(self.home))  # the stale full snapshot is still a valid one
        out = drive.stop_decision(self.home, {"session_id": MISSION}, now=later, is_main=True)
        self.assertEqual(out.get("decision"), "block")
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl",
                        drive._sign(self.home, {"key": key, "ts": later + 1}))
        self.assertIn("solve:RELEASE_CHECK_OFF", [a["key"] for r in drive.load_snapshot(self.home)["rows"]
                                                  for a in r["actions"]])
        for t in (5, 120):
            self.assertEqual(drive.stop_decision(self.home, {"session_id": MISSION}, now=later + t, is_main=True),
                             {}, t)

    def test_response_before_any_snapshot_saw_condition_counts(self):
        """Delta D2 (probe): a valid respond made before drive's snapshot had the key answers that episode, once."""
        self.owner()
        st = ort.load_state(self.home, "solve")
        st["last_beat"], st["launches"] = {"ts": NOW}, [{"ts": NOW, "code": 0}]
        ort.save_state(self.home, "solve", st)
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        later = NOW + 45 * 60  # snapshot stale; the owner is now STALLED, a key no snapshot has yet
        st["launches"].append({"ts": later, "code": 0})
        ort.save_state(self.home, "solve", st)
        drive.respond(self.home, "solve", "STALLED", "owner", now=later)
        for t in (5, 120):
            out = drive.stop_decision(self.home, {"session_id": MISSION}, now=later + t, is_main=True)
            self.assertNotIn("solve STALLED", json.dumps(out), t)
        # a pre-episode response older than the one-hour window never anchors a new episode
        snap = {"at": later + 4000, "rows": [{"goal": "solve", "actions": [{"key": "solve:NEWTHING"}]}]}
        old = [{"key": "solve:NEWTHING", "ts": later, "pre": True}]
        self.assertEqual(drive.with_episodes(self.home, snap, prev={}, responses=old)["rows"][0]["actions"][0]["since"],
                         later + 4000)

    def test_partial_view_carries_unseen_episodes_until_full_tick(self):
        snap = {"at": NOW, "rows": [{"goal": "solve", "actions": [{"key": "solve:MERGED_NOT_RELEASED",
                                                                   "since": NOW - 500}]}]}
        live = drive.with_episodes(self.home, {"at": NOW + 10, "rows": [{"goal": "solve", "actions": []}]}, prev=snap)
        self.assertEqual(live["carry"], {"solve:MERGED_NOT_RELEASED": NOW - 500})
        again = drive.with_episodes(self.home, {"at": NOW + 20, "rows": [
            {"goal": "solve", "actions": [{"key": "solve:MERGED_NOT_RELEASED"}]}]}, prev=live)
        self.assertEqual(again["rows"][0]["actions"][0]["since"], NOW - 500)
        full = drive.tick(self.home, MISSION, now=NOW + 30, owner_rows=[])
        self.assertEqual(full["carry"], {})

    def test_stop_stale_snapshot_still_checks(self):
        out = drive.stop_decision(self.home, self.payload(), now=NOW, is_main=True)  # no snapshot at all
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("stale", out["reason"])

    def test_stop_internal_error_fails_open(self):
        import io
        with mock.patch.object(drive, "stop_decision", side_effect=RuntimeError("x")), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(drive.cmd_stop(io.StringIO(json.dumps(self.payload()))), 0)
        self.assertNotIn('"block"', out.getvalue())


class OpsWatchTests(Base):
    def test_ops_watch_alerts_one_per_unanswered_action(self):
        with mock.patch.object(ort, "tick", return_value=[{"goal": "solve", "action": "stuck", "reason": "x"}]):
            alerts = drive.ops_alerts(self.home, now=NOW)
        keys = [a["key"] for a in alerts]
        self.assertIn("owner:solve:stuck", keys)
        self.assertIn("drive:solve:UNOWNED", keys)
        self.assertIn("drive:leads:IMPORTED", keys)
        self.assertTrue(all(a["severity"] == "high" for a in alerts))


class McTests(Base):
    def test_mc_api_state_carries_drive_rows(self):
        sys.path.insert(0, str(HOOKS.parent / "mission_control"))
        with mock.patch.dict(os.environ, {"MC_HOOKS": str(HOOKS)}):
            import server  # noqa: PLC0415
        drive.tick(self.home, MISSION, now=time.time(), owner_rows=[])
        fake = type("S", (), {"demo": False})()
        cls = next(v for v in vars(server).values() if isinstance(v, type) and "drive_snapshot" in vars(v))
        out = cls.drive_snapshot(fake)
        self.assertEqual(out["state"], "ok")
        self.assertEqual(sorted(r["goal"] for r in out["rows"]), ["leads", "old", "pp", "solve"])
        solve = next(r for r in out["rows"] if r["goal"] == "solve")
        self.assertTrue(solve["actions"][0]["required"])


if __name__ == "__main__":
    unittest.main()
