"""goodqa#17156 (INC 1c): the recorded supervisor's reviewer-only top-rung grant.

Source: queue:1eaed05e-9884-44ca-a537-09a25d215e7c/2026-11-24T22:35:40.582Z#3862575e22f5 "create another script that
adds reviewer-level grant abilities so citations from supervisor are sufficient". The grant covers a peer_review.py
reviewer run at a rung that needs the user's permission and nothing else: every writer path keeps reading only the
user's own `permission` record. Each class names the acceptance criterion it proves (spec-inc1c.md).

Run: python3 -I -m unittest tests.test_grant_reviewer
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent / "harness" / "hooks"
AH = HOOKS / "ah.py"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))
import escalation as esc  # noqa: E402
import model_tiers as tiers  # noqa: E402
import supervisor as sv  # noqa: E402
import tier_gate as gate  # noqa: E402
import top_assent_fixture as fx  # noqa: E402

SUP = "1eaed05e-9884-44ca-a537-09a25d215e7c"
OTHER = "76b72de0-6bb7-47e2-bdf6-7e18a3b290dc"
UID = "a158ca26-0ba7-4d64-b60a-569d5d6ac9c2"
TAKE_OVER = "check the most recent session that was acting as a supervisor to several sub-sessions, take over/become it"
LATER = ("create another script that adds reviewer-level grant abilities so citations from supervisor are sufficient",
         "add a script that adds checkout-cleanup/removal abilities so supervisor may ok such cleanups")
TICKET = "GoodQA goodqa#17156"
REASON = "TIMBAR finish PR 41 needs the top-rung reviewer before merge"
STANDING = """# rules

<!-- supervisor-standing-authority:begin -->
## Supervisor standing authority (mine)

- **Merge and push:** the supervisor may merge a pull request.
- **Top rung:** the supervisor may grant Fable or Astra as the reviewer for a named task in a supervised project and
  record that grant itself. Using them as writers still needs my own words for the task.
<!-- supervisor-standing-authority:end -->
"""
T0 = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc).timestamp()


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="grant-reviewer-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home"
        self.claude = self.home / ".claude"
        self.claude.mkdir(parents=True)
        self.root = Path(self.temp.name) / "ledger"
        self.root.mkdir(mode=0o700)
        self.wals = self.claude / "wals"
        (self.wals / SUP).mkdir(parents=True)
        (self.wals / OTHER).mkdir(parents=True)
        self.wal = self.wals / SUP / "main.jsonl"
        self.wal.write_text("")
        (self.wals / OTHER / "main.jsonl").write_text("")
        self.env = mock.patch.dict(os.environ, {"AGENT_HARNESS_ESCALATION_DIR": str(self.root),
                                                "AGENT_HARNESS_WALS_DIR": str(self.wals), "HOME": str(self.home),
                                                "AH_HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(self.claude)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.policy = tiers.load_policy()
        self.ledger = esc.Ledger(self.root, self.policy)
        (self.claude / "CLAUDE.md").write_text(STANDING)
        self.rows = []

    # -- helpers
    def source(self, words=TAKE_OVER, session=SUP, uid=UID, excerpt=None):
        return fx.user_turn(self.claude, words, session=session, uid=uid, excerpt=excerpt)

    def make_supervisor(self, session=SUP):
        return sv.set_supervisor(self.ledger, session, self.source(session=session), session)

    def row(self, note, source):
        """The WAL decision row, as ah's wal_note call writes it; returns its id."""
        wid = "w%011x" % (len(self.rows) + 1)
        record = {"id": wid, "event": "decision", "note": note, "source": source}
        with self.wal.open("a") as out:
            out.write(json.dumps(record) + "\n")
        self.rows.append(record)
        return wid

    def grant(self, **kw):
        args = dict(stamp_session=SUP, task="t1", reason=REASON, ticket=TICKET, wal=self.wal, self_authored=False,
                    hours=168, write_row=self.row, at_ts=T0)
        args.update(kw)
        return sv.grant_review(self.ledger, **args)

    def state_with(self, task, *grants, **extra):
        state = self.ledger.fresh(task)
        state["review_grants"] = list(grants)
        state.update(extra)
        (self.root / (task + ".json")).write_text(json.dumps(state))
        return state

    def a_grant(self, task="t1", **kw):
        grant = {"id": "rg-0123456789ab", "task": task, "scope": "review", "rungs": ["R5", "R6"], "by": SUP,
                 "at": "2026-11-24T12:00:00+00:00", "expires_at": "2026-12-01T12:00:00+00:00"}
        grant.update(kw)
        return grant


class MarkerCheck(Base):
    """AC-5, NEG-2: the standing-authority block must be present, whole-line, in a regular file this user owns."""

    def problem(self, text=None):
        if text is not None:
            path = self.claude / "CLAUDE.md"
            path.unlink()
            path.write_text(text)
        return sv.marker_problem(self.claude)

    def test_the_real_block_shape_passes(self):
        self.assertIsNone(self.problem())

    def test_each_broken_shape_is_refused_with_its_reason(self):
        cases = {
            "no begin line": STANDING.replace(sv.MARKER_BEGIN, "<!-- other -->"),
            "no end line": STANDING.replace(sv.MARKER_END, "<!-- other -->"),
            "no Top rung item": STANDING.replace("**Top rung:**", "**Bottom rung:**"),
        }
        for expected, text in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.problem(text) or "")
        inside = STANDING.replace(sv.MARKER_BEGIN + "\n", "see " + sv.MARKER_BEGIN + " here\n")
        self.assertIn("no begin line", self.problem(inside) or "")  # a marker inside a longer line is not a marker
        swapped = "x\n%s\n- **Top rung:** reviewer\n%s\n" % (sv.MARKER_END, sv.MARKER_BEGIN)
        self.assertIn("after the begin line", self.problem(swapped) or "")
        reviewer_elsewhere = STANDING.replace("as the reviewer", "as the author")
        self.assertIn("no Top rung item", self.problem(reviewer_elsewhere) or "")

    def test_missing_symlinked_fifo_and_foreign_files_are_refused(self):
        real = self.claude / "CLAUDE.md"
        planted = Path(self.temp.name) / "planted.md"
        planted.write_text(STANDING)
        real.unlink()
        self.assertIn("does not exist", sv.marker_problem(self.claude) or "")
        real.symlink_to(planted)
        self.assertIn("is a symlink", sv.marker_problem(self.claude) or "")
        real.unlink()
        os.mkfifo(real)
        self.assertIn("not a regular file", sv.marker_problem(self.claude) or "")
        real.unlink()
        real.write_text(STANDING)
        with mock.patch.object(sv.os, "getuid", return_value=os.getuid() + 1):
            self.assertIn("not owned by this user", sv.marker_problem(self.claude) or "")
        real.write_text(STANDING + "x" * sv.CLAUDE_MD_MAX)
        self.assertIn("larger than", sv.marker_problem(self.claude) or "")

    def test_the_installed_ledger_reads_the_installed_claude_md_only(self):
        # CLAUDE_CONFIG_DIR points at a planted file; the installed ledger must ignore it (advisor point 4).
        with mock.patch.object(esc, "DEFAULT_ROOT", self.root), \
                mock.patch.object(esc, "installed_home", return_value=Path(self.temp.name) / "elsewhere"):
            self.assertEqual(sv.claude_home(self.ledger), Path(self.temp.name) / "elsewhere" / ".claude")
            self.make_supervisor_installed = None
            with self.assertRaises(sv.SupervisorError) as caught:
                self.grant()
        self.assertEqual(caught.exception.code, "no_standing_authority")


class SupervisorSet(Base):
    """AC-4, NEG-7, NEG-8: only the user's own words to that session make it the supervisor."""

    def test_the_real_take_over_sentence_sets_the_supervisor_and_later_mentions_do_not_void_it(self):
        record = sv.set_supervisor(self.ledger, SUP, self.source(), SUP, later_texts=LATER)
        self.assertEqual(record["session"], SUP)
        self.assertEqual(sv.current_supervisor(self.ledger)["session"], SUP)
        self.assertEqual([r["event"] for r in sv.audit_rows(self.ledger)], ["supervisor-set"])

    def test_refusals(self):
        cases = [
            ("do not supervise anything for now", "plain sentence"),
            ("if you can, take over as supervisor", "plain sentence"),
            ("can you become the supervisor?", "plain sentence"),
            ("the supervisor session crashed again", "plain sentence"),
        ]
        for n, (words, expected) in enumerate(cases):
            with self.subTest(words=words):
                src = self.source(words, uid="00000000-0000-4000-8000-%012d" % n)
                with self.assertRaises(sv.SupervisorError) as caught:
                    sv.set_supervisor(self.ledger, SUP, src, SUP)
                self.assertIn(expected, caught.exception.message)
        self.assertIsNone(sv.current_supervisor(self.ledger))

    def test_a_later_message_that_ends_supervision_voids_it(self):
        with self.assertRaises(sv.SupervisorError) as caught:
            sv.set_supervisor(self.ledger, SUP, self.source(), SUP, later_texts=("stop supervising, I am back",))
        self.assertIn("latest words decide", caught.exception.message)

    def test_words_from_another_sessions_transcript_cannot_set_this_session(self):  # NEG-8
        src = self.source(session=OTHER)
        with self.assertRaises(sv.SupervisorError) as caught:
            sv.set_supervisor(self.ledger, SUP, src, SUP)
        self.assertIn("belong to session", caught.exception.message)

    def test_session_ids_compare_in_lower_case_and_a_lookalike_is_refused(self):  # NEG-7
        record = sv.set_supervisor(self.ledger, SUP.upper(), self.source(), SUP)
        self.assertEqual(record["session"], SUP)
        with self.assertRaises(sv.SupervisorError):
            sv.set_supervisor(self.ledger, SUP[:-1] + "d", self.source(), SUP)

    def test_an_excerpt_outside_the_sentence_and_a_non_user_source_are_refused(self):
        words = "the blog looks fine. take over as the supervisor now"
        with self.assertRaises(sv.SupervisorError) as caught:
            sv.set_supervisor(self.ledger, SUP, self.source(words, excerpt="the blog looks fine"), SUP)
        self.assertIn("not part of that sentence", caught.exception.message)
        with self.assertRaises(sv.SupervisorError) as caught:
            sv.set_supervisor(self.ledger, SUP, "ticket:GoodQA goodqa#17156", SUP)
        self.assertIn("user's own words", caught.exception.message)

    def test_a_second_set_replaces_the_first_and_names_it(self):
        self.make_supervisor(SUP)
        record = sv.set_supervisor(self.ledger, OTHER, self.source(session=OTHER), OTHER)
        self.assertEqual(record["replaced"], SUP)
        self.assertEqual(sv.current_supervisor(self.ledger)["session"], OTHER)

    def test_the_installed_ledger_ignores_the_environment_transcript_root(self):
        src = self.source()
        with mock.patch.object(esc, "DEFAULT_ROOT", self.root), \
                mock.patch.object(esc, "installed_home", return_value=Path(self.temp.name) / "elsewhere"):
            with self.assertRaises(sv.SupervisorError) as caught:
                sv.set_supervisor(self.ledger, SUP, src, SUP)
        self.assertIn("could not be read", caught.exception.message)


class GrantRules(Base):
    """AC-3, AC-6, AC-8, NEG-4 to NEG-6, NEG-11."""

    def setUp(self):
        super().setUp()
        self.make_supervisor()

    def assert_refused(self, code, **kw):
        before = self.wal.read_text()
        with self.assertRaises(sv.SupervisorError) as caught:
            self.grant(**kw)
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        self.assertEqual(self.wal.read_text(), before)  # nothing written to the WAL
        self.assertFalse(sv.list_grants(self.ledger))  # nor to the ledger
        return caught.exception.message

    def test_a_grant_writes_the_wal_row_first_and_names_it(self):  # AC-8
        grant = self.grant()
        row = json.loads(self.wal.read_text().splitlines()[-1])
        self.assertEqual(grant["wal_row"], row["id"])
        self.assertEqual(grant["source"], "supervisor:%s/%s" % (SUP, row["id"]))
        self.assertEqual(row["source"], "ticket:" + TICKET)
        self.assertIn("[task:t1]", row["note"])
        self.assertIn("never a writer", row["note"])
        self.assertIn("not detected (best effort)", row["note"])
        self.assertEqual((grant["scope"], grant["rungs"], grant["by"]), ("review", ["R5", "R6"], SUP))
        state = self.ledger.load("t1")
        self.assertIsNone(state["permission"])  # the user permission slot is untouched
        self.assertEqual([g["id"] for g in state["review_grants"]], [grant["id"]])

    def test_only_the_recorded_supervisor_main_session_grants(self):  # AC-3
        self.assertIn("hook stamps", self.assert_refused("main_only", stamp_session=None))
        self.assertIn("not the recorded supervisor", self.assert_refused("not_supervisor", stamp_session=OTHER))
        (self.root / "supervisor" / "supervisor.json").unlink()
        self.assertIn("ah supervisor set", self.assert_refused("no_supervisor"))

    def test_the_standing_authority_must_be_in_claude_md(self):
        (self.claude / "CLAUDE.md").write_text("# rules\n")
        self.assertIn("supervisor-standing-authority", self.assert_refused("no_standing_authority"))

    def test_argument_refusals(self):  # AC-6, NEG-11
        self.assert_refused("bad_request", task="t1 t2")
        self.assert_refused("bad_request", task="*")
        self.assert_refused("bad_request", reason="too short")
        self.assert_refused("bad_request", reason="token ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8 for the reviewer")
        self.assert_refused("bad_request", ticket="goodqa#17156")
        self.assert_refused("bad_request", hours=169)
        self.assert_refused("bad_request", hours=0)
        self.assert_refused("bad_request", wal=self.wals / OTHER / "main.jsonl")
        self.assertEqual(self.grant(hours=168)["expires_at"], "2026-12-01T12:00:00+00:00")

    def test_a_self_authored_task_needs_the_flag_and_the_row_says_so(self):  # AC-6
        sub = self.claude / "projects" / "-proj" / SUP / "subagents"
        sub.mkdir(parents=True)
        (sub / "agent-a1b2c3.jsonl").write_text("{}\n")
        self.state_with("t1", dispatches=[{"agent_id": "a1b2c3", "kind": "agent", "status": "ended"}])
        self.assertIn("--self-authored", self.assert_refused("self_authored"))
        grant = self.grant(self_authored=True)
        self.assertTrue(grant["self_authored"] and grant["self_authored_detected"])
        self.assertIn("self-authored (declared, detected)", self.rows[-1]["note"])

    def test_ten_grants_a_day_then_refused_and_a_new_utc_day_is_allowed(self):  # AC-6
        for n in range(sv.DAILY_CAP):
            self.grant(task="t%d" % n, at_ts=T0 + n)
        with self.assertRaises(sv.SupervisorError) as caught:
            self.grant(task="t99", at_ts=T0 + 100)
        self.assertEqual(caught.exception.code, "daily_cap")
        self.assertEqual(self.grant(task="t99", at_ts=T0 + 12 * 3600 + 1)["task"], "t99")  # 00:00:01Z next day

    def test_the_stamp_is_bound_to_every_argument(self):  # NEG-4
        base = sv.stamp_parts_grant("t1", REASON, TICKET, self.wal, False, 168)
        for changed in (("t2", REASON, TICKET, self.wal, False, 168), ("t1", REASON + ".", TICKET, self.wal, False, 168),
                        ("t1", REASON, "GoodQA goodqa#1", self.wal, False, 168),
                        ("t1", REASON, TICKET, self.wals / OTHER / "main.jsonl", False, 168),
                        ("t1", REASON, TICKET, self.wal, True, 168), ("t1", REASON, TICKET, self.wal, False, 24)):
            with self.subTest(changed=changed[:2]):
                self.assertNotEqual(sv.stamp_parts_grant(*changed), base)
        self.assertNotEqual(sv.stamp_parts_set(SUP, "a"), sv.stamp_parts_set(SUP, "b"))

    def test_two_grants_for_one_task_are_two_and_both_count(self):  # NEG-6
        first, second = self.grant(), self.grant(at_ts=T0 + 1)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(len(sv.list_grants(self.ledger, T0 + 2)), 2)


class LiveGrant(Base):
    """AC-1 (the deciding reader), NEG-3, NEG-5."""

    def live(self, state, rung="R6", t=None):
        return esc.live_review_grant(state, rung, self.policy, now_ts=T0 + 60 if t is None else t)

    def test_each_condition_of_a_live_grant(self):
        good = self.a_grant()
        state = self.state_with("t1", good)
        self.assertEqual(self.live(state)["id"], good["id"])
        self.assertEqual(self.live(state, "R5")["id"], good["id"])
        self.assertIsNone(self.live(state, "R4"))  # a rung that needs no permission is not a grant use
        for bad in (dict(good, scope="writer"), dict(good, task="t2"), dict(good, rungs=["R4"]), dict(good, rungs="R6"),
                    dict(good, revoked_at="2026-11-24T12:30:00+00:00"), dict(good, at="nonsense")):
            with self.subTest(bad=json.dumps({k: v for k, v in bad.items() if good.get(k) != v})):
                self.assertIsNone(self.live(self.state_with("t1", bad)))
        end = esc._grant_time(good["expires_at"])
        self.assertIsNotNone(self.live(state, t=end - 1))
        self.assertIsNone(self.live(state, t=end))  # NEG-5: expired at the boundary
        self.assertIsNone(self.live(state, t=esc._grant_time(good["at"]) - 1))

    def test_a_reset_keeps_grants_and_their_revokes(self):  # NEG-5 grant-durability
        self.state_with("t1", self.a_grant(), self.a_grant(id="rg-111111111111", revoked_at="2026-11-24T12:01:00+00:00"))
        self.ledger.reset("t1", "state_corrupt", "test")
        grants = self.ledger.load("t1")["review_grants"]
        self.assertEqual([g["id"] for g in grants], ["rg-0123456789ab", "rg-111111111111"])
        self.assertIsNotNone(self.live(self.ledger.load("t1")))
        self.assertTrue(grants[1]["revoked_at"])

    def test_add_review_grant_refuses_a_writer_scope_or_another_task(self):
        for bad in (self.a_grant(scope="writer"), self.a_grant(task="t2")):
            with self.assertRaises(esc.LedgerError):
                self.ledger.add_review_grant("t1", bad)


class WriterPathsRefuse(Base):
    """AC-2: a state holding only a live review grant satisfies no writer path, while the reviewer launch passes."""

    def setUp(self):
        super().setUp()
        far = "2099-01-01T00:00:00+00:00"
        self.state_with("t1", self.a_grant(at="2026-01-01T00:00:00+00:00", expires_at=far),
                        events=[])

    def bash(self, command):
        return gate.decide_bash({"tool_name": "Bash", "tool_input": {"command": command}}, self.policy, self.ledger)

    def test_status_permission_stays_empty(self):
        self.assertIsNone(self.ledger.status("t1")["permission"])
        self.assertNotIn("review_grants", self.ledger.status("t1"))

    def test_tier_gate_denies_writer_launches_and_spawns(self):
        decision, reason, _, _ = self.bash("claude -p --model fable --task t1 x")
        self.assertEqual(decision, "deny")
        self.assertIn("needs the user permission", reason)
        decision, reason, _, _ = self.bash("codex exec --model gpt-6-astra --task t1 -")
        self.assertEqual(decision, "deny")
        spawn = gate.decide_spawn({"tool_name": "Agent", "session_id": SUP, "tool_input": {
            "prompt": "fix it", "description": "owner [task:t1]", "subagent_type": "task-owner", "model": "fable"}},
            self.policy, self.ledger, session_id=SUP)
        self.assertEqual(spawn[0], "deny")

    def test_tier_gate_lets_the_peer_review_launch_through_on_the_grant(self):
        line = "python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task t1 --author-rung R5"
        decision, reason, _, facts = self.bash(line)
        self.assertNotEqual(decision, "deny", reason)
        self.assertEqual(facts.get("review_grant"), "rg-0123456789ab")
        self.state_with("t1", self.a_grant(expires_at="2026-11-24T12:00:01+00:00"))  # NEG-10: expired
        decision, reason, _, _ = self.bash(line)
        self.assertEqual(decision, "deny")
        self.assertIn("ah grant-reviewer --task t1", reason)

    def test_rescue_and_central_publish_see_no_permission(self):
        import central_decisions as cd
        import rescue
        self.assertIsNone(rescue.rescue_rung(self.policy, "t1", None)[1])
        with self.assertRaises(cd.Denied) as caught:
            cd.publish("t1", ledger=self.ledger, test_mode=True)
        self.assertEqual(caught.exception.code, "no_local_permission")

    @unittest.skipUnless((Path.home() / ".claude" / "hooks" / "codex_pool.py").is_file() or
                         (esc.installed_home() / ".claude" / "hooks" / "codex_pool.py").is_file(),
                         "codex_pool.py is installed only; not on this host")
    def test_installed_codex_pool_sees_no_astra_approval(self):
        import importlib.util
        path = esc.installed_home() / ".claude" / "hooks" / "codex_pool.py"
        spec = importlib.util.spec_from_file_location("codex_pool_installed", path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as error:  # noqa: BLE001
            self.skipTest("installed codex_pool does not import here: %s" % type(error).__name__)
        self.assertFalse(module.astra_approved("t1"))


class ReaderContract(Base):
    """AC-2: every reader of `permission` and `review_grants` is classified, by AST, in the repo and installed dir."""

    def test_every_repo_reader_is_classified_and_no_entry_is_stale(self):
        rows = sv.scan(HOOKS)
        self.assertEqual([r for r in rows if r[3] is None], [])
        found = {(name, qualname, what) for name, qualname, what, _ in rows}
        for name, entries in sv.CLASSIFIED.items():
            for qualname, what in entries:
                with self.subTest(entry=(name, qualname, what)):
                    self.assertIn((name, qualname, what), found)  # a stale entry would hide a moved reader

    def doctored(self, name, source):
        self.folders = getattr(self, "folders", 0) + 1
        folder = Path(self.temp.name) / ("doctored%d" % self.folders)
        folder.mkdir()
        (folder / name).write_text(source)
        return sv.scan(folder)

    def test_a_new_reader_is_reported(self):
        rows = self.doctored("tier_gate.py", "def newer(status):\n    return bool(status.get('permission'))\n")
        self.assertEqual([(r[1], r[2], r[3]) for r in rows], [("newer", "get:permission", None)])
        rows = self.doctored("rescue.py", "def sneaky(s, p):\n    return esc.live_review_grant(s, 'R5', p)\n")
        self.assertEqual([r[3] for r in rows], [None])  # only the two reviewer checks may call it
        rows = self.doctored("other.py", "def f(state):\n    return state['review_grants']\n")
        self.assertEqual([r[3] for r in rows], [None])

    def test_the_installed_only_codex_pool_reader_is_classified(self):
        rows = self.doctored("codex_pool.py", "def astra_approved(task):\n    return bool(L().load(task).get('permission'))\n")
        self.assertEqual(rows[0][3], sv.INSTALLED_ONLY["codex_pool.py"][("astra_approved", "get:permission")])

    def test_the_readers_cli_exits_1_on_an_unclassified_reader(self):
        self.doctored("tier_gate.py", "def newer(status):\n    return status['permission']\n")
        done = subprocess.run([sys.executable, "-I", str(HOOKS / "supervisor.py"), "readers",
                               str(Path(self.temp.name) / ("doctored%d" % self.folders))], capture_output=True, text=True,
                              timeout=60)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("UNCLASSIFIED", done.stdout)


class StatusAndRevoke(Base):
    """AC-7, NEG-9: grants are listed with grantor, reason, ticket and expiry, and a revoke takes effect at once."""

    def setUp(self):
        super().setUp()
        self.make_supervisor()

    def test_list_status_and_revoke(self):
        import ah
        grant = self.grant(at_ts=sv.now_ts())
        (self.wals / SUP / "main.jsonl").write_text(json.dumps({"id": "w1", "event": "note", "at": "2026-11-24T12:00:00Z"}) + "\n")
        data = ah.status_report(self.home, SUP, 3600)
        text = ah.status_text(data)
        self.assertIn("## SUPERVISOR " + SUP, text)
        self.assertIn("live     %s [task:t1] by %s" % (grant["id"], SUP[:8]), text)
        self.assertIn("never an Agent-spawned reviewer", text)  # D1 stated in the output
        sv.revoke(self.ledger, grant["id"], "claimed session x")
        self.assertIsNone(esc.live_review_grant(self.ledger.load("t1"), "R6", self.policy))
        listed = sv.list_grants(self.ledger)
        self.assertEqual((listed[0]["state"], listed[0]["revoked_by"]), ("revoked", "claimed session x"))
        self.assertEqual([r["event"] for r in sv.audit_rows(self.ledger)], ["supervisor-set", "grant", "revoke"])

    def test_a_deleted_record_shows_no_supervisor_and_the_audit_keeps_the_history(self):  # NEG-9
        self.grant()
        (self.root / "supervisor" / "supervisor.json").unlink()
        summary = sv.summary(self.ledger)
        self.assertIsNone(summary["supervisor"])
        self.assertEqual(summary["supervisor_sets_audited"], 1)
        self.assertEqual(len(summary["grants"]), 1)


class EndToEnd(Base):
    """AC-3 through the real hook and CLI: mission_gate's PreToolUse hook mints the bound stamp for main's exact
    Bash line, and the ah.py subprocess takes it; a sub-agent payload, --list and an echoed line mint nothing."""

    def setUp(self):
        super().setUp()
        import mission_gate
        self.mission_gate = mission_gate
        proj = self.claude / "projects" / "-proj"
        proj.mkdir(parents=True, exist_ok=True)
        self.transcript = proj / (SUP + ".jsonl")
        self.src = self.source()
        self.calls = 0

    def hook(self, words, agent=None):
        self.calls += 1
        payload = {"tool_name": "Bash", "tool_input": {"command": " ".join(words)}, "session_id": SUP,
                   "transcript_path": str(self.transcript), "tool_use_id": "toolu_%08d" % self.calls,
                   "hook_event_name": "PreToolUse"}
        if agent:
            payload.update(agent_id=agent, agent_type="task-owner")
        self.mission_gate.cmd_pretool(payload)

    def ah(self, argv, stamp=True, agent=None):
        if stamp:
            quoted = [("'%s'" % a) if (" " in a or '"' in a) and "'" not in a else a for a in argv]
            self.hook(["python3", str(AH)] + quoted, agent=agent)
        done = subprocess.run([sys.executable, str(AH)] + argv, capture_output=True, text=True, timeout=120,
                              env=dict(os.environ))
        try:
            return done.returncode, json.loads(done.stdout)
        except ValueError:
            self.fail("ah.py printed no JSON: stdout=%r stderr=%r" % (done.stdout[-400:], done.stderr[-800:]))

    def grant_argv(self):
        return ["grant-reviewer", "--task", "t1", "--reason", REASON, "--ticket", TICKET, "--wal", str(self.wal)]

    def test_set_then_grant_through_the_hook_and_cli(self):
        code, out = self.ah(["supervisor", "set", "--session", SUP, "--source", self.src])
        self.assertEqual(code, 0, out)
        code, out = self.ah(self.grant_argv())
        self.assertEqual(code, 0, out)
        self.assertEqual(out["grant"]["by"], SUP)
        rows = [json.loads(line) for line in self.wal.read_text().splitlines() if line.strip()]
        self.assertEqual(rows[-1]["id"], out["grant"]["wal_row"])
        code, out = self.ah(self.grant_argv(), stamp=False)  # a replay of the same line finds no stamp
        self.assertEqual((code, out["code"]), (2, "main_only"))

    def test_a_sub_agent_and_an_echoed_line_get_no_stamp(self):
        self.ah(["supervisor", "set", "--session", SUP, "--source", self.src])
        code, out = self.ah(self.grant_argv(), agent="a0123456789abcdef")
        self.assertEqual((code, out["code"]), (2, "main_only"))
        self.hook(["echo", "python3", str(AH)] + self.grant_argv())
        code, out = self.ah(self.grant_argv(), stamp=False)
        self.assertEqual((code, out["code"]), (2, "main_only"))
        self.assertEqual(self.mission_gate.supervisor_stamps("python3 %s grant-reviewer --list" % AH), [])


if __name__ == "__main__":
    unittest.main()
