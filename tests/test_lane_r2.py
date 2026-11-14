"""S1 (GoodQA goodqa#15946): PR 238 round-2 review fixes over the REAL adapters.

F1: RealPorts.task_register runs the real `ah.py task register` (real provenance) and must succeed with a grounded
source, be an ah duplicate on retry, refuse an ungrounded ticket and refuse a second holder of a registered stream.
F2: `ah lane new` killed between ticket steps (real TicketPort and GoodQA adapter against an in-process fake GoodQA
server that links an upload only through a comment) must end, after a fresh retry, with exactly one linked digest
attachment and one comment. F4: a checkpoint killed after the real wal_note append and before its effect is
acknowledged, and two concurrent checkpoints, leave exactly one session-log note.

Bounded probes: temp HOME only (HOME and AH_HOME point at it), no network (HARNESS_PROVENANCE_OFFLINE=1, a loopback
fake server, proxies disabled), at most 4 forked children per test that end with os._exit, 60 s join each, and at most
6 short `python3 ah.py|wal_note.py` subprocesses per test.
"""
import fcntl
import json
import multiprocessing
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ah_lane  # noqa: E402
import spec_flow as sf  # noqa: E402
import commit_policy as cp  # noqa: E402
from lane import commands as cmd, lanes, manifest as mf, store as st  # noqa: E402
from test_lane_commands import Cmd, owner  # noqa: E402

TICKET = "GoodQA goodqa#15946"
FORK = multiprocessing.get_context("fork")


def run_child(target, *args):
    proc = FORK.Process(target=target, args=args)
    proc.start()
    proc.join(60)
    if proc.is_alive():
        proc.kill()
        raise AssertionError("child hung")
    return proc.exitcode


class HomeCase(Cmd):
    """A temp HOME for the real subprocesses (ah.py, wal_note.py read Path.home() and AH_HOME)."""

    def setUp(self):
        super().setUp()
        self.saved = {k: os.environ.get(k) for k in ("HOME", "AH_HOME", "HARNESS_PROVENANCE_OFFLINE", "no_proxy",
                                                     "NO_PROXY", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID")}
        os.environ.update(HOME=str(self.base), AH_HOME=str(self.base), HARNESS_PROVENANCE_OFFLINE="1", no_proxy="*",
                          NO_PROXY="*")
        os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
        os.environ.pop("CLAUDE_SESSION_ID", None)
        (self.base / ".claude" / "wals" / "sess").mkdir(parents=True)
        self.main_wal = self.base / ".claude" / "wals" / "sess" / "main.jsonl"

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        super().tearDown()

    def real_ports(self, keep=()):
        """RealPorts whose named methods are the real ones; every other port is the test's fake."""
        class Ports(ah_lane.RealPorts):
            ticket = None
        real = Ports.__new__(Ports)
        real._caller = {"id": "main"}
        real.session = "sess"
        for name, value in vars(self.p).items():
            if name not in keep:
                setattr(real, name, value)
        return real

    def wal_rows(self, path=None):
        path = path or self.main_wal
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ------------------------------------------------------------------------------------------------------------- F1
class RealTaskRegisterTests(HomeCase):
    def setUp(self):
        super().setUp()
        cache = self.base / ".agent-harness" / "provenance"
        cache.mkdir(parents=True)
        (cache / "tickets.json").write_text(json.dumps({"goodqa#15946": {"title": "S1 lane factory",
                                                                          "checked_by": "test"}}))
        self.real = self.real_ports(keep=("task_register",))

    def ledger(self):
        path = self.base / ".agent-harness" / "state" / "ah" / "ledger.jsonl"
        found = list(self.base.glob(".agent-harness/**/ledger.jsonl"))
        path = found[0] if found else path
        rows = [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
        return [r for r in rows if r.get("op") == "task.register" and r.get("state", "applied") == "applied"]

    def register(self, agent="A1", op="bind-lane_x-g1-A1", task="goodqa-15946"):
        return self.real.task_register(task=task, agent=agent, ticket=TICKET, branch="lane/goodqa-15946",
                                       worktree=str(self.base / "wt"), op=op)

    def test_real_register_succeeds_with_a_grounded_source_and_a_retry_is_a_duplicate(self):  # F1
        cid = self.register()
        self.assertTrue(cid)
        rows = self.ledger()
        self.assertEqual(len(rows), 1, rows)
        self.assertTrue(rows[0]["args"]["source"].startswith("inferred: from ticket:GoodQA goodqa#15946 -- "))
        scope = [r for r in self.wal_rows() if r.get("event") == "scope"]
        self.assertEqual(len(scope), 1)
        self.assertEqual(self.ticket.count("comment"), 1)
        self.register()  # a retry after a crash between register and the effect record
        self.assertEqual(len(self.ledger()), 1, "the retry is an ah duplicate, not a second registration")
        self.assertEqual(self.ticket.count("comment"), 1, "the ticket comment is not posted twice")

    def test_an_ungrounded_ticket_is_refused_and_nothing_is_registered(self):  # F1 negative
        (self.base / ".agent-harness" / "provenance" / "tickets.json").write_text("{}")
        with self.assertRaises(RuntimeError):
            self.register()
        self.assertEqual(self.ledger(), [])
        self.assertEqual(self.ticket.count("comment"), 0)

    def test_a_second_holder_of_a_registered_stream_is_a_refusal_not_a_retry_loop(self):  # F1, generation 2
        self.register()
        with self.assertRaises(lanes.LaneRefusal):
            self.register(agent="A2", op="bind-lane_x-g2-A2")
        self.assertEqual(len(self.ledger()), 1)

    def test_bind_through_the_real_register_reaches_holder_bound(self):  # F1 end to end through commands.bind
        lane = self.mk()
        cmd.start(self.p, self.store, lane=lane)
        m = mf.read_current(self.store.lane_dir(lane))
        self.dispatch["A1"] = m["stream_key"]
        self.owner_rows = [owner(1)]
        self.p.task_register = self.real.task_register
        r = cmd.bind(self.p, self.store, lane=lane, agent="A1")
        self.assertEqual(r.code, cmd.OK, r.lines)
        rows = self.store._rows(self.store.lane_dir(lane))
        self.assertEqual([x["data"]["agent"] for x in rows if x["kind"] == "holder_bound"], ["A1"])

    def test_bind_of_a_stream_registered_to_another_holder_is_refused_not_partial(self):  # F1 through commands.bind
        lane = self.mk()
        cmd.start(self.p, self.store, lane=lane)
        m = mf.read_current(self.store.lane_dir(lane))
        self.register(agent="A0", op="bind-other-g1-A0", task=m["stream_key"])  # an earlier holder of the stream
        self.dispatch["A1"] = m["stream_key"]
        self.owner_rows = [owner(1)]
        self.p.task_register = self.real.task_register
        r = cmd.bind(self.p, self.store, lane=lane, agent="A1")
        self.assertEqual(r.code, cmd.REFUSED, r.lines)
        self.assertIn("already registered to another holder", " ".join(r.lines))
        rows = self.store._rows(self.store.lane_dir(lane))
        self.assertEqual([x for x in rows if x["kind"] == "holder_bound"], [])


# ------------------------------------------------------------------------------------------------------------- F2
def _new_child(store_root, repo, templates, cfg, point):
    """Run `ah lane new` with the real TicketPort and die (os._exit, no cleanup) at ``point``."""
    port = ah_lane_ticket_port(cfg)
    real_upload, real_comment = port.upload, port.comment

    def upload(*a, **kw):
        out = real_upload(*a, **kw)
        if point == "after-upload":
            os._exit(17)
        return out

    def comment(*a, **kw):
        if point == "before-comment":
            os._exit(17)
        out = real_comment(*a, **kw)
        if point == "after-comment":
            os._exit(17)
        return out
    port.upload, port.comment = upload, comment
    ports = _new_ports(port, templates)
    cmd.new(ports, st.Store(store_root), ticket="GoodQA harness#168", repo=repo)
    os._exit(0)


def _new_ports(port, templates):
    ids = iter(["lane_r2crash"])
    return SimpleNamespace(host_alias="mac", session="sess", now=lambda: "2027-01-15T08:00:00Z",
                           new_id=lambda: next(ids), templates_root=templates, policy_files=lambda: {},
                           default_kit_version="v1", ticket=port, is_main=lambda c, k: True,
                           caller=lambda: {"id": "main", "session": "sess"})


def ah_lane_ticket_port(cfg):
    """The real TicketPort and GoodQA adapter, pointed at the fake server (no spec_policy.local, no live key)."""
    port = ah_lane.TicketPort.__new__(ah_lane.TicketPort)
    port.sf, port.policy, port.config = sf, cfg["policy"], cfg["config"]
    port._issue = {}
    if hasattr(ah_lane.TicketPort, "__init__"):
        port._pending = []  # the pre-fix port keeps uploads here (process-local); the fix no longer reads it
    return port


class NewCrashTests(HomeCase):
    def setUp(self):
        super().setUp()
        from test_spec_flow import FakeGoodQA, PROJECT  # noqa: PLC0415 - the real tracker contract, in-process
        self.fake = FakeGoodQA()
        key = self.base / "key"
        key.write_text("test-key")
        key.chmod(0o600)
        policy = cp.load_policy(HOOKS / "commit_policy.json")
        config = dict(policy["ticket_systems"]["goodqa"], endpoint=self.fake.url, key_file=str(key), org_id="org-1",
                      timeout_seconds=5, total_deadline_seconds=30)
        spec_policy = sf.load_spec_policy(HOOKS / "spec_policy.json")
        spec_policy["projects"] = {"harness": {"project_id": PROJECT, "org_id": "00000000-0000-4000-8000-000000000001"}}
        self.cfg = {"policy": spec_policy, "config": config}

    def tearDown(self):
        self.fake.server.shutdown()
        super().tearDown()

    def linked(self):
        from test_spec_flow import ISSUE  # noqa: PLC0415
        ids = {c["id"] for c in self.fake.comments[ISSUE]}
        return [a for a in self.fake.attachments.values() if a["commentId"] in ids]

    def op_comments(self):
        from test_spec_flow import ISSUE  # noqa: PLC0415
        return [c for c in self.fake.comments[ISSUE] if "[op new-lane_r2crash]" in c["body"]]

    def test_killed_between_ticket_steps_then_a_fresh_retry_links_exactly_one_attachment(self):  # F2
        for point in ("after-upload", "before-comment", "after-comment"):
            with self.subTest(point=point):
                from test_spec_flow import ISSUE  # noqa: PLC0415
                self.fake.comments[ISSUE], self.fake.attachments = [], {}
                root = self.base / ("lanes-" + point)
                code = run_child(_new_child, str(root), str(self.repo), str(self.templates), self.cfg, point)
                self.assertEqual(code, 17, "the crash point must be reached")
                retry = cmd.new(_new_ports(ah_lane_ticket_port(self.cfg), self.templates), st.Store(root),
                                ticket="GoodQA harness#168", repo=str(self.repo))
                self.assertEqual(retry.code, cmd.OK, retry.lines)
                linked = self.linked()
                name = "kit-digests-lane_r2crash.txt"
                self.assertEqual([a["metadata"]["filename"] for a in linked], [name],
                                 "exactly one digest attachment is linked to the issue")
                d = st.Store(root).lane_dir("lane_r2crash")
                m = mf.read_current(d)
                text = "".join("%s  %s\n" % (dg, n) for n, dg in sorted(m["kit_digests"].items()))
                import hashlib  # noqa: PLC0415
                self.assertEqual(linked[0]["sha256"], hashlib.sha256(text.encode()).hexdigest())
                self.assertEqual(len(self.op_comments()), 1, "one creation comment")
                again = cmd.new(_new_ports(ah_lane_ticket_port(self.cfg), self.templates), st.Store(root),
                                ticket="GoodQA harness#168", repo=str(self.repo))
                self.assertEqual((again.code, len(self.linked()), len(self.op_comments())), (cmd.OK, 1, 1))

    def test_the_attachment_effect_is_not_done_until_the_comment_linked_it(self):  # F2 ordering
        root = self.base / "lanes-order"
        code = run_child(_new_child, str(root), str(self.repo), str(self.templates), self.cfg, "before-comment")
        self.assertEqual(code, 17)
        d = st.Store(root).lane_dir("lane_r2crash")
        rec = json.loads(next((d / "ops").glob("new-*.json")).read_text())
        effects = {e["name"]: e for e in rec["effects"]}
        self.assertNotEqual(effects["attach"]["state"], "done")
        self.assertTrue(effects["attach"]["ref"], "the uploaded attachment id is persisted before the comment")


# ------------------------------------------------------------------------------------------------------------- F4
def _ckpt_child(home, store_root, lane, templates, kill_after_note, barrier, ticket_file):
    os.environ.update(HOME=home, AH_HOME=home)
    if kill_after_note:
        real_set = st.Store.set_effect

        def set_effect(self, lane_dir, op, name, state, ref=None, ts=None):
            if name == "note" and state == "done":
                os._exit(17)  # the WAL append happened; its acknowledgement never does
            return real_set(self, lane_dir, op, name, state, ref=ref, ts=ts)
        st.Store.set_effect = set_effect
    ports = _ckpt_ports(templates, ticket_file)
    if barrier is not None:
        barrier.wait(30)
    r = cmd.checkpoint(ports, st.Store(store_root), lane=lane, kind="plan", note="plan: do the thing", main=True)
    os._exit(0 if r.code in (cmd.OK, cmd.PARTIAL) else 30 + r.code)


class FileTicket:
    """A ticket fake whose state is a file under flock, so separate processes see one tracker."""

    def __init__(self, path):
        self.path = Path(path)

    def _io(self, fn):
        with open(self.path, "a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.seek(0)
            data = json.loads(handle.read() or "{}")
            out = fn(data)
            handle.seek(0)
            handle.truncate()
            handle.write(json.dumps(data))
            return out

    def find_comment(self, ref, key):
        return self._io(lambda d: ("c-" + key) if key in d else None)

    def comment(self, ref, body, key, attachment_ids=()):
        def post(d):
            d.setdefault(key, []).append(body)
            return "c-" + key
        return self._io(post)

    def comments(self):
        return self._io(lambda d: dict(d))


def _ckpt_ports(templates, ticket_file):
    class Ports(ah_lane.RealPorts):
        ticket = None
    real = Ports.__new__(Ports)
    real._caller = {"id": "main"}
    real.session = "sess"
    real.ticket = FileTicket(ticket_file)
    real.now = lambda: "2027-01-15T08:00:00Z"
    real.templates_root = templates
    real.last_remote_head = lambda lane: None
    return real


class CheckpointExactlyOnceTests(HomeCase):
    def setUp(self):
        super().setUp()
        self.lane = self.mk()
        self.ticket_file = self.base / "tracker.json"

    def wal_notes(self):
        return [r for r in self.wal_rows() if "lane %s checkpoint plan" % self.lane in str(r.get("note"))]

    def test_killed_after_the_real_append_then_a_fresh_retry_leaves_one_note(self):  # F4 crash
        code = run_child(_ckpt_child, str(self.base), str(self.store.root), self.lane, str(self.templates), True, None,
                         str(self.ticket_file))
        self.assertEqual(code, 17, "the crash point must be reached")
        self.assertEqual(len(self.wal_notes()), 1, "the append happened before the kill")
        code = run_child(_ckpt_child, str(self.base), str(self.store.root), self.lane, str(self.templates), False, None,
                         str(self.ticket_file))
        self.assertEqual(code, 0)
        notes = self.wal_notes()
        self.assertEqual(len(notes), 1, "the retry did not append a second note")
        rows = [r for r in self.store._rows(self.store.lane_dir(self.lane)) if r["kind"] == "checkpoint"]
        self.assertEqual([r["data"]["note_row"] for r in rows], [notes[0]["id"]])
        self.assertEqual([len(v) for v in FileTicket(self.ticket_file).comments().values()], [1])

    def test_two_concurrent_checkpoints_leave_one_note_and_one_comment(self):  # F4 concurrency
        barrier = FORK.Barrier(2)
        procs = [FORK.Process(target=_ckpt_child, args=(str(self.base), str(self.store.root), self.lane,
                                                        str(self.templates), False, barrier, str(self.ticket_file)))
                 for _ in range(2)]
        [p.start() for p in procs]
        [p.join(60) for p in procs]
        self.assertEqual([p.exitcode for p in procs], [0, 0])
        self.assertEqual(len(self.wal_notes()), 1, "one note for one checkpoint operation")
        self.assertEqual([len(v) for v in FileTicket(self.ticket_file).comments().values()], [1])


class WalNoteOpKeyTests(HomeCase):
    def note(self, *extra):
        import subprocess  # noqa: PLC0415
        argv = [sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.main_wal), "--event", "status",
                "--note", "lane x checkpoint plan: n", *extra]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60)

    def test_same_key_twice_writes_one_row_and_answers_its_id(self):
        first, second = self.note("--op-key", "lane:x:ckpt-1"), self.note("--op-key", "lane:x:ckpt-1")
        a, b = json.loads(first.stdout), json.loads(second.stdout)
        self.assertEqual((a["status"], b["status"], a["id"]), ("WROTE", "DUPLICATE", b["id"]))
        self.assertEqual(len(self.wal_rows()), 1)
        self.assertEqual(self.wal_rows()[0]["op_key"], "lane:x:ckpt-1")

    def test_without_a_key_nothing_changes_and_a_bad_key_is_refused(self):
        self.note()
        self.note()
        self.assertEqual(len(self.wal_rows()), 2, "unkeyed notes are still plain appends")
        bad = self.note("--op-key", "short")
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(len(self.wal_rows()), 2)

    def test_four_concurrent_writers_with_one_key_leave_one_row(self):
        import subprocess  # noqa: PLC0415
        argv = [sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.main_wal), "--event", "status",
                "--note", "lane x checkpoint plan: n", "--op-key", "lane:x:ckpt-race"]
        procs = [subprocess.Popen(argv, stdout=subprocess.PIPE, text=True) for _ in range(4)]
        answers = [json.loads(p.communicate(timeout=60)[0]) for p in procs]
        self.assertEqual(len({a["id"] for a in answers}), 1)
        self.assertEqual(sorted(a["status"] for a in answers), ["DUPLICATE"] * 3 + ["WROTE"])
        self.assertEqual(len(self.wal_rows()), 1)


if __name__ == "__main__":
    unittest.main()
