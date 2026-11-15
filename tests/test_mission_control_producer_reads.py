"""Every producer x every way a read can lose data (goodqa#15920, PR 234 v8; receipt v7 F1, F2, F4).

Each cell damages one source the real producer reads and checks two things:
- the producer's own `read` block is not "ok" (it is "partial" or "failed");
- what the page is told (the collector's Health row, or the ledger part) is not "current".

Producers: ah requirements, ah status, ah owners and provenance asks. Failure kinds: a malformed (complete) line, a
truncated last line in a file nobody is writing, an unreadable file (not a regular file), a permission error, an
oversized source and a timeout (the producer's own scan budget and the runner's). Where a kind cannot occur for a
producer, the table says why instead of leaving it out.

Controls: an undamaged fixture is ok and current; a truncated last line in a file written seconds ago is a write in
progress, so it does not count (receipt v7 F4); a record written with spaced JSON is read, not dropped.
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

REPO = Path(__file__).resolve().parents[1]
HOOKS = REPO / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
sys.path.insert(0, str(REPO / "tests"))
os.environ.setdefault("MC_HOOKS", str(HOOKS))

import ah  # noqa: E402
import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import provenance as prov  # noqa: E402
import safeio  # noqa: E402

SID = "abcdef12-0000-4000-8000-000000000002"
AGENT = "a0000000000000001"
ROOT = os.geteuid() == 0  # chmod cannot take a file away from root
OLD = 1800  # seconds: inside the status window (12 h), well past the append grace (provenance.APPEND_GRACE_S)


def stamp(age=60):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))


def line(record, spaced=False):
    return (json.dumps(record) if spaced else json.dumps(record, separators=(",", ":"))) + "\n"


class Home:
    """A throwaway home: one session with a main WAL (a requirement, a blocker, an ask, an owner spawn), the owner's
    agent WAL and transcript meta, and an ah ledger."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory(prefix="mc-reads-")
        case.addCleanup(tmp.cleanup)
        self.case = case
        self.home = Path(tmp.name).resolve()
        self.folder = self.home / ".claude" / "wals" / SID
        self.folder.mkdir(parents=True)
        self.main = self.folder / "main.jsonl"
        self.main.write_text(
            line({"event": "requirement", "id": "wreq00000001", "note": "Keep 1000 leads", "at": stamp(), "source": "inferred: fixture"})
            + line({"event": "blocker", "id": "wblk00000001", "note": "blocked on staging", "at": stamp()})
            + line({"event": "ask", "id": "wask00000001", "note": "May main push?", "reason": "shared", "at": stamp(), "source": "inferred: fixture"})
            + line({"event": "subagent", "agent_id": AGENT, "agent_type": "task-owner", "at": stamp()}))
        self.agent = self.folder / f"agent-{AGENT}.jsonl"
        self.agent.write_text(line({"event": "intent", "note": "Build goodqa#1", "at": stamp()}))
        self.meta_dir = self.home / ".claude" / "projects" / "-proj" / SID / "subagents"
        self.meta_dir.mkdir(parents=True)
        self.meta = self.meta_dir / f"agent-{AGENT}.meta.json"
        self.meta.write_text(json.dumps({"agentType": "task-owner", "description": "Build"}))
        self.ledger = ah.store_dir(self.home) / "ledger.jsonl"
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        self.ledger.write_text(line({"op": "task.register", "key": "k1", "state": "applied", "seq": 1,
                                     "args": {"owner_agent": AGENT, "session": SID}}))
        self.locked = []
        case.addCleanup(self.unlock)

    def unlock(self):
        for path in self.locked:
            if path.exists():
                os.chmod(path, 0o700 if path.is_dir() else 0o600)

    # ---- damage
    def lock(self, path):
        os.chmod(path, 0)
        self.locked.append(path)

    def append(self, path, text, age=None):
        with open(path, "a") as handle:
            handle.write(text)
        if age is not None:
            when = time.time() - age
            os.utime(path, (when, when))

    def not_regular(self, path):
        """The source exists but is not a regular file (a directory where the WAL should be)."""
        path.unlink()
        path.mkdir()


class CliRunner:
    """The real producer CLI, with the argv Mission Control's allowlist builds, against the throwaway home."""

    def __init__(self, home: Path):
        self.home = home
        self.real = safeio.Runner(python=sys.executable, ah=str(HOOKS / "ah.py"))
        self.force = {}

    def run(self, kind, *args, timeout=20.0, limit=4 * 1024 * 1024):
        if kind in self.force:
            return self.force[kind]
        if kind in ("ah-ticket-get", "ah-goals"):
            return (0, json.dumps({"state": "ok", "warnings": [], "goals": []})) if kind == "ah-goals" else (1, "")
        argv = self.real.argv(kind, *args)
        env = {"HOME": str(self.home), "AH_HOME": str(self.home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        proc = subprocess.run(argv, capture_output=True, timeout=60, env=env, stdin=subprocess.DEVNULL, cwd="/")
        return proc.returncode, proc.stdout[:limit].decode("utf-8", "replace")


class InProcess(CliRunner):
    """The real producer functions in process, so a cell can shrink a producer's own limit (scan budget, size cap)."""

    def run(self, kind, *args, timeout=20.0, limit=0):
        if kind in self.force:
            return self.force[kind]
        try:
            if kind == "ah-requirements":
                data = ah.requirements_view(self.home, args[0])
            elif kind == "ah-status":
                data = ah.status_report(self.home, args[0], 12 * 3600)
            elif kind == "provenance-asks":
                data = prov.ask_items(args[0], self.home / ".claude")
            elif kind == "ah-owners":
                data = ah.owners(self.home, args[0] if args else SID)
            else:
                return super().run(kind, *args)
        except ah.AhError as error:
            return error.exit_code, json.dumps({"ok": False, "code": error.code})
        except prov.Problem:
            return 2, ""
        return 0, json.dumps(data, default=str)


# ---- the producers, each read through its real collector

def via_ledger(part):
    def run(runner):
        hub = ev.Hub()
        health = col.Health(hub)
        ledger = col.Ledger(hub, health, runner, lambda: SID)
        ledger.run(time.time())
        return hub.snapshots["ledger"][part]["truth"]
    return run


def via_asks(runner):
    hub = ev.Hub()
    health = col.Health(hub)
    asks = col.Asks(hub, health, runner, lambda: SID)
    asks.run(time.time())
    return health.rows["asks"]["truth"]


def via_owners(runner):
    hub = ev.Hub()
    health = col.Health(hub)
    owners = col.Owners(hub, health, runner, None)
    owners.run(time.time())
    return health.rows["owners"]["truth"]


PRODUCERS = {
    "requirements": ("ah-requirements", lambda: ah.requirements_view, via_ledger("requirements")),
    "status": ("ah-status", None, via_ledger("status")),
    "owners": ("ah-owners", None, via_owners),
    "asks": ("provenance-asks", None, via_asks),
}


def block(home, producer):
    """The producer's own read block, called in process against the damaged home."""
    if producer == "requirements":
        return ah.requirements_view(home.home, SID)["read"]
    if producer == "status":
        return ah.status_report(home.home, SID, 12 * 3600)["read"]
    if producer == "owners":
        return ah.owners(home.home, SID)["read"]
    return prov.ask_items(SID, home.home / ".claude")["read"]


def block_or_failed(home, producer):
    try:
        return block(home, producer)
    except (ah.AhError, prov.Problem, OSError) as error:   # the producer exits non-zero: the collector sees a failure
        return {"state": "failed", "error": type(error).__name__}


# ---- the damage, per producer and kind. Each value is (damage(home), runner class, patch or None), or a str: why
# the kind cannot occur for that producer.

def shrink_bounded():
    real = ah._bounded
    return mock.patch.object(ah, "_bounded", lambda path, limit=64 << 20: real(path, 8))   # every WAL is over the cap


def torn_record(event):
    return '{"event":"%s","id":"wtorn0000001","note":"torn' % event


TABLE = {
    "requirements": {
        "malformed line": (lambda h: h.append(h.main, torn_record("requirement") + "\n"), CliRunner, None),
        "truncated last line": (lambda h: h.append(h.main, torn_record("requirement"), age=OLD), CliRunner, None),
        "unreadable file": (lambda h: h.not_regular(h.main), CliRunner, None),
        "permission error": (lambda h: h.lock(h.main), CliRunner, None),
        "oversize": (None, InProcess, lambda: mock.patch.object(prov, "MAX_SCAN_BYTES", 8)),
        "timeout (producer)": (None, InProcess, lambda: mock.patch.object(prov, "SCAN_SECONDS", -1.0)),
        "row cap": (None, InProcess, lambda: mock.patch.object(ah, "VIEW_ROW_CAP", 0)),
        "non-object line": (lambda h: h.append(h.main, '["requirement"]\n'), CliRunner, None),
    },
    "status": {
        "malformed line": (lambda h: h.append(h.main, '{"event":"blocker","note":"torn\n'), CliRunner, None),
        "truncated last line": (lambda h: h.append(h.main, '{"event":"blocker","note":"torn', age=OLD), CliRunner, None),
        "unreadable file": (lambda h: h.not_regular(h.agent), CliRunner, None),
        "permission error": (lambda h: h.lock(h.agent), CliRunner, None),
        "oversize": (None, InProcess, lambda: shrink_bounded()),
        "timeout (producer)": "ah status has no scan time budget of its own: the runner's timeout is the cell for it",
        "non-object line": (lambda h: h.append(h.main, '[1, 2]\n'), CliRunner, None),
        "owners view partial": (lambda h: h.append(h.ledger, '{"op":"task.dispose","torn\n'), CliRunner, None),
    },
    "owners": {
        "malformed line": (lambda h: h.append(h.main, '{"event":"subagent_stop","agent_id":"%s"\n' % AGENT), CliRunner, None),
        "malformed line (agent WAL)": (lambda h: h.append(h.agent, '{"event":"result","note":"torn\n'), CliRunner, None),
        "truncated last line": (lambda h: h.append(h.agent, '{"event":"result","note":"torn', age=OLD), CliRunner, None),
        "unreadable file": (lambda h: h.not_regular(h.agent), CliRunner, None),
        "permission error": (lambda h: h.lock(h.agent), CliRunner, None),
        "permission error (ledger)": (lambda h: h.lock(h.ledger), CliRunner, None),
        "torn ledger row": (lambda h: h.append(h.ledger, '{"op":"task.dispose","torn\n'), CliRunner, None),
        "oversize": (lambda h: h.meta.write_text(json.dumps({"agentType": "task-owner", "pad": "x" * 70000})), CliRunner, None),
        "non-object meta": (lambda h: h.meta.write_text("[1]"), CliRunner, None),
        "timeout (producer)": "ah owners has no scan time budget of its own: the runner's timeout is the cell for it",
    },
    "asks": {
        "malformed line": (lambda h: h.append(h.main, torn_record("ask") + "\n"), CliRunner, None),
        "truncated last line": (lambda h: h.append(h.main, torn_record("ask"), age=OLD), CliRunner, None),
        "unreadable file": (lambda h: h.not_regular(h.agent), CliRunner, None),
        "permission error": (lambda h: h.lock(h.agent), CliRunner, None),
        "oversize": (None, InProcess, lambda: mock.patch.object(prov, "MAX_SCAN_BYTES", 8)),
        "timeout (producer)": (None, InProcess, lambda: mock.patch.object(prov, "SCAN_SECONDS", -1.0)),
        "non-object line": (lambda h: h.append(h.main, '["ask"]\n'), CliRunner, None),
    },
}


class Control(unittest.TestCase):
    def test_an_undamaged_home_is_ok_and_current_for_every_producer(self):
        for producer, (_kind, _fn, page) in PRODUCERS.items():
            with self.subTest(producer=producer):
                home = Home(self)
                self.assertEqual(block(home, producer)["state"], "ok")
                self.assertEqual(page(CliRunner(home.home)), "current")

    def test_a_last_line_being_written_now_is_not_a_lost_record(self):  # receipt v7 F4
        cases = {"requirements": ("main", torn_record("requirement")), "status": ("main", '{"event":"blocker","note":"half'),
                 "owners": ("agent", '{"event":"result","note":"half'), "asks": ("main", torn_record("ask"))}
        for producer, (which, text) in cases.items():
            with self.subTest(producer=producer):
                home = Home(self)
                home.append(home.main if which == "main" else home.agent, text)   # written just now: in progress
                self.assertEqual(block(home, producer)["state"], "ok")

    def test_a_spaced_record_is_read_not_dropped(self):
        home = Home(self)
        home.append(home.main, line({"event": "requirement", "id": "wreq00000002", "note": "Spaced", "at": stamp(), "source": "inferred: x"}, spaced=True)
                    + line({"event": "ask", "id": "wask00000002", "note": "Spaced?", "reason": "r", "at": stamp(), "source": "inferred: x"}, spaced=True))
        self.assertEqual(ah.requirements_view(home.home, SID)["total"], 2)
        self.assertEqual(len(prov.ledger(SID, home.home / ".claude")), 2)


@unittest.skipIf(ROOT, "root reads any file")
class EveryProducerEveryKind(unittest.TestCase):
    def test_each_damaged_read_is_not_ok_and_not_current(self):
        for producer, kinds in TABLE.items():
            kind_name, _fn, page = PRODUCERS[producer]
            for kind, cell in kinds.items():
                with self.subTest(producer=producer, kind=kind):
                    if isinstance(cell, str):
                        self.assertTrue(cell.strip())   # stated why the kind does not apply
                        continue
                    damage, runner_class, patch = cell
                    home = Home(self)
                    if producer == "owners":
                        ah.owners(home.home, SID)   # warm the index first: a torn line seen once must keep counting
                    if damage:
                        damage(home)
                    with (patch() if patch else _null()):
                        read = block_or_failed(home, producer)
                        truth = page(runner_class(home.home))
                    self.assertNotEqual(read["state"], "ok", read)
                    self.assertNotEqual(truth, "current")
                    if producer == "owners":   # the second, warm call is the one an incremental reader gets wrong
                        with (patch() if patch else _null()):
                            self.assertNotEqual(block_or_failed(home, producer)["state"], "ok")
                            self.assertNotEqual(page(runner_class(home.home)), "current")

    def test_an_index_an_older_ah_advanced_is_rescanned(self):
        """An ah without the skipped count can move the agent WAL index past a torn line (install order, or a second
        install): the count is then rebuilt from the start of the WAL, never trusted from the old offset."""
        home = Home(self)
        ah.owners(home.home, SID)
        home.append(home.agent, '{"event":"result","note":"torn\n' + line({"event": "status", "note": "later", "at": stamp()}))
        cache = next((ah.state_dir(home.home, "ah-index")).glob("wal-*.json"))
        index = json.loads(cache.read_text())
        index["meta"]["offset"] = home.agent.stat().st_size   # what an older ah leaves: offset moved, count not
        cache.write_text(json.dumps(index))
        self.assertEqual(ah.owners(home.home, SID)["read"]["skipped"], 1)

    def test_the_runner_timeout_is_never_current(self):
        for producer, (kind_name, _fn, page) in PRODUCERS.items():
            with self.subTest(producer=producer):
                home = Home(self)
                runner = CliRunner(home.home)
                runner.force[kind_name] = (124, "")
                self.assertNotEqual(page(runner), "current")


def iso_at(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


WINDOW = 12 * 3600   # the status window Mission Control asks for
TORN = '{"event":"result","note":"torn\n'


class OutsideTheWindow(unittest.TestCase):
    """PR 234 v9, main's decision: a read covers a window (the status window; the owners the default view shows). A
    line lost inside it makes the read partial; one lost outside it does not, and is disclosed as a count on the read
    block and on the page's source-health row, never hidden."""

    def history(self, home, before, after, name="agent-a0000000000000003.jsonl", age=None):
        """A WAL with a record dated `before`, a lost line, then a record dated `after` (None: the lost line is last)."""
        path = home.folder / name
        text = line({"event": "status", "note": "early", "at": iso_at(before)}) + TORN
        if after is not None:
            text += line({"event": "status", "note": "next", "at": iso_at(after)})
        path.write_text(text)
        if age is not None:
            os.utime(path, (time.time() - age, time.time() - age))
        return path

    def status(self, home, now):
        return ah.status_report(home.home, SID, WINDOW, now=now)["read"]

    def test_status_inside_partial_outside_ok_and_disclosed(self):
        now = int(time.time())
        cases = [  # (record before the lost line, record after it, WAL age) -> (state, skipped, outside)
            ("next record inside the window", now - WINDOW - 7200, now - 600, None, ("partial", 1, 0)),
            ("next record before the cutoff", now - WINDOW - 7200, now - WINDOW - 3600, None, ("ok", 0, 1)),
            ("boundary: next record at the cutoff second", now - WINDOW - 7200, now - WINDOW, None, ("partial", 1, 0)),
            ("boundary: next record one second before it", now - WINDOW - 7200, now - WINDOW - 1, None, ("ok", 0, 1)),
            ("last line, WAL written since the cutoff", now - WINDOW - 7200, None, None, ("partial", 1, 0)),
            ("last line, WAL last written before the cutoff", now - WINDOW - 7200, None, WINDOW + 600, ("ok", 0, 1)),
        ]
        for name, before, after, age, want in cases:
            with self.subTest(case=name):
                home = Home(self)
                self.history(home, before, after, age=age)
                read = self.status(home, now)
                self.assertEqual((read["state"], read["skipped"], read["outside_window"]), want, read)

    def stopped_owner(self, home, ended_ago, torn=True):
        """The fixture owner returned a result and stopped `ended_ago` seconds ago, with a lost line in its WAL."""
        at = iso_at(time.time() - ended_ago)
        home.agent.write_text(line({"event": "intent", "note": "Build goodqa#1", "at": at}) + (TORN if torn else "")
                              + line({"event": "result", "note": "done", "at": at}))
        home.append(home.main, line({"event": "subagent_stop", "agent_id": AGENT, "at": at}))
        for path in (home.agent, home.meta):
            os.utime(path, (time.time() - ended_ago, time.time() - ended_ago))

    def test_owners_hidden_row_is_outside_shown_row_is_inside(self):
        home = Home(self)
        self.stopped_owner(home, ah.OWNERS_RECENT_S + 3600)   # done and idle past the default view: hidden
        for call in ("cold", "warm"):
            with self.subTest(call=call):
                read = ah.owners(home.home, SID)["read"]
                self.assertEqual((read["state"], read["skipped"], read["outside_window"]), ("ok", 0, 1), read)
        home = Home(self)
        self.stopped_owner(home, 600)   # done ten minutes ago: still shown, so its lost line is inside
        read = ah.owners(home.home, SID)["read"]
        self.assertEqual((read["state"], read["skipped"], read["outside_window"]), ("partial", 1, 0), read)

    def test_owners_window_boundary_is_the_default_view(self):
        row = {"state": "done", "decision_required": False}
        self.assertTrue(ah.shown_owner(dict(row, idle_s=ah.OWNERS_RECENT_S)))
        self.assertFalse(ah.shown_owner(dict(row, idle_s=ah.OWNERS_RECENT_S + 1)))
        self.assertTrue(ah.shown_owner(dict(row, idle_s=ah.OWNERS_RECENT_S + 1, decision_required=True)))
        self.assertTrue(ah.shown_owner({"state": "SILENT", "idle_s": 10 ** 6}))   # a silent owner is always shown

    def test_the_page_discloses_the_count_on_the_source_health_row(self):
        home = Home(self)
        # ended before the status window too: inside the 12 h status window its lost line would make status partial
        self.stopped_owner(home, WINDOW + 3600)
        now = time.time()
        self.history(home, now - WINDOW - 7200, now - WINDOW - 3600)
        hub = ev.Hub()
        health = col.Health(hub)
        owners = col.Owners(hub, health, CliRunner(home.home), None)
        owners.run(time.time())
        row = health.rows["owners"]
        self.assertEqual((row["status"], row["truth"]), ("ok", "current"))
        # two: the stopped owner's line, and the history WAL's (an agent WAL too, idle 13 h, so its row is hidden)
        self.assertIn("2 older unreadable records outside this window", row["detail"])
        ledger = col.Ledger(hub, health, CliRunner(home.home), lambda: SID)
        ledger.run(time.time())
        self.assertEqual(hub.snapshots["ledger"]["status"]["truth"], "current")
        self.assertIn("status: 2 older unreadable records outside this window", health.rows["ledger"]["detail"])
        sources = {r["name"]: r for r in hub.snapshots["health"]}
        self.assertIn("outside this window", sources["owners"]["detail"])

    def test_no_disclosure_when_nothing_is_outside(self):
        self.assertEqual(col.outside_window({"read": {"outside_window": 0}}), "")
        self.assertEqual(col.outside_window({"read": {}}), "")
        self.assertEqual(col.outside_window({"read": {"outside_window": True}}), "")
        self.assertEqual(col.outside_window({"read": {"outside_window": 1}}), "")   # no rule stated: never "older"
        self.assertEqual(col.outside_window({"read": {"outside_window": 1, "window": {"rule": prov.LOST_WINDOW_RULE}}}),
                         "1 older unreadable record outside this window")


class RecentLostLineOfAHiddenRow(unittest.TestCase):
    """Receipt v9 F1: a hidden row is hidden by the lines that parsed, so the row alone never places a lost line outside.
    The reviewer's cases: a result 7 h ago, then a lost line written 5 minutes ago, in an agent WAL and in a task WAL,
    cold and warm. The lost line is inside: partial, skipped 1, outside_window 0."""

    def old_result_then(self, home, path, tail, recent=300, ended=7 * 3600):
        at = iso_at(time.time() - ended)
        path.write_text(line({"event": "intent", "note": "Build goodqa#1", "at": at}) + line({"event": "result", "note": "done", "at": at})
                        + tail)
        os.utime(path, (time.time() - recent, time.time() - recent))   # written 5 minutes ago, past the append grace
        return at

    def check(self, home):
        for call in ("cold", "warm"):
            with self.subTest(call=call):
                read = ah.owners(home.home, SID)["read"]
                self.assertEqual((read["state"], read["skipped"], read["outside_window"]), ("partial", 1, 0), read)

    def test_agent_wal_torn_tail_after_an_old_result(self):
        home = Home(self)
        at = self.old_result_then(home, home.agent, '{"event":"intent","note":"reopened')
        home.append(home.main, line({"event": "subagent_stop", "agent_id": AGENT, "at": at}))
        os.utime(home.meta, (time.time() - 7 * 3600, time.time() - 7 * 3600))
        rows = {r["agent_id"]: r for r in ah.owners(home.home, SID)["owners"]}
        self.assertFalse(ah.shown_owner(rows[AGENT]), rows[AGENT])   # the case needs the row hidden
        self.check(home)

    def test_agent_wal_complete_lost_line_after_an_old_result(self):
        home = Home(self)
        at = self.old_result_then(home, home.agent, '{"event":"intent","note":"reopened\n')
        home.append(home.main, line({"event": "subagent_stop", "agent_id": AGENT, "at": at}))
        os.utime(home.meta, (time.time() - 7 * 3600, time.time() - 7 * 3600))
        self.check(home)

    def test_task_wal_torn_tail_after_an_old_result(self):
        home = Home(self)
        task = home.folder / "goodqa-1-build.jsonl"
        self.old_result_then(home, task, '{"event":"intent","note":"reopened')
        rows = {r["agent_id"]: r for r in ah.owners(home.home, SID)["owners"]}
        self.assertFalse(ah.shown_owner(rows["goodqa-1-build"]), rows["goodqa-1-build"])
        self.check(home)

    def test_each_condition_alone_and_neither(self):
        """(b) the file was last written before the window: outside. (a) the next dated record, in an ordered file, is
        before it: outside. Neither: inside. The row is hidden in every case."""
        ended = 8 * 3600
        cases = {
            "(b) file last written before the window": (ended, '{"event":"note","torn\n', None, ("ok", 0, 1)),
            "(a) next dated record before the window": (300, '{"event":"note","torn\n', ended - 60, ("ok", 0, 1)),
            "neither: next dated record inside the window": (300, '{"event":"note","torn\n', 600, ("partial", 1, 0)),
        }
        for name, (recent, lost, next_ago, want) in cases.items():
            with self.subTest(case=name):
                home = Home(self)
                task = home.folder / "goodqa-2-build.jsonl"
                early = iso_at(time.time() - ended)
                text = line({"event": "intent", "note": "x", "at": early}) + lost
                if next_ago is not None:   # a record another actor wrote later; its date is the evidence
                    text += line({"event": "result", "note": "done", "at": iso_at(time.time() - next_ago), "by": "main"})
                else:
                    text += line({"event": "result", "note": "done", "at": early})
                task.write_text(text)
                os.utime(task, (time.time() - recent, time.time() - recent))
                rows = {r["agent_id"]: r for r in ah.owners(home.home, SID)["owners"]}
                if want[0] == "ok":
                    self.assertFalse(ah.shown_owner(rows["goodqa-2-build"]))
                read = ah.owners(home.home, SID)["read"]
                self.assertEqual((read["state"], read["skipped"], read["outside_window"]), want, read)


class OutOfOrder(unittest.TestCase):
    """Receipt v9 F2: dates in a WAL are written by whoever makes the record, so a later line can carry an earlier date.
    A file whose dated records go back in time proves nothing about where a lost line sits: (a) does not apply."""

    def test_status_out_of_order_is_inside(self):
        now = int(time.time())
        home = Home(self)
        path = home.folder / "agent-a0000000000000004.jsonl"
        path.write_text(line({"event": "status", "note": "fresh", "at": iso_at(now - 600)}) + TORN
                        + line({"event": "status", "note": "backdated", "at": iso_at(now - WINDOW - 3600)}))
        read = ah.status_report(home.home, SID, WINDOW, now=now)["read"]
        self.assertEqual((read["state"], read["skipped"], read["outside_window"]), ("partial", 1, 0), read)

    def test_status_in_order_control_is_outside(self):
        now = int(time.time())
        home = Home(self)
        path = home.folder / "agent-a0000000000000004.jsonl"
        path.write_text(line({"event": "status", "note": "old", "at": iso_at(now - WINDOW - 7200)}) + TORN
                        + line({"event": "status", "note": "older", "at": iso_at(now - WINDOW - 3600)}))
        read = ah.status_report(home.home, SID, WINDOW, now=now)["read"]
        self.assertEqual((read["state"], read["skipped"], read["outside_window"]), ("ok", 0, 1), read)

    def test_owners_out_of_order_is_inside(self):
        home = Home(self)
        task = home.folder / "goodqa-3-build.jsonl"
        task.write_text(line({"event": "intent", "note": "x", "at": iso_at(time.time() - 7 * 3600)}) + TORN
                        + line({"event": "result", "note": "done", "at": iso_at(time.time() - 9 * 3600), "by": "main"}))
        os.utime(task, (time.time() - 300, time.time() - 300))
        read = ah.owners(home.home, SID)["read"]
        self.assertEqual((read["state"], read["skipped"], read["outside_window"]), ("partial", 1, 0), read)

    def test_the_trail_records_order_and_survives_the_index(self):
        trail = prov.LostTrail()
        trail.dated(100.0)
        trail.lost()
        trail.dated(50.0)   # back in time
        self.assertEqual((trail.nexts, trail.ordered), ([50.0], False))
        again = prov.LostTrail.from_state(json.loads(json.dumps(trail.state())))
        self.assertEqual((again.nexts, again.ordered), ([50.0], False))
        self.assertIsNone(prov.LostTrail.from_state({"nexts": ["x"]}))
        self.assertFalse(prov.lost_outside(50.0, False, 10 ** 10, 60.0))
        self.assertTrue(prov.lost_outside(50.0, True, 10 ** 10, 60.0))
        self.assertTrue(prov.lost_outside(None, False, 40.0, 60.0))
        self.assertFalse(prov.lost_outside(None, True, 10 ** 10, 60.0))
        self.assertFalse(prov.lost_outside(50.0, True, 40.0, None))   # no window: always inside


class OneSharedRule(unittest.TestCase):
    """The user's v10 rule: ONE function decides inside or outside for every producer. Fails if a producer counts
    outside_window itself, calls the rule directly, or passes an outside count to a read block."""

    def test_only_the_shared_window_counts_outside(self):
        import re
        sources = {name: (HOOKS / name).read_text() for name in ("ah.py", "provenance.py", "ah_export.py")}
        sources["collectors.py"] = (REPO / "harness" / "mission_control" / "collectors.py").read_text()
        for name, text in sources.items():
            with self.subTest(file=name):
                counted = re.findall(r"\.outside\s*\+=", text)
                self.assertEqual(len(counted), 2 if name == "provenance.py" else 0, "only LostWindow.place counts outside")
                calls = re.findall(r"(?<!def )\blost_outside\(", text)
                self.assertEqual(len(calls), 2 if name == "provenance.py" else 0, "only LostWindow.place calls the rule")
                self.assertNotRegex(text, r"read_block\([^)]*\boutside\s*=", "an outside count is never passed in")
                built = re.findall(r'"outside_window"\s*:', text)
                self.assertEqual(len(built), 1 if name == "provenance.py" else 0, "outside_window is built in one place")

    def test_an_outside_count_without_the_rule_is_partial(self):
        good = {"schema": col.READ_SCHEMA, "state": "ok", "sources_read": 1, "unread": [], "unread_total": 0,
                "skipped": 0, "limited": False}
        for block, partial in ((dict(good, outside_window=2), True),
                               (dict(good, outside_window=2, window={"rule": "something else"}), True),
                               (dict(good, outside_window=2, window={"rule": prov.LOST_WINDOW_RULE}), False),
                               (dict(good, outside_window=0), False)):
            with self.subTest(block=block):
                data, notes = col.producer_read("x", 0, json.dumps({"read": block}))
                self.assertEqual(bool(notes), partial, notes)
                self.assertEqual(bool(col.outside_window(data)), not partial and block["outside_window"] > 0)

    def test_export_says_it_does_not_split_by_window(self):
        import ah_export
        self.assertIn("not split by window", ah_export.SKIPPED_SCOPE)
        self.assertNotIn("window", ah.status_report(Home(self).home, SID, WINDOW, rows=[], sources_read=1)["read"])


class NoLiteralWholeRead(unittest.TestCase):
    def test_no_producer_builds_a_read_block_from_a_literal_count(self):
        import re
        for path in (HOOKS / "ah.py", HOOKS / "provenance.py"):
            source = path.read_text()
            literal = [m.group(0) for m in re.finditer(r"read_block\(\s*\d", source)]
            self.assertEqual(literal, [], f"{path.name}: a read block's sources_read must be counted, never a literal")
            self.assertNotRegex(source, r"\bread_ok\s*=\s*1\b", f"{path.name}: read_ok is counted, never set to 1")


class HealthLock(unittest.TestCase):
    """Receipt v7 F3: Health.expire reads a row and writes it back aged; a fresh read written in between must win."""

    def test_a_write_during_expire_is_not_lost(self):
        import threading
        health = col.Health(ev.Hub())
        health.ok("owners", "read")
        health.rows["owners"]["checked"] = time.time() - 1000   # due to be aged out
        inside, release = threading.Event(), threading.Event()
        real = col.read_truth

        def slow(*args, **kwargs):   # expire has read the old row and is about to write it back aged
            if threading.current_thread() is ager:
                inside.set()
                release.wait(2)
            return real(*args, **kwargs)
        with mock.patch.object(col, "read_truth", slow):
            ager = threading.Thread(target=health.expire, args=({"owners": 60.0},))
            ager.start()
            self.assertTrue(inside.wait(2))
            writer = threading.Thread(target=health.ok, args=("owners", "fresh read"))
            writer.start()
            writer.join(0.3)   # with the lock it waits for expire; without it, it writes now and is then overwritten
            release.set()
            ager.join(2)
            writer.join(2)
        row = health.rows["owners"]
        self.assertEqual((row["status"], row.get("aged"), row["detail"]), ("ok", None, "fresh read"))

    def test_snapshot_is_a_copy_taken_under_the_lock(self):
        health = col.Health(ev.Hub())
        health.ok("owners", "read")
        rows = health.snapshot()
        rows[0]["status"] = "changed"
        self.assertEqual(health.rows["owners"]["status"], "ok")


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


if __name__ == "__main__":
    unittest.main()
