"""The truth chain end to end (goodqa#15920, PR 234 v7): producer -> collector -> dataset read.

Rule under test: no layer turns an exception or a missing field into an empty success, and what is declared to feed a
dataset equals what is observed to feed it.

ProducerToCollector and SilentSources drive seams that exist before this change (the `ah` and `provenance` producers,
Collector.run, the hub snapshots), so each row fails there by assertion. DerivedFeeds, Envelope and AgedOut test the
new declarations (collectors.FEEDS, producer_read, Health.expire)."""

import collections
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
os.environ.setdefault("MC_HOOKS", str(HOOKS))

import ah  # noqa: E402
import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import provenance as prov  # noqa: E402
import safeio  # noqa: E402
import server as mcs  # noqa: E402

SID = "abcdef12-0000-4000-8000-000000000001"
ROOT = os.geteuid() == 0  # chmod cannot take a file away from root


def stamp(age=60):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))


def wal_lines():
    return [
        {"event": "requirement", "id": "wreq00000001", "note": "The export must keep 1000 leads", "at": stamp(), "source": "inferred: fixture"},
        {"event": "blocker", "id": "wblk00000001", "note": "blocked on the staging database", "at": stamp()},
        {"event": "ask", "id": "wask00000001", "note": "May main push the branch?", "reason": "shared branch", "at": stamp(),
         "source": "inferred: fixture"},
    ]


class Home:
    """A throwaway home with one session's main WAL, as the producers read it."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory(prefix="mc-chain-")
        case.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.folder = self.home / ".claude" / "wals" / SID
        self.folder.mkdir(parents=True)
        self.wal = self.folder / "main.jsonl"
        self.wal.write_text("".join(json.dumps(line, separators=(",", ":")) + "\n" for line in wal_lines()))  # compact, as the WAL writer
        case.addCleanup(self.readable)

    def unreadable(self):
        os.chmod(self.wal, 0)

    def readable(self):
        if self.wal.exists():
            os.chmod(self.wal, 0o600)


class CliRunner:
    """Runs the real producer CLI, with the argv Mission Control's allowlist builds, against a throwaway home."""

    def __init__(self, home: Path):
        self.home = home
        self.real = safeio.Runner(python=sys.executable, ah=str(HOOKS / "ah.py"))
        self.force = {}  # kind -> (code, out): a Runner-level outcome (its timeout, its output cap)

    def run(self, kind, *args, timeout=20.0, limit=4 * 1024 * 1024):
        if kind in self.force:
            return self.force[kind]
        if kind == "ah-ticket-get":
            return 1, ""
        argv = self.real.argv(kind, *args)
        env = {"HOME": str(self.home), "AH_HOME": str(self.home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        proc = subprocess.run(argv, capture_output=True, timeout=60, env=env, stdin=subprocess.DEVNULL, cwd="/")
        return proc.returncode, proc.stdout[:limit].decode("utf-8", "replace")


class InProcess:
    """The real producer functions called in process, so a test can shrink a producer's own limits (its scan time
    budget, its size cap) and hand the collector exactly what that producer then prints."""

    def __init__(self, home: Path):
        self.home = home

    def run(self, kind, *args, timeout=20.0, limit=0):
        try:
            if kind == "ah-requirements":
                data = ah.requirements_view(self.home, args[0])
            elif kind == "ah-status":
                data = ah.status_report(self.home, args[0], 12 * 3600)
            elif kind == "provenance-asks":
                data = prov.ask_items(args[0], self.home / ".claude")
            elif kind == "ah-goals":
                return 0, json.dumps({"state": "ok", "warnings": [], "goals": []})
            else:
                return 1, ""
        except ah.AhError as error:
            return error.exit_code, json.dumps({"ok": False, "code": error.code})
        except prov.Problem:
            return 2, ""
        return 0, json.dumps(data, default=str)


def ledger_on(runner):
    hub = ev.Hub()
    health = col.Health(hub)
    return col.Ledger(hub, health, runner, lambda: SID), hub, health


def asks_on(runner):
    hub = ev.Hub()
    health = col.Health(hub)
    return col.Asks(hub, health, runner, lambda: SID), hub, health


def part_of(hub, name):
    part = hub.snapshots["ledger"][name]
    rows = part.get("items") if name == "requirements" else part.get("blockers")
    return part["truth"], len(rows or [])


def shrink_scan_time():
    return mock.patch.object(prov, "SCAN_SECONDS", -1.0)


def shrink_scan_size():
    return mock.patch.object(prov, "MAX_SCAN_BYTES", 8)


def shrink_status_size():
    real = ah._bounded
    return mock.patch.object(ah, "_bounded", lambda path, limit=64 << 20: real(path, 8))


class ProducerToCollector(unittest.TestCase):
    """review PR 234 v6 F1 and its class: a WAL the producer cannot read is never a healthy empty list. Each row runs
    the real producer into the real collector and checks what the page would be told."""

    def test_control_a_readable_wal_is_current_with_its_rows(self):
        home = Home(self)
        ledger, hub, _ = ledger_on(CliRunner(home.home))
        ledger.run(1000.0)
        self.assertEqual(part_of(hub, "requirements"), ("current", 1))
        self.assertEqual(part_of(hub, "status"), ("current", 1))
        asks, hub, health = asks_on(CliRunner(home.home))
        asks.run(1000.0)
        self.assertEqual((health.rows["asks"]["truth"], len(asks.items) + len(asks.flagged)), ("current", 1))

    @unittest.skipIf(ROOT, "root reads any file")
    def test_permission_error_before_any_good_read_is_unknown(self):
        for part in ("requirements", "status"):
            with self.subTest(part=part):
                home = Home(self)
                home.unreadable()
                ledger, hub, health = ledger_on(CliRunner(home.home))
                ledger.run(1000.0)
                self.assertEqual(part_of(hub, part), ("unknown", 0))
                self.assertTrue(hub.snapshots["ledger"][part]["error"])
                self.assertEqual(health.rows["ledger"]["status"], "error")

    @unittest.skipIf(ROOT, "root reads any file")
    def test_permission_error_after_a_good_read_keeps_the_rows_as_stale(self):
        for part in ("requirements", "status"):
            with self.subTest(part=part):
                home = Home(self)
                ledger, hub, _ = ledger_on(CliRunner(home.home))
                ledger.run(1000.0)
                self.assertEqual(part_of(hub, part), ("current", 1))
                home.unreadable()
                ledger.run(1060.0)
                self.assertEqual(part_of(hub, part), ("stale", 1))
                home.readable()
                ledger.run(1120.0)
                self.assertEqual(part_of(hub, part), ("current", 1))

    @unittest.skipIf(ROOT, "root reads any file")
    def test_asks_permission_error_is_never_nothing_needs_you(self):
        home = Home(self)
        home.unreadable()
        asks, _hub, health = asks_on(CliRunner(home.home))
        asks.run(1000.0)
        self.assertEqual((health.rows["asks"]["status"], health.rows["asks"]["truth"]), ("error", "unknown"))
        home.readable()
        asks.run(1010.0)
        self.assertEqual(health.rows["asks"]["truth"], "current")
        home.unreadable()
        asks.run(1020.0)
        self.assertEqual((health.rows["asks"]["truth"], len(asks.items) + len(asks.flagged)), ("stale", 1))

    @unittest.skipIf(ROOT, "root reads any file")
    def test_an_unreadable_agent_wal_makes_the_asks_partial_not_whole(self):
        home = Home(self)
        other = home.folder / "agent-a0000000000000001.jsonl"
        other.write_text(json.dumps({"event": "ask", "id": "wask00000002", "note": "Hidden?", "at": stamp(), "source": "inferred: x"}, separators=(",", ":")) + "\n")
        os.chmod(other, 0)
        self.addCleanup(os.chmod, other, 0o600)
        asks, _hub, health = asks_on(CliRunner(home.home))
        asks.run(1000.0)
        self.assertEqual((health.rows["asks"]["status"], health.rows["asks"]["truth"]), ("ok", "partial"))

    def test_producer_scan_timeout_and_oversize(self):
        cases = [("requirements", "ah-requirements", shrink_scan_time), ("requirements", "ah-requirements", shrink_scan_size),
                 ("status", "ah-status", shrink_status_size)]
        for part, kind, shrink in cases:
            with self.subTest(part=part, limit=shrink.__name__, when="before any good read"):
                home = Home(self)
                ledger, hub, _ = ledger_on(InProcess(home.home))
                with shrink():
                    ledger.run(1000.0)
                self.assertEqual(part_of(hub, part), ("unknown", 0))
            with self.subTest(part=part, limit=shrink.__name__, when="after a good read"):
                home = Home(self)
                ledger, hub, _ = ledger_on(InProcess(home.home))
                ledger.run(1000.0)
                self.assertEqual(part_of(hub, part), ("current", 1))
                with shrink():
                    ledger.run(1060.0)
                self.assertEqual(part_of(hub, part), ("stale", 1))

    def test_asks_scan_timeout_and_oversize(self):
        for shrink in (shrink_scan_time, shrink_scan_size):
            with self.subTest(limit=shrink.__name__):
                home = Home(self)
                asks, _hub, health = asks_on(InProcess(home.home))
                with shrink():
                    asks.run(1000.0)
                self.assertEqual(health.rows["asks"]["truth"], "unknown")
                asks.run(1010.0)
                self.assertEqual(health.rows["asks"]["truth"], "current")
                with shrink():
                    asks.run(1020.0)
                self.assertEqual((health.rows["asks"]["truth"], len(asks.items) + len(asks.flagged)), ("stale", 1))

    def test_runner_timeout_and_oversize_output(self):
        outcomes = {"timeout": (124, ""), "oversize": (0, "x" * (col.Ledger.REQ_LIMIT + 2))}
        for name, outcome in outcomes.items():
            for part, kind in (("requirements", "ah-requirements"), ("status", "ah-status")):
                with self.subTest(outcome=name, part=part):
                    home = Home(self)
                    runner = CliRunner(home.home)
                    ledger, hub, _ = ledger_on(runner)
                    runner.force[kind] = outcome
                    ledger.run(1000.0)
                    self.assertEqual(part_of(hub, part), ("unknown", 0))
                    del runner.force[kind]
                    ledger.run(1060.0)
                    self.assertEqual(part_of(hub, part), ("current", 1))
                    runner.force[kind] = outcome
                    ledger.run(1120.0)
                    self.assertEqual(part_of(hub, part), ("stale", 1))

    def test_a_line_the_producer_cannot_parse_is_partial(self):
        home = Home(self)
        with open(home.wal, "a") as handle:
            handle.write('{"event":"requirement","id":"wreq00000002","note": broken\n')
        ledger, hub, _ = ledger_on(CliRunner(home.home))
        ledger.run(1000.0)
        self.assertEqual(part_of(hub, "requirements"), ("partial", 1))
        self.assertEqual(part_of(hub, "status"), ("partial", 1))


class SilentSources(unittest.TestCase):
    """Collector reads that reported ok while they had read nothing or only part (found by the v7 chain audit)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="mc-chain-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)

    def truth(self, name):
        row = self.health.rows[name]
        return row["status"], row["truth"]

    def test_initiatives_refused_after_the_signature_was_taken_never_turns_ok(self):
        path = self.base / "initiatives.json"
        path.write_text(json.dumps({"initiatives": [{"id": "i1", "initiative": "Ship"}]}))
        reader = safeio.Reader([self.base])
        source = col.Initiatives(self.hub, self.health, reader, path)
        source.run(1.0)
        self.assertEqual(self.truth("initiatives"), ("ok", "current"))
        path.write_text(json.dumps({"initiatives": []}))
        with mock.patch.object(reader, "read", side_effect=safeio.Refused("refused")):
            source.run(2.0)
            self.assertEqual(self.truth("initiatives"), ("error", "stale"))
            source.run(3.0)  # the file has not changed since the refused read
            self.assertEqual(self.truth("initiatives"), ("error", "stale"))
        self.assertEqual(len(source.items), 1, "the last good copy is kept")

    def test_one_failed_ticket_is_not_hidden_by_the_next_good_one(self):
        class Runner:
            def run(self, kind, ref, timeout=20.0, limit=0):
                return (1, "") if ref == "goodqa#1" else (0, json.dumps({"comments": []}))
        source = col.Tickets(self.hub, self.health, Runner(), lambda: ["goodqa#1", "goodqa#2"])
        source.run(1.0)
        self.assertEqual(self.truth("goodqa"), ("error", "unknown"))
        source.run(11.0)  # the other ticket reads well; the first is still unread
        self.assertEqual(self.truth("goodqa"), ("ok", "partial"))

    def test_a_drop_directory_that_cannot_be_listed_is_a_failed_read(self):
        drop = self.base / "sources"
        drop.mkdir()
        source = col.FileDrop(self.hub, self.health, safeio.Reader([self.base]), drop)
        source.run(1.0)
        self.assertEqual(self.truth("sources"), ("ok", "current"))
        with mock.patch.object(os, "scandir", side_effect=PermissionError("denied")):
            source.run(6.0)
        self.assertEqual(self.truth("sources"), ("error", "stale"))

    def test_a_goals_report_that_warns_its_scan_was_cut_is_partial(self):
        class Runner:
            def run(self, kind, *args, timeout=20.0, limit=0):
                return 0, json.dumps({"state": "ok", "warnings": ["tag scan was partial (time or size bound)"], "goals": []})
        ledger = col.Ledger(self.hub, self.health, Runner(), lambda: "")
        ledger.run(1.0)
        self.assertEqual(self.hub.snapshots["ledger"]["goals"]["truth"], "partial")

    def test_a_chat_folder_that_cannot_be_listed_is_not_an_empty_chat(self):
        with mock.patch.dict(os.environ, {"MC_HOME": str(self.base / "mc")}):
            app = App(self.base)
            app.chat_once()
            self.assertEqual(app.health.rows["chat"]["status"], "ok")
            real = os.listdir
            with mock.patch.object(os, "listdir", side_effect=lambda p: (_ for _ in ()).throw(PermissionError("denied")) if "chat" in str(p) else real(p)):
                app.chat_once()
            self.assertEqual((app.health.rows["chat"]["status"], app.health.rows["chat"]["truth"]), ("error", "stale"))


# ---- the declared feeds against the observed ones

HEX = "a0123456789abcdef"


class Outputs:
    """Every allowlisted producer answers with a whole, non-empty read, so every path that carries data runs."""

    def __init__(self):
        self.state = "live"
        self.real = safeio.Runner(python=sys.executable, ah="/x/ah.py", codex="/x/codex", fabric_bin=None)

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.real.argv(kind, *args)
        read = {"schema": "harness.read/1", "state": "ok", "sources_read": 1, "unread_total": 0, "unread": [], "skipped": 0, "limited": False}
        if kind == "ah-owners":
            return 0, json.dumps({"read": read, "session": SID, "owners": [{"agent_id": HEX, "state": self.state, "ticket": "goodqa#1", "idle_s": 1}]})
        if kind == "provenance-asks":
            return 0, json.dumps({"read": read, "items": [{"id": "wask00000001", "note": "Q? (goodqa#1)", "owner": "agent-" + HEX, "at": stamp()}],
                                  "blocked": [], "resolved": []})
        if kind == "ah-goals":
            return 0, json.dumps({"state": "ok", "warnings": [], "goals": [{"id": "g1", "title": "G", "state": "UNKNOWN"}]})
        if kind == "ah-requirements":
            return 0, json.dumps({"read": read, "total": 1, "truncated": False,
                                  "requirements": [{"id": "r1", "text": "R", "at": stamp(), "ticket": "goodqa#1"}]})
        if kind == "ah-status":
            return 0, json.dumps({"read": read, "session": SID, "since_s": 43200, "entries": 1, "unread": [], "owners": {"counts": {}},
                                  **{k: [] for k in col.Ledger.STATUS_LISTS}})
        if kind == "ah-ticket-comments":
            return 0, json.dumps({"comments": [{"id": "c1", "body": "checkpoint", "createdAt": stamp()}]})
        if kind == "ah-ticket-get":
            return 0, json.dumps({"issue": {"closedAt": None}})
        if kind == "gh-user":
            return 0, json.dumps({"login": "someone"})
        if kind == "gh-events":
            return 0, json.dumps([{"type": "PushEvent", "id": "1", "repo": {"name": "o/r"}, "created_at": stamp(),
                                   "payload": {"ref": "refs/heads/x", "size": 1}}])
        if kind == "remote-wal-probe":
            return 0, "/h/.claude/wals/s1/agent-x.jsonl\t" + json.dumps({"event": "result", "note": "remote"}) + "\x1e\n"
        return 1, ""


def App(base: Path, remote=False, runner=None, initiatives=None, wal_roots=None):
    return mcs.App(port=1, root=base / "mc", initiatives=initiatives, remote=remote, fabric_bin=None, runner=runner or Outputs(),
                   wal_roots=wal_roots or [(base / "nowals", "claude")], start_threads=False, codex=False)


class Named:
    def __init__(self, name):
        self.name = name


class Trace:
    """Observes one run of the real App: which collector published each snapshot and each event, which Health rows
    each wrote, which other collector's data each read, and which ledger parts were read for a session."""

    def __init__(self):
        self.stack = []
        self.snapshots = collections.defaultdict(set)   # snapshot name -> collectors that pushed it
        self.events = set()                             # collectors that published a feed event
        self.rows = collections.defaultdict(set)        # collector -> Health rows it wrote
        self.cross = set()                              # (reader, provider, attribute)
        self.session_parts = set()                      # ledger parts read with a session argument
        self.unattributed = set()                       # ("row" | "snapshot" | "event", name) written with no source on the stack
        self.patches = []

    def active(self):
        return self.stack[-1] if self.stack else None

    def wrap_methods(self, cls):
        trace = self
        for name, func in list(vars(cls).items()):
            if name.startswith("__") or not callable(func) or isinstance(func, (staticmethod, classmethod, type)):
                continue

            def make(func=func):
                def wrapped(self, *args, **kwargs):
                    trace.stack.append(self)
                    try:
                        return func(self, *args, **kwargs)
                    finally:
                        trace.stack.pop()
                return wrapped
            self.patches.append(mock.patch.object(cls, name, make()))

    def start(self, app):
        trace = self
        classes = {type(c) for c in vars(app).values() if isinstance(c, col.Collector)}
        for cls in classes:
            for klass in cls.__mro__:
                if klass is not object and klass.__module__ == col.__name__:
                    self.wrap_methods(klass)
        plain = col.Collector.__getattribute__

        def spy(self, name):
            reader = trace.active()
            if reader is not None and reader is not self and reader.name != "truth" and not name.startswith("_") \
                    and name not in ("name", "hub", "health"):
                trace.cross.add((reader.name, object.__getattribute__(self, "name"), name))
            return plain(self, name)
        self.patches.append(mock.patch.object(col.Collector, "__getattribute__", spy))
        real_set, real_snapshot, real_publish, real_read = col.Health._set, ev.Hub.snapshot, ev.Hub.publish, col.Ledger._read

        def health_set(health, name, *args, **kwargs):
            if trace.active() is None:
                trace.unattributed.add(("row", name))
            elif trace.active().name != "truth":
                trace.rows[trace.active().name].add(name)
            return real_set(health, name, *args, **kwargs)

        def snapshot(hub, name, data):
            if trace.active() is None:
                trace.unattributed.add(("snapshot", name))
            elif trace.active().name != "truth":
                trace.snapshots[name].add(trace.active().name)
            return real_snapshot(hub, name, data)

        def publish(hub, event):
            if trace.active() is None:
                trace.unattributed.add(("event", event.get("kind")))
            else:
                trace.events.add(trace.active().name)
            return real_publish(hub, event)

        def read(ledger, part, label, kind, args, parse, now):
            if args:
                trace.session_parts.add(part)
            return real_read(ledger, part, label, kind, args, parse, now)
        self.patches += [mock.patch.object(col.Health, "_set", health_set), mock.patch.object(ev.Hub, "snapshot", snapshot),
                         mock.patch.object(ev.Hub, "publish", publish), mock.patch.object(col.Ledger, "_read", read)]
        # Truth recomposes the reads inside every push; what it reads is its own business, not the pushing collector's
        real_publish_truth, real_reads = col.Truth.publish, col.Truth.reads

        def outside(real):
            def wrapped(truth, *args, **kwargs):
                trace.stack.append(Named("truth"))
                try:
                    return real(truth, *args, **kwargs)
                finally:
                    trace.stack.pop()
            return wrapped
        self.patches += [mock.patch.object(col.Truth, "publish", outside(real_publish_truth)), mock.patch.object(col.Truth, "reads", outside(real_reads))]
        # the chat store is read by the App itself, not by a Collector: its methods are traced as the source "chat"
        for method in ("chat_once", "refresh_chat", "chat_snapshot"):
            def as_chat(real=getattr(mcs.App, method)):
                def wrapped(app_, *args, **kwargs):
                    trace.stack.append(Named("chat"))
                    try:
                        return real(app_, *args, **kwargs)
                    finally:
                        trace.stack.pop()
                return wrapped
            self.patches.append(mock.patch.object(mcs.App, method, as_chat()))
        for patch in self.patches:
            patch.start()
        # callbacks bound before the trace started are bound again, so the work they do is seen as their owner's
        app.health.on_change = app.truth.publish
        app.hub.before = app.truth.publish
        if app.supervised:
            app.supervised.on_change = app.owners.publish
        app.tailer.on_ask = app.asks.mark_dirty

    def stop(self):
        for patch in reversed(self.patches):
            patch.stop()


class DerivedFeeds(unittest.TestCase):
    """collectors.FEEDS is compared with what a traced run of the real App shows. It fails when a collector, a Health
    row, a snapshot or a read between collectors exists that FEEDS, NOT_A_FEED or SAFE_READS does not account for:
    that is how a stacked change (an owner-policy row, a session pin, an org graph) is made to declare itself."""

    DATA_SNAPSHOTS = {"owners": "owners", "asks": "asks", "initiatives": "initiatives", "chat": "chat"}
    META_SNAPSHOTS = {"health", "reads", "ledger"}
    STATE_META = {"version", "stream", "started", "host", "health", "limits", "reads", "requirement_actions", "events", "ledger"}
    # a row one collector writes about something other than its own rows
    ROW_ROLES = {("owners", "main-session"): "what the owners read knows of main's session: it feeds the session-scoped datasets"}

    def run_app(self):
        tmp = tempfile.TemporaryDirectory(prefix="mc-chain-")
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        home = base / "home"
        claude, codex = home / ".claude" / "wals", home / ".agent-harness" / "codex-wals"
        (claude / SID).mkdir(parents=True)
        (codex / "thread-00000001").mkdir(parents=True)
        (claude / SID / f"agent-{HEX}.jsonl").write_text(json.dumps({"event": "intent", "note": "start", "at": stamp()}) + "\n")
        (codex / "thread-00000001" / "main.jsonl").write_text(json.dumps({"event": "result", "note": "done", "at": stamp()}) + "\n")
        supervised = home / ".agent-harness" / "codex-owners" / "worker-a"
        supervised.mkdir(parents=True)
        (supervised / "status.json").write_text(json.dumps({"name": "worker-a", "harness": "openai", "state": "running",
                                                            "supervisor_pid": os.getpid(), "thread": "thread-00000001"}))
        initiatives = base / "initiatives.json"
        initiatives.write_text(json.dumps({"initiatives": [{"id": "i1", "initiative": "Ship", "ticket": "goodqa#1"}]}))
        for patch in (mock.patch.dict(os.environ, {"MC_HOME": str(base / "mc")}), mock.patch.object(Path, "home", return_value=home)):
            patch.start()
            self.addCleanup(patch.stop)
        runner = Outputs()
        app = App(base, remote=True, runner=runner, initiatives=str(initiatives), wal_roots=[(claude, "claude"), (codex, "codex")])
        (base / "mc" / "sources" / "ext.jsonl").write_text(json.dumps(ev.make("deploy", "ext", "deployed", eid="ext-1")) + "\n")
        trace = Trace()
        trace.start(app)
        self.addCleanup(trace.stop)
        # every Collector the App holds, however it is wired: a new one is run and traced without being listed here
        sources = list({id(c): c for c in vars(app).values() if isinstance(c, col.Collector)}.values())
        sources += [c for c in app.collectors if c not in sources]
        now = time.time()
        for source in sources:
            source.run(now)
        # a second pass with changed inputs: sources publish feed events only on a change
        runner.state = "DROPPED"
        initiatives.write_text(json.dumps({"initiatives": [{"id": "i1", "initiative": "Ship it", "ticket": "goodqa#1"}]}))
        with open(claude / SID / f"agent-{HEX}.jsonl", "a") as handle:
            handle.write(json.dumps({"event": "result", "note": "DEPLOYED to live", "at": stamp(0)}) + "\n")
        for source in sources:
            source.run(now + 400)
        app.chat_once()
        app.follow_sessions()
        state = app.state()
        return app, trace, state

    def test_declared_feeds_equal_the_observed_ones(self):
        app, trace, state = self.run_app()
        self.assertFalse([r for r in app.health.rows.values() if r["status"] == "error"], "the fixture reads everything")
        derived = collections.defaultdict(set)
        for snapshot, writers in trace.snapshots.items():
            if snapshot in self.META_SNAPSHOTS:
                continue
            self.assertIn(snapshot, self.DATA_SNAPSHOTS, f"snapshot {snapshot!r} is pushed to the page but is no dataset in FEEDS")
            for writer in writers:
                derived[self.DATA_SNAPSHOTS[snapshot]] |= self.sources_of(writer, trace)
        derived["events"] = set().union(*(self.sources_of(writer, trace) for writer in trace.events))
        # a ledger part rests on its own read, on anything else the ledger source wrote or read, and on main's session
        # when its read took one
        beside = self.sources_of("ledger", trace) - {"ledger"}
        for part in ("goals", "requirements", "status"):
            derived[part] = {f"ledger:{part}"} | beside | ({"main-session"} if part in trace.session_parts else set())
        # every read of main's session is declared: the dataset its reader publishes rests on main-session
        for reader, provider, attribute in trace.cross:
            if attribute == "session" and reader in self.DATA_SNAPSHOTS:
                derived[self.DATA_SNAPSHOTS[reader]].add("main-session")
        self.assertEqual({k: sorted(v) for k, v in derived.items()}, {k: sorted(v) for k, v in col.FEEDS.items()})
        self.assertEqual(sorted(trace.unattributed), [], "a Health row, snapshot or event written by no traced source: give it a "
                                                         "Collector (or trace its writer as a named source) and a line in FEEDS")

    def sources_of(self, writer, trace):
        """A collector's own row, the other rows it writes, and every collector whose data it reads (unless that read
        is declared safe), followed through."""
        seen, todo = set(), [writer]
        while todo:
            name = todo.pop()
            if name in seen:
                continue
            seen.add(name)
            for reader, provider, attribute in trace.cross:
                if reader != name:
                    continue
                reason = col.SAFE_READS.get((reader, provider, attribute))
                if reason is None or reason.startswith("covered"):
                    if attribute != "session":
                        todo.append(provider)
        rows = set()
        for name in seen:
            rows |= {name} | {row for row in trace.rows.get(name, ()) if (name, row) not in self.ROW_ROLES}
        return rows

    def test_every_read_between_collectors_is_a_feed_or_a_stated_exemption(self):
        _app, trace, _state = self.run_app()
        unknown = sorted(edge for edge in trace.cross if edge not in col.SAFE_READS)
        self.assertEqual(unknown, [], "a collector reads another's data: add the provider to FEEDS, or the edge to SAFE_READS with its reason")
        for (reader, provider, attribute), reason in col.SAFE_READS.items():
            self.assertTrue(reason.strip())
            if reason.startswith("covered") and attribute != "session":
                into = [self.DATA_SNAPSHOTS[s] for s, writers in trace.snapshots.items() if reader in writers and s in self.DATA_SNAPSHOTS]
                into += ["events"] if reader in trace.events else []
                for dataset in into:
                    self.assertIn(provider, col.FEEDS[dataset], f"{reader} reads {provider}.{attribute} into {dataset}")

    def test_every_health_row_and_state_key_is_accounted_for(self):
        app, _trace, state = self.run_app()
        fed = {source for sources in col.FEEDS.values() for source in sources}
        stray = sorted(name for name in app.health.rows if name not in fed and name not in col.NOT_A_FEED)
        self.assertEqual(stray, [], "a Health row that feeds no dataset and is not in NOT_A_FEED")
        self.assertEqual(sorted(name for name in fed if not name.startswith("ledger:") and name not in app.health.rows), [],
                         "FEEDS names a source that reported no row: the page would hold its datasets unknown for ever")
        known = set(self.DATA_SNAPSHOTS) | self.STATE_META
        self.assertEqual(sorted(set(state) - known), [], "a key of /api/state that is neither a dataset nor declared meta")
        self.assertEqual(sorted(state["reads"]), sorted(col.FEEDS))

    def test_a_seeded_undeclared_source_fails_the_derivation(self):
        """The shape of T242-1 and T243-2: a collector writes a row, or pushes a snapshot, that FEEDS does not name."""
        app, trace, _state = self.run_app()
        trace.rows["owners"].add("seeded-undeclared-row")  # owner-policy itself is declared since T242-1
        derived = self.sources_of("owners", trace)
        self.assertNotEqual(sorted(derived), sorted(col.FEEDS["owners"]))
        trace.snapshots["org"].add("orggraph")
        self.assertNotIn("org", self.DATA_SNAPSHOTS)
        # the shape of T243-6: a row written while the ledger reads (a session pin) reaches every ledger part
        trace.rows["ledger"].add("session-pin")
        self.assertIn("session-pin", self.sources_of("ledger", trace))
        # and a writer that is no Collector at all is reported, not ignored
        app.health.error("session-pin", "pin not writable")
        app.hub.snapshot("org", {})
        self.assertEqual(sorted(trace.unattributed), [("row", "session-pin"), ("snapshot", "health"), ("snapshot", "org")])

    def test_no_source_is_aged_out_while_its_thread_is_still_reading(self):
        app, _trace, _state = self.run_app()
        loop = sum(source.read_budget for source in app.collectors)
        for source in app.collectors:
            for name in (source.name,) + tuple(source.rows_written):
                self.assertGreaterEqual(app.max_ages[name], max(source.interval, source.idle_interval) + loop, name)
        for source in (app.asks, app.ledger):
            self.assertGreaterEqual(app.max_ages[source.name], max(source.interval, source.idle_interval) + source.read_budget)
        self.assertEqual(sorted(set(app.health.rows) - set(app.max_ages) - set(col.NOT_A_FEED)), [], "a row no reader ages out")


class Envelope(unittest.TestCase):
    """producer_read: the one parse of a producer run. Nothing short of a whole read is whole."""

    WHOLE = {"schema": "harness.read/1", "state": "ok", "sources_read": 1, "unread_total": 0, "unread": [], "skipped": 0, "limited": False}

    def test_table(self):
        whole = json.dumps({"read": self.WHOLE, "rows": []})
        partial = dict(self.WHOLE, state="partial")
        rows = [
            ("timeout", 124, "", None),
            ("refused exit code", 3, whole, None),
            ("oversize", 0, whole + " " * 2048, None),
            ("not JSON", 0, "{not json", None),
            ("not an object", 0, "[]", None),
            ("no read block", 0, json.dumps({"rows": []}), None),
            ("unknown schema", 0, json.dumps({"read": dict(self.WHOLE, schema="x")}), None),
            ("unknown state", 0, json.dumps({"read": dict(self.WHOLE, state="fine")}), None),
            ("failed", 0, json.dumps({"read": dict(self.WHOLE, state="failed", unread=[{"source": "main.jsonl", "reason": "denied"}])}), None),
            ("whole", 0, whole, 0),
            ("partial: unread", 0, json.dumps({"read": dict(partial, unread_total=1, unread=[{"source": "agent-x.jsonl", "reason": "denied"}])}), 1),
            ("partial: skipped", 0, json.dumps({"read": dict(partial, skipped=2)}), 1),
            ("partial: limited", 0, json.dumps({"read": dict(partial, limited=True)}), 1),
            ("partial with no reason", 0, json.dumps({"read": partial}), 1),
            ("says ok but lists an unread source", 0, json.dumps({"read": dict(self.WHOLE, unread=[{"source": "x", "reason": "y"}])}), 1),
            ("says ok but skipped is missing", 0, json.dumps({"read": {k: v for k, v in self.WHOLE.items() if k != "skipped"}}), 1),
            ("says ok but limited is missing", 0, json.dumps({"read": {k: v for k, v in self.WHOLE.items() if k != "limited"}}), 1),
        ]
        for name, code, out, notes in rows:
            with self.subTest(name):
                if notes is None:
                    with self.assertRaises(col.ReadFailed):
                        col.producer_read("ah x", code, out, cap=len(whole) + 1024)
                else:
                    _data, found = col.producer_read("ah x", code, out, cap=len(whole) + 1024)
                    self.assertEqual(len(found), notes)

    def test_the_producers_send_the_block(self):
        home = Home(self)
        for data in (ah.requirements_view(home.home, SID), ah.status_report(home.home, SID, 43200), ah.owners(home.home, SID),
                     prov.ask_items(SID, home.home / ".claude")):
            self.assertEqual((data["read"]["schema"], data["read"]["state"]), ("harness.read/1", "ok"))
        missing = "abcdef12-0000-4000-8000-00000000dead"
        self.assertEqual(ah.requirements_view(home.home, missing)["read"]["state"], "failed")
        self.assertEqual(prov.ask_items(missing, home.home / ".claude")["read"]["state"], "failed")


class AgedOut(unittest.TestCase):
    """A source whose reader stopped is not current for ever, and a session-scoped row read for another session is
    never this session's read."""

    def setUp(self):
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)

    def test_a_row_not_checked_within_its_max_age_turns_stale_then_recovers(self):
        self.health.ok("owners", "3 owners")
        self.health.off("t2-dev", "remote probe disabled", truth="current")
        now = time.time()
        self.assertEqual(self.health.expire({"owners": 100.0, "t2-dev": 100.0}, now + 50), [])
        self.assertEqual(self.health.expire({"owners": 100.0, "t2-dev": 100.0}, now + 101), ["owners"])
        row = self.health.rows["owners"]
        self.assertEqual((row["status"], row["truth"]), ("error", "stale"))
        self.assertIn("reader may have stopped", row["detail"])
        self.assertEqual(self.health.rows["t2-dev"]["truth"], "current", "a source that is off has no reader to stop")
        self.health.ok("owners", "3 owners")
        self.assertEqual(self.health.rows["owners"]["truth"], "current")

    def test_a_row_never_read_ages_to_unknown_and_a_beat_keeps_a_row(self):
        self.health.error("asks", "boom")
        self.health.ok("chat", "chat store read")
        now = time.time()
        with mock.patch.object(time, "time", return_value=now + 90):
            self.health.beat("chat")
        self.assertEqual(self.health.expire({"asks": 100.0, "chat": 100.0}, now + 150), ["asks"])
        self.assertEqual(self.health.rows["asks"]["truth"], "unknown")

    def test_a_dataset_is_the_worst_of_its_sources_and_a_missing_source_is_unknown(self):
        truth = col.Truth(self.hub, self.health, None, lambda: SID, feeds={"owners": ("owners", "wals"), "nothing": ()})
        self.assertEqual(truth.reads()["owners"]["truth"], "unknown")
        self.health.ok("owners", "1")
        self.assertEqual(truth.reads()["owners"]["truth"], "unknown", "wals has not reported")
        self.health.ok("wals", "1", truth="partial")
        self.assertEqual(truth.reads()["owners"]["truth"], "partial")
        self.health.error("owners", "boom")
        self.assertEqual(truth.reads()["owners"]["truth"], "stale")
        self.assertEqual(truth.reads()["nothing"]["truth"], "unknown")

    def test_a_row_read_for_another_session_is_unknown_not_stale(self):
        truth = col.Truth(self.hub, self.health, None, lambda: SID, feeds={"asks": ("asks",)})
        self.health.ok("asks", "0 open", session="another-session-0001")
        self.assertEqual(truth.reads()["asks"]["truth"], "unknown")
        self.health.ok("asks", "0 open", session=SID)
        self.assertEqual(truth.reads()["asks"]["truth"], "current")

    def test_the_reads_go_out_before_the_rows(self):
        order = []
        real = self.hub._broadcast
        self.hub._broadcast = lambda frame: (order.append(frame.split(b"\n")[1].decode()), real(frame))
        truth = col.Truth(self.hub, self.health, None, lambda: SID, feeds={"owners": ("owners",)})
        self.health.on_change = truth.publish
        self.hub.before = truth.publish
        self.health.ok("owners", "1")
        self.hub.snapshot("owners", [])
        self.health.error("owners", "boom")
        self.assertEqual(order, ["event: health", "event: reads", "event: owners", "event: health", "event: reads"])


if __name__ == "__main__":
    unittest.main()
