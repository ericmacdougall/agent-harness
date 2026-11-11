"""Mission Control server, collectors and responder (GoodQA #15585). Classes map to spec ACs/NEGs:
Initiatives AC-1/NEG-1, WalTail AC-2/NEG-2/NEG-9, GithubEvents+Deploys AC-3/NEG-3, TicketPoll AC-4/NEG-4,
CodexResponder AC-6/NEG-6, Security AC-7/NEG-7, ReadOnly+Redaction AC-8/NEG-8, Budget AC-9/NEG-9,
Schema+FileDrop AC-13/NEG-13."""
import http.client
import importlib.util
import json
import os
import re
import socket
import stat
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import mc_chat  # noqa: E402
import safeio  # noqa: E402
import server as mcs  # noqa: E402
from codex_responder import CodexResponder, StreamRedactor  # noqa: E402

GH_TOKEN = "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6"
STRIPE = "sk" + "_live_" + "Ab3dEf6hIj9kLm2nOp5qRs8t"


class FakeRunner:
    """Canned outputs per allowlisted shape; records every call. Unknown shapes raise like the real Runner."""

    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []
        self.real = safeio.Runner(python=sys.executable, ah="/x/ah.py", codex="/x/codex", fabric_bin=None)

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.real.argv(kind, *args)  # refuses anything off the allowlist
        self.calls.append((kind, args, time.time()))
        value = self.outputs.get(kind, (0, "{}"))
        return value(*args) if callable(value) else value


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "mc"
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.hub = ev.Hub(max_rate=10_000)
        self.health = col.Health(self.hub)

    def kinds(self):
        return [e["kind"] for e in self.hub.recent()]


class Initiatives(Tmp):
    def write(self, value):
        self.path.write_text(value if isinstance(value, str) else json.dumps(value))
        os.utime(self.path, ns=(time.time_ns(), time.time_ns() + self.bump))
        self.bump += 10**9

    def setUp(self):
        super().setUp()
        self.bump = 0
        self.path = self.base / "dash" / "initiatives.json"
        self.path.parent.mkdir()
        self.reader = safeio.Reader([self.path.parent])
        self.collector = col.Initiatives(self.hub, self.health, self.reader, self.path)

    def row(self, **over):
        row = {"id": "leads", "initiative": "Leads", "state": "At risk", "milestones_done": 2, "milestones_total": 5,
               "pct": 40, "owner": "none", "ticket": "goodqa#15095", "milestones": "Done: a · Not yet: b",
               "next_step": "rerun", "next_eta": "~3 h", "full_eta": "~2 days", "note": "", "updated": "x"}
        row.update(over)
        return row

    def test_progress_eta_and_estimator_come_from_the_file(self):
        self.write([self.row(), self.row(id="t", milestones_done=None, milestones_total=None, pct=None,
                                         estimate_by="owner aaef3bc7")])
        self.collector.run(time.time())
        items = self.collector.items
        self.assertEqual((items[0]["milestones_done"], items[0]["milestones_total"], items[0]["pct"]), (2, 5, 40))
        self.assertEqual(items[0]["estimate_by"], "main")
        self.assertEqual(items[0]["full_eta"], "~2 days")
        self.assertEqual([m["done"] for m in items[0]["milestone_items"]], [True, False])
        self.assertIsNone(items[1]["pct"], "null counts stay indeterminate, never 0%")
        self.assertEqual(items[1]["estimate_by"], "owner aaef3bc7")

    def test_edits_are_picked_up_and_pulse(self):
        self.write([self.row()])
        self.collector.run(time.time())
        self.write([self.row(milestones_done=3)])
        self.collector.run(time.time())
        self.assertEqual(self.collector.items[0]["pct"], 60)
        self.assertIn("initiative", self.kinds())

    def test_bad_file_keeps_the_last_good_snapshot(self):
        self.write([self.row()])
        self.collector.run(time.time())
        self.write('[{"id": "leads", "initiat')
        self.collector.run(time.time())
        self.assertTrue(self.collector.stale)
        self.assertEqual(len(self.collector.items), 1)
        self.assertEqual(self.health.rows["initiatives"]["status"], "error")

    def test_bad_rows_show_a_data_error(self):
        self.write([self.row(milestones_done=7, milestones_total=5), self.row(milestones_done="two"), 42])
        self.collector.run(time.time())
        items = self.collector.items
        self.assertIn("error", items[0])
        self.assertIsNone(items[0]["pct"] if items[0]["pct"] != 40 else None)
        self.assertIn("error", items[1])
        self.assertEqual(items[2]["initiative"], "data error")

    def test_missing_file_is_an_error_not_a_crash(self):
        self.collector.run(time.time())
        self.assertEqual(self.health.rows["initiatives"]["status"], "error")


class WalTail(Tmp):
    def setUp(self):
        super().setUp()
        self.wals = self.base / "wals"
        self.codex = self.base / "codex-wals"
        (self.wals / "sess1").mkdir(parents=True)
        (self.codex / "thread1").mkdir(parents=True)
        self.reader = safeio.Reader([self.wals, self.codex])
        self.tailer = col.WalTailer(self.hub, self.health, self.reader, [(self.wals, "claude"), (self.codex, "codex")])

    def append(self, path, *entries, raw=b""):
        with open(path, "ab") as handle:
            for entry in entries:
                handle.write(json.dumps(entry).encode() + b"\n")
            handle.write(raw)

    def test_existing_lines_seed_last_item_without_pulsing_then_appends_pulse(self):
        agent = self.wals / "sess1" / "agent-abc.jsonl"
        self.append(agent, {"at": "t0", "event": "intent", "note": "old work"})
        self.tailer.run(time.time())
        self.assertEqual(self.hub.recent(), [])
        self.assertEqual(self.tailer.last_for("claude", "sess1", "abc")["note"], "old work")
        self.append(agent, {"at": "t1", "event": "result", "note": "REALLY_TESTED x: passed"})
        self.tailer.run(time.time())
        events = self.hub.recent()
        self.assertEqual(events[-1]["kind"], "wal")
        self.assertEqual(events[-1]["actor"], {"runtime": "claude", "session": "sess1", "agent": "abc"})
        self.assertEqual(self.tailer.last_for("claude", "sess1", "abc")["event"], "result")

    def test_real_progress_is_tracked_apart_from_notes(self):  # goodqa#15585 slowest / at risk
        agent = self.wals / "sess1" / "agent-pro.jsonl"
        self.append(agent, {"at": "2026-11-10T01:00:00Z", "event": "commit", "note": "abc123 pushed"},
                    {"at": "2026-11-10T01:30:00Z", "event": "intent", "note": "plan the next step"})
        self.tailer.run(time.time())  # seed path
        last = self.tailer.last_for("claude", "sess1", "pro")
        self.assertEqual((last["note"], last["progress_at"], last["progress_event"]),
                         ("plan the next step", "2026-11-10T01:00:00Z", "commit"))
        self.append(agent, {"at": "2026-11-10T02:00:00Z", "event": "note", "note": "thinking"},
                    {"at": "2026-11-10T02:05:00Z", "event": "check", "note": "gate", "by": "dropped_gate"})
        self.tailer.run(time.time())  # append path: a note and a gate-written line are not progress
        self.assertEqual(self.tailer.last_for("claude", "sess1", "pro")["progress_at"], "2026-11-10T01:00:00Z")
        self.append(agent, {"at": "2026-11-10T02:10:00Z", "event": "result", "note": "REALLY_TESTED y: ok"})
        self.tailer.run(time.time())
        self.assertEqual(self.tailer.last_for("claude", "sess1", "pro")["progress_at"], "2026-11-10T02:10:00Z")

    def test_codex_wal_and_new_files_are_found(self):
        self.tailer.run(time.time())
        main = self.codex / "thread1" / "main.jsonl"
        self.append(main, {"at": "t", "event": "UserPromptSubmit", "prompt_chars": 12})
        self.tailer.last_scan = 1.0  # force the rescan that finds new files
        self.tailer.run(time.time())
        self.assertEqual(self.hub.recent()[-1]["actor"]["runtime"], "codex")

    def test_partial_lines_wait_for_their_newline_and_garbage_is_skipped(self):
        path = self.wals / "sess1" / "main.jsonl"
        path.write_text("")
        self.tailer.run(time.time())
        self.append(path, raw=b'not json\n{"event":"intent","note":"half')
        self.tailer.run(time.time())
        self.assertEqual(self.hub.recent(), [])
        self.append(path, raw=b' done"}\n')
        self.tailer.run(time.time())
        self.assertIn("half done", self.hub.recent()[-1]["summary"])

    def test_over_long_line_and_truncation_are_survived(self):
        path = self.wals / "sess1" / "main.jsonl"
        path.write_text("")
        self.tailer.run(time.time())
        self.append(path, raw=b"x" * (70 * 1024) + b"\n")
        self.tailer.run(time.time())
        path.write_text(json.dumps({"event": "intent", "note": "after truncate"}) + "\n")
        self.tailer.run(time.time())
        self.assertIn("after truncate", self.hub.recent()[-1]["summary"])

    def test_tool_calls_collapse_into_one_event(self):
        path = self.wals / "sess1" / "agent-x.jsonl"
        path.write_text("")
        self.tailer.run(time.time())
        self.append(path, *[{"event": "pretool", "tool": "Bash"} for _ in range(40)])
        self.tailer.run(time.time())
        events = self.hub.recent()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["count"], 40)

    def test_tool_and_lifecycle_lines_are_quiet_and_keep_the_last_work_item(self):
        path = self.wals / "sess1" / "agent-q.jsonl"
        path.write_text("")
        self.tailer.run(time.time())
        self.append(path, {"at": "2026-11-09T22:00:00Z", "event": "intent", "note": "wire the SSE stream"})
        self.tailer.run(time.time())
        self.append(path, {"at": "2026-11-09T22:05:00Z", "event": "pretool", "tool": "Bash"},
                    {"at": "2026-11-09T22:06:00Z", "event": "subagent", "agent_id": "a22e3925b2329ce4d",
                     "agent_type": "red-team"},
                    {"at": "2026-11-09T22:07:00Z", "event": "pending_stop", "by": "dropped_gate",
                     "note": "stopped with pending work and no armed waiter"})
        self.tailer.run(time.time())
        last = self.tailer.last_for("claude", "sess1", "q")
        self.assertEqual(last["note"], "wire the SSE stream", "tool calls and gate notes never replace the work item")
        self.assertEqual(last["active_at"], "2026-11-09T22:07:00Z")
        events = self.hub.recent()
        self.assertFalse(events[0].get("quiet"))
        self.assertEqual([e.get("quiet") for e in events[1:]], [True, True, True])
        self.assertIn("started red-team a22e3925", [e["summary"] for e in events])

    def test_symlinked_wal_is_not_followed(self):
        secret = self.base / "secret.txt"
        secret.write_text(json.dumps({"event": "intent", "note": "SECRET CONTENT"}) + "\n")
        os.symlink(secret, self.wals / "sess1" / "agent-evil.jsonl")
        self.tailer.run(time.time())
        self.tailer.last_scan = 1.0
        self.tailer.run(time.time())
        self.assertNotIn(str(self.wals / "sess1" / "agent-evil.jsonl"), self.tailer.files)
        self.assertNotIn("SECRET CONTENT", json.dumps(self.hub.recent()))

    def test_flood_is_bounded(self):
        path = self.wals / "sess1" / "agent-f.jsonl"
        path.write_text("")
        self.tailer.run(time.time())
        self.append(path, *[{"event": "intent", "note": f"line {n}"} for n in range(1000)])
        self.tailer.run(time.time())
        events = self.hub.recent()
        self.assertLessEqual(len(events), self.tailer.max_events_per_tick + 1)
        self.assertEqual(sum(e["count"] for e in events if e["id"].startswith("walburst")) + len(events) - 1, 1000)


class Deploys(WalTail):
    def test_deployed_note_is_a_deploy_pulse(self):
        path = self.wals / "sess1" / "agent-d.jsonl"
        path.write_text("")
        self.tailer.run(time.time())
        self.append(path, {"event": "result", "note": "DEPLOYED 0e2084b on t2-dev via deploy-live.sh"})
        self.tailer.run(time.time())
        self.assertEqual(self.kinds(), ["wal", "deploy"])


class GithubEvents(Tmp):
    FEED = [
        {"id": "3", "type": "PushEvent", "repo": {"name": "eric/agent-harness"}, "created_at": "2026-11-09T22:00:00Z",
         "payload": {"ref": "refs/heads/feat/x", "size": 2}},
        {"id": "2", "type": "ReleaseEvent", "repo": {"name": "eric/goodqa"}, "created_at": "2026-11-09T21:00:00Z",
         "payload": {"action": "published", "release": {"tag_name": "v0.2.57"}}},
        {"id": "1", "type": "WatchEvent", "repo": {"name": "x/y"}, "created_at": "2026-11-09T20:00:00Z", "payload": {}},
    ]

    def test_push_and_release_events(self):
        feed = list(self.FEED)
        runner = FakeRunner({"gh-user": (0, '{"login": "eric"}'), "gh-events": lambda login: (0, json.dumps(feed))})
        gh = col.GitHub(self.hub, self.health, runner)
        gh.run(time.time())
        first = self.hub.recent()
        self.assertEqual([e["kind"] for e in first], ["release", "push"])
        self.assertTrue(all(e.get("historic") for e in first), "the first page is history, not pulses")
        feed.insert(0, {"id": "4", "type": "PushEvent", "repo": {"name": "eric/t2-sites"},
                        "created_at": "2026-11-09T22:05:00Z", "payload": {"ref": "refs/heads/main", "size": 1}})
        gh.run(time.time() + 61)
        new = self.hub.recent()[-1]
        self.assertEqual((new["kind"], new["subject"]["branch"]), ("push", "main"))
        self.assertNotIn("historic", new)
        self.assertEqual(len(self.hub.recent()), 3, "already-seen events are not repeated")

    def test_failure_is_shown_and_not_retried_faster(self):
        runner = FakeRunner({"gh-user": (1, "")})
        gh = col.GitHub(self.hub, self.health, runner)
        now = time.time()
        gh.run(now)
        self.assertEqual(self.health.rows["github"]["status"], "error")
        self.assertFalse(gh.due(now + 30))
        self.assertTrue(gh.due(now + 60))


class TicketPoll(Tmp):
    def test_new_comment_pulses_once_and_reads_are_rate_bounded(self):
        comments = {"comments": [{"id": "c1", "body": "old", "createdAt": "2026-11-09T20:00:00Z"}]}
        runner = FakeRunner({"ah-ticket-comments": lambda ref: (0, json.dumps(comments))})
        poll = col.Tickets(self.hub, self.health, runner, lambda: ["goodqa#15585", "bad ref; rm -rf /", "x#1"])
        self.assertEqual(poll.tracked(), ["goodqa#15585", "x#1"])
        now = time.time()
        poll.run(now)
        comments["comments"].append({"id": "c2", "body": "checkpoint: PR ready " + GH_TOKEN,
                                     "createdAt": "2026-11-09T22:00:00Z"})
        poll.run(now + 10)  # x#1's turn
        poll.run(now + 20)
        tickets = [e for e in self.hub.recent() if e["kind"] == "ticket"]
        self.assertEqual([e.get("historic", False) for e in tickets if e["subject"]["ticket"] == "goodqa#15585"],
                         [True, False])
        self.assertNotIn(GH_TOKEN, json.dumps(tickets))
        times = [c[2] for c in runner.calls]
        self.assertFalse(poll.due(now + 25), "one read per 10 s")
        self.assertEqual(len(times), 3)

    def test_at_most_twelve_tickets(self):
        poll = col.Tickets(self.hub, self.health, FakeRunner(), lambda: [f"goodqa#{n}" for n in range(1, 40)])
        self.assertEqual(len(poll.tracked()), 12)


class OwnersPoll(Tmp):
    def rows(self, state="DROPPED"):
        return {"session": "sess1", "owners": [
            {"agent_id": "aaef3bc7aaaa", "state": state, "task": "build tokens", "ticket": "goodqa#15561", "idle_s": 600,
             "disposition": {"kind": "waiting", "ref": "GoodQA goodqa#15561", "reason": "waiting on its own background work",
                             "until": 1794787200.0, "live": True, "evidence": "secret-ish " + GH_TOKEN}},
            {"agent_id": "abbbbbbb", "state": "returned", "idle_s": 7 * 3600},
            {"agent_id": "acccccc; rm", "state": "live", "idle_s": 5},
            {"agent_id": "acccccc", "state": "live", "idle_s": 5},
        ]}

    def test_rows_keep_state_and_disposition_and_drop_old_terminal_helpers(self):
        data = self.rows()
        runner = FakeRunner({"ah-owners": lambda: (0, json.dumps(data))})
        wals = self.base / "w"
        (wals / "sess1").mkdir(parents=True)
        (wals / "sess1" / "agent-aaef3bc7aaaa.jsonl").write_text(json.dumps({"at": "t", "event": "intent", "note": "polling CI"}) + "\n")
        tailer = col.WalTailer(self.hub, self.health, safeio.Reader([wals]), [(wals, "claude")])
        tailer.run(time.time())
        owners = col.Owners(self.hub, self.health, runner, tailer)
        owners.run(time.time())
        ids = [r["agent_id"] for r in owners.rows]
        self.assertEqual(ids, ["acccccc", "aaef3bc7aaaa"], "old terminal rows and malformed ids are dropped")
        row = owners.rows[1]
        self.assertEqual(row["state"], "DROPPED", "the page shows what ah owners says")
        self.assertEqual(row["disposition"]["kind"], "waiting")
        self.assertIn("own background work", row["disposition"]["reason"])
        self.assertNotIn("evidence", row["disposition"])
        self.assertEqual(row["last_item"]["note"], "polling CI")
        data["owners"][0]["state"] = "live"
        owners.run(time.time() + 61)
        change = [e for e in self.hub.recent() if e["kind"] == "owner"]
        self.assertEqual(change[-1]["summary"], "aaef3bc7aaaa DROPPED → live")


class LaunchAgent(unittest.TestCase):
    def test_plist_is_well_formed_with_xml_characters_in_paths(self):
        import plistlib
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"MC_HOME": str(Path(tmp) / "a&b<c>")}):
            data = plistlib.loads(mcs.plist_text(47615, "/usr/bin/python3").encode())
        self.assertEqual(data["Label"], "com.agent-harness.mission-control")
        self.assertEqual(data["ProgramArguments"][1:], [str(mcs.HERE / "server.py"), "serve", "--port", "47615"])
        self.assertTrue(data["EnvironmentVariables"]["MC_HOME"].endswith("a&b<c>"))
        self.assertTrue(data["KeepAlive"])
        self.assertTrue(data["StandardErrorPath"].endswith("a&b<c>/log/launchd.err.log"))


class Schema(unittest.TestCase):
    def test_made_events_validate_and_bad_ones_do_not(self):
        good = ev.make("push", "github", "x", eid="github:1", subject={"repo": "a/b"})
        self.assertIsNone(ev.validate(good))
        for bad, reason in ((dict(good, schema="mc.event/2"), "unknown schema"), (dict(good, kind="nope"), "unknown kind"),
                            (dict(good, summary="x" * 281), "bad summary"), (dict(good, id="../../etc"), "bad id"),
                            (dict(good, count=True), "bad count"), ("str", "not an object")):
            self.assertEqual(ev.validate(bad), reason)

    def test_json_schema_file_matches_the_kinds(self):
        schema = json.loads((REPO / "docs" / "schemas" / "mc-event-v1.schema.json").read_text())
        self.assertEqual(schema["properties"]["kind"]["enum"], list(ev.KINDS))
        self.assertEqual(schema["properties"]["summary"]["maxLength"], ev.SUMMARY_MAX)
        chat = json.loads((REPO / "docs" / "schemas" / "mc-chat-v1.schema.json").read_text())
        self.assertEqual(chat["properties"]["schema"]["const"], mc_chat.SCHEMA)


class FileDrop(Tmp):
    def test_valid_lines_are_accepted_and_bad_ones_counted(self):
        drop = self.base / "sources"
        drop.mkdir()
        good = ev.make("deploy", "fabric", "fab-live deployed " + STRIPE, eid="fabric:1")
        lines = [json.dumps(good), json.dumps(dict(good, schema="x")), json.dumps(dict(good, id="fabric:2", kind=None)),
                 json.dumps(dict(good, id="fabric:3", summary="y" * 10**6)), "{broken", json.dumps(good)]
        (drop / "fabric.jsonl").write_text("\n".join(lines) + "\n")
        target = self.base / "elsewhere.jsonl"
        target.write_text(json.dumps(dict(good, id="fabric:9")) + "\n")
        os.symlink(target, drop / "evil.jsonl")
        reader = safeio.Reader([drop])
        fd = col.FileDrop(self.hub, self.health, reader, drop)
        for n in range(4):  # the 1 MB line spans several 512 KiB reads
            fd.run(time.time() + 10 * n)
        events = self.hub.recent()
        self.assertEqual([e["id"] for e in events], ["fabric:1"])
        self.assertEqual(events[0]["source"], "fabric")
        self.assertNotIn(STRIPE, json.dumps(events))
        self.assertEqual(fd.skipped, 5)  # schema, kind, oversize, broken, symlink


class PrivacyBoundaries(Tmp):
    @staticmethod
    def shape():
        return "hf_" + "q" * 24

    def test_file_drop_refuses_credential_shapes_before_seen_and_sse(self):
        folder = self.base / "drop"
        folder.mkdir()
        valid = ev.make("deploy", "external", "ordinary", eid="ordinary")
        value = self.shape()
        rejected = [
            dict(valid, id=value),
            dict(valid, id="actor", actor={"session": value}),
            dict(valid, id="subject", subject={"branch": value}),
        ]
        kept = tuple("id-" + "n" * 196 + suffix for suffix in ("a", "b"))
        accepted = [dict(valid, id=event_id, summary="fixture " + value) for event_id in kept]
        (folder / "external.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rejected + accepted))
        (folder / (value + ".jsonl")).write_text(json.dumps(dict(valid, id="pinned-source")) + "\n")
        source = col.FileDrop(self.hub, self.health, mcs.Reader([self.base]), folder)
        client = self.hub.attach()
        source.tick(0)
        recent = self.hub.recent()
        self.assertEqual(source.accepted, len(kept))
        self.assertEqual(source.skipped, len(rejected) + 1)
        self.assertTrue(source.seen == set(kept), "only admitted identities may enter deduplication")
        self.assertTrue(all(value not in path for path in source.files), "refused source must not be retained")
        self.assertTrue([row["id"] for row in recent] == list(kept), "keep distinct exact nonsecret identities")
        self.assertTrue(all("[REDACTED:huggingface]" in row["summary"] for row in recent))
        frames = client.take(0)
        self.assertEqual(len(frames), len(kept))
        self.assertTrue(all(value.encode() not in frame for frame in frames), "no shape may enter an SSE frame")

    def test_raw_trim_and_emitted_word_projection_are_both_checked(self):
        value = self.shape()
        cases = (
            ("source-trim", {"source": "!" * 32 + value}),
            ("actor-trim", {"actor": {"session": "!" * 150 + value}}),
            ("subject-trim", {"subject": {"repo": "!" * 150 + value}}),
            ("word-replacement", {"actor": {"session": "hf?" + "q" * 24}}),
            ("oversized-raw", {"subject": {"ref": "." * 9000}}),
        )
        client = self.hub.attach()
        for label, fields in cases:
            with self.subTest(label=label):
                options = dict(source="ordinary", eid="ordinary")
                options.update(fields)
                self.assertFalse(self.hub.publish(ev.make("wal", summary="ordinary", **options)))
        raw = ev.make("wal", "ordinary", "ordinary", eid="ordinary")
        raw["id"] = value
        self.assertFalse(self.hub.publish(raw))
        self.assertEqual(len(self.hub.recent()), 0)
        self.assertEqual(len(client.take(0)), 0)
        self.assertEqual(self.hub.window[1], 0)

    def test_github_convert_checks_actual_raw_inputs_before_its_earlier_clipping(self):
        value = self.shape()
        cases = (
            ("id", {"id": "." * 26 + value}, {}),
            ("repo", {"repo": {"name": "." * 112 + value}}, {}),
            ("branch", {}, {"ref": "refs/heads/" + "." * 112 + value}),
            ("tag", {"type": "ReleaseEvent"}, {"release": {"tag_name": "." * 72 + value}}),
            ("created-branch", {"type": "CreateEvent"}, {"ref_type": "branch", "ref": "." * 112 + value}),
        )
        for label, fields, payload in cases:
            with self.subTest(label=label):
                item = {"id": 42, "repo": {"name": "owner/repo"}, "type": "PushEvent", "payload": payload}
                item.update(fields)
                self.assertTrue(col.GitHub.convert(item) is None, "raw structured value must be refused")
        normal = col.GitHub.convert({"id": 42, "repo": {"name": "owner/repo"}, "type": "PushEvent",
                                     "payload": {"ref": "refs/heads/topic"}})
        self.assertEqual(normal["id"], "github:42")
        self.assertEqual(normal["subject"]["branch"], "topic")

    def test_local_hostname_is_checked_before_split_and_clipping(self):
        def fresh_events(raw_host):
            spec = importlib.util.spec_from_file_location("fixture_events", ev.__file__)
            module = importlib.util.module_from_spec(spec)
            with mock.patch("socket.gethostname", return_value=raw_host):
                spec.loader.exec_module(module)
            return module

        value = self.shape()
        cases = ("-" * 59 + value + ".local", "fixture-box." + value)
        for index, raw_host in enumerate(cases):
            with self.subTest(case=index):
                module = fresh_events(raw_host)
                hub = module.Hub(max_rate=100)
                client = hub.attach()
                self.assertFalse(hub.publish(module.make("owner", "fixture", "ordinary", eid="ordinary")))
                self.assertFalse(hub.recent())
                self.assertFalse(client.take(0))
        module = fresh_events("fixture-box.local")
        normal = module.make("owner", "fixture", "ordinary", eid="ordinary")
        self.assertEqual(normal["host"], "fixture-box")
        self.assertTrue(module.Hub(max_rate=100).publish(normal))

    def test_ticket_comment_id_is_checked_before_clipping_and_seen(self):
        value = self.shape()
        comments = {"comments": [{"id": "-" * 35 + value}, {"id": "ordinary"}]}
        runner = FakeRunner({"ah-ticket-comments": lambda ref: (0, json.dumps(comments))})
        poll = col.Tickets(self.hub, self.health, runner, lambda: ["goodqa#15585"])
        client = self.hub.attach()
        poll.tick(time.time())
        self.assertTrue(poll.seen["goodqa#15585"] == {"ordinary"}, "only admitted comment IDs enter seen")
        self.assertTrue([row["id"] for row in self.hub.recent()] == ["goodqa:ordinary"])
        self.assertEqual(len(client.take(0)), 1)

    def test_normal_fabric_fields_and_optional_hub_tenant_survive(self):
        folder = self.base / "fabric-fields"
        folder.mkdir()
        actor = {"runtime": "codex", "session": "session-1", "agent": "main"}
        subject = {"repo": "owner/repo", "branch": "main", "ref": "refs/heads/main",
                   "ticket": "goodqa#15585", "initiative": "fixture"}
        row = dict(ev.make("owner", "exporter", "ordinary", eid="fabric:one", actor=actor, subject=subject),
                   tenant="fixture-tenant")
        (folder / "fabric.jsonl").write_text(json.dumps(row) + "\n")
        source = col.FileDrop(self.hub, self.health, mcs.Reader([self.base]), folder)
        source.tick(0)
        admitted, = self.hub.recent()
        self.assertEqual(admitted["actor"], actor)
        self.assertEqual(admitted["subject"], subject)
        self.assertNotIn("tenant", admitted)  # existing FileDrop projection drops exporter metadata
        self.assertTrue(self.hub.publish(dict(row, id="direct:ordinary")))
        self.assertFalse(self.hub.publish(dict(row, id="direct:refused", tenant=self.shape())))
        self.assertEqual(self.hub.recent()[-1]["tenant"], "fixture-tenant")

    def test_fabric_ingress_refuses_full_decoded_lines_before_any_sink_effect(self):
        value = self.shape()
        ordinary = ev.make("owner", "exporter", "ordinary", eid="fabric:one")
        encoded = json.dumps(ordinary)
        escaped = json.dumps(dict(ordinary, discarded={"nested": [value]})).replace("hf_", r"\u0068f_")
        duplicate = encoded[:-1] + ', "ignored": ' + json.dumps(value) + ', "ignored": null}'
        invalid = "contains an invalid event line"
        privacy = "failed event privacy admission"
        cases = (
            ("escaped-value", escaped, privacy),
            ("nested-key", json.dumps(dict(ordinary, ignored=[{value: False}])), privacy),
            ("summary", json.dumps(dict(ordinary, summary=value)), privacy),
            ("duplicate", duplicate, invalid),
            ("depth", encoded[:-1] + ', "ignored":' + "[" * 34 + "0" + "]" * 34 + "}", privacy),
            ("parser-depth", encoded[:-1] + ', "ignored":' + "[" * 1500 + "0" + "]" * 1500 + "}", invalid),
            ("nan", json.dumps(dict(ordinary, ignored=float("nan"))), invalid),
            ("infinity", json.dumps(dict(ordinary, ignored=float("inf"))), invalid),
            ("escaped-surrogate", json.dumps(dict(ordinary, ignored="\ud800")), privacy),
            ("non-utf8", json.dumps(dict(ordinary, ignored="\ud800"), ensure_ascii=False), "is not valid UTF-8"),
        )
        for label, line, category in cases:
            with self.subTest(label=label):
                folder = self.base / label
                folder.mkdir()
                runner = mock.Mock()
                runner.run.return_value = (0, line + '\n{"cursor":"fx1:refused"}\n')
                remote = col.Remote(self.hub, self.health, runner, fabric=True, drop_dir=folder)
                with self.assertRaisesRegex(ValueError, f"^Fabric response {category}$"):
                    remote.fabric_export()
                self.assertEqual(remote.cursor, "")
                self.assertFalse(tuple(folder.iterdir()), "refused initial batch must create no files")

    def test_fabric_decoded_node_ceiling_counts_keys_and_values(self):
        self.assertFalse(col._fabric_privacy_refused({"metadata": [0] * 4093}))
        self.assertTrue(col._fabric_privacy_refused({"metadata": [0] * 4094}))

    def test_fabric_ingress_preserves_committed_prefix_and_safe_retry_bytes(self):
        import redact

        folder = self.base / "durable-fabric"
        folder.mkdir()
        runner = mock.Mock()
        remote = col.Remote(self.hub, self.health, runner, fabric=True, drop_dir=folder)
        first = json.dumps(ev.make("owner", "exporter", "ordinary", eid="fabric:first"), separators=(",", ":"))
        good = json.dumps(ev.make("owner", "exporter", "[REDACTED:huggingface]", eid="fabric:good"), indent=None)
        bad = json.dumps(dict(json.loads(good), id="fabric:bad", summary=self.shape()))

        def response(lines, cursor):
            runner.run.return_value = (0, "\n".join([*lines, json.dumps({"cursor": cursor})]) + "\n")

        response([first], "fx1:first")
        remote.fabric_export()
        sink = folder / "fabric.jsonl"
        checkpoint = folder / col.FABRIC_CHECKPOINT
        before = sink.read_bytes(), checkpoint.read_bytes(), checkpoint.stat().st_ino
        response([good, bad], "fx1:second")
        with self.assertRaisesRegex(ValueError, "^Fabric response failed event privacy admission$"):
            remote.fabric_export()
        self.assertTrue((sink.read_bytes(), checkpoint.read_bytes(), checkpoint.stat().st_ino) == before)
        self.assertEqual(remote.cursor, "fx1:first")
        response([good], "fx1:second")
        with mock.patch.object(redact, "has_secret", None):
            with self.assertRaisesRegex(ValueError, "^Fabric response failed event privacy admission$"):
                remote.fabric_export()
        self.assertTrue((sink.read_bytes(), checkpoint.read_bytes(), checkpoint.stat().st_ino) == before)
        self.assertEqual(remote.cursor, "fx1:first")
        remote.fabric_export()
        runner.run.assert_called_with("fabric-export", "fx1:first", timeout=15, limit=1024 * 1024)
        self.assertEqual(remote.cursor, "fx1:second")
        self.assertTrue(sink.read_bytes() == (first + "\n" + good + "\n").encode())

    def test_chat_missing_redactor_has_no_creation_or_reply_effect(self):
        empty = self.base / "empty-chat-root"
        existing = self.base / "existing-chat-root"
        message, _ = mc_chat.new_message("codex", "ordinary fixture", client_key="fixture-key", root=existing)

        def state(root):
            result = {}
            for path in (root, *root.rglob("*")):
                info = path.stat()
                data = path.read_bytes() if path.is_file() and path.name != "secret" else None
                result[path.relative_to(root)] = (info.st_mode, info.st_size, info.st_mtime_ns, data)
            return result

        before = state(existing)
        original_import = __import__
        def missing(name, *args, **kwargs):
            if name == "redact":
                raise ImportError("fixture dependency unavailable")
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=missing):
            with self.subTest(entry="create"):
                with self.assertRaises(mc_chat.ChatError) as error:
                    mc_chat.new_message("codex", self.shape(), client_key="empty-fixture", root=empty)
                self.assertEqual(error.exception.code, "redaction-unavailable")
                self.assertFalse(empty.exists())
            with self.subTest(entry="reply"):
                with self.assertRaises(mc_chat.ChatError) as error:
                    mc_chat.write_reply(message["id"], "codex", self.shape(), root=existing)
                self.assertEqual(error.exception.code, "redaction-unavailable")
                self.assertTrue(state(existing) == before, "no persistent reply or state may change")


class ReadOnly(unittest.TestCase):
    def setUp(self):
        self.runner = safeio.Runner(python="/usr/bin/python3", ah="/h/ah.py", gh="/b/gh", codex="/b/codex",
                                    fabric_bin="/srv/fabric/bin/fab-live")

    def test_only_read_shapes_are_allowed(self):
        self.assertEqual(self.runner.argv("ah-owners"), ["/usr/bin/python3", "-I", "/h/ah.py", "owners"])
        self.assertEqual(self.runner.argv("gh-events", "eric")[-1], "/users/eric/events?per_page=30")
        self.assertIn("GET", self.runner.argv("gh-user"))
        self.assertIn("control export --since abc", self.runner.argv("fabric-export", "abc")[-1])
        for kind, args in (("ah-ticket-comments", ("goodqa#1; rm -rf /",)), ("gh-events", ("eric/../../x",)),
                           ("ah-ticket-comment", ("goodqa#1",)), ("gh-api", ("repos/x", "-X", "POST")),
                           ("fabric-export", ("x; reboot",)), ("ah-owners", ("--all",)), ("shell", ("ls",))):
            with self.subTest(kind=kind):
                with self.assertRaises(safeio.Refused):
                    self.runner.argv(kind, *args)

    def test_no_write_verbs_in_any_allowlisted_argv(self):
        shapes = [("ah-owners", ()), ("ah-sessions", ()), ("ah-ticket-comments", ("goodqa#1",)), ("gh-user", ()),
                  ("gh-events", ("eric",)), ("remote-wal-probe", ()), ("fabric-export", ("c",)),
                  ("codex-login-status", ()), ("codex-pool-status", ())]
        for kind, args in shapes:
            words = " ".join(self.runner.argv(kind, *args))
            for verb in (" comment ", "POST", "PATCH", "DELETE", " push", " rm ", " mv ", "tee "):
                self.assertNotIn(verb, words + " ", (kind, verb))
            self.assertIsNone(re.search(r">(?!/dev/null)", words), (kind, "redirect"))

    def test_child_environment_drops_credentials(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "x", "OPENAI_API_KEY": "y", "AWS_SECRET_ACCESS_KEY": "z",
                                          "PATH": "/usr/bin", "HOME": "/h"}, clear=True):
            env = safeio.scrubbed_env()
        self.assertEqual(set(env), {"PATH", "HOME"})
        with self.assertRaises(safeio.Refused):
            safeio.scrubbed_env({"GITHUB_TOKEN": "x"})

    def test_reader_refuses_credentials_symlinks_and_outside_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            (root / ".ssh").mkdir(parents=True)
            (root / ".ssh" / "config").write_text("x")
            (root / "auth.json").write_text("x")
            (root / "ok.jsonl").write_text("x")
            outside = Path(tmp) / "outside.txt"
            outside.write_text("x")
            os.symlink(outside, root / "link.jsonl")
            reader = safeio.Reader([root])
            self.assertEqual(reader.read(root / "ok.jsonl", 10), b"x")
            for path in (root / ".ssh" / "config", root / "auth.json", root / "link.jsonl", outside,
                         root / ".." / "outside.txt"):
                with self.subTest(path=path.name):
                    with self.assertRaises(safeio.Refused):
                        reader.read(path, 10)

    def test_server_never_calls_subprocess_outside_the_runner(self):
        source = "\n".join((REPO / "harness" / "mission_control" / name).read_text()
                           for name in ("collectors.py", "events.py", "server.py"))
        self.assertNotIn("subprocess.Popen", source)
        self.assertNotIn("os.system", source)


class Redaction(unittest.TestCase):
    def test_events_redact_summaries(self):
        event = ev.make("wal", "claude-wal", "token " + GH_TOKEN + " and " + STRIPE, eid="w:1")
        self.assertNotIn(GH_TOKEN, event["summary"])
        self.assertNotIn(STRIPE, event["summary"])

    def test_stream_redactor_never_shows_part_of_a_split_secret(self):
        stream = StreamRedactor()
        shown = []
        text = "Here is the value " + STRIPE + " which you asked about.\n" + "x" * 5000
        for cut in range(5, len(text), 7):
            stream.update("i1", text[:cut])
            shown.append(stream.safe())
        stream.update("i1", text)
        shown.append(stream.safe(final=True))
        for value in shown:
            for n in range(12, len(STRIPE) + 1):
                self.assertNotIn(STRIPE[:n], value)

    def test_pem_block_is_redacted_in_a_reply(self):
        stream = StreamRedactor()
        pem = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\n-----END OPENSSH PRIVATE KEY-----"
        stream.update("i", "key:\n" + pem + "\nok")
        self.assertNotIn("AAAAB3Nza", stream.safe(final=True))


FAKE_CODEX = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys, time
    mode = os.environ.get("FAKE_MODE") or open(os.path.join(os.path.dirname(__file__), "mode")).read().strip()
    args = sys.argv[1:]
    if args[:2] == ["login", "status"]:
        print("Logged in using ChatGPT"); sys.exit(0)
    prompt = sys.stdin.read()
    open(os.path.join(os.path.dirname(__file__), "argv.json"), "w").write(json.dumps({"argv": args, "cwd": os.getcwd(),
        "env": sorted(os.environ), "prompt": prompt}))
    def out(o): print(json.dumps(o), flush=True)
    if mode == "hang":
        time.sleep(60)
    if mode == "fail":
        out({"type": "turn.failed", "error": {"message": "model refused"}}); sys.exit(1)
    out({"type": "thread.started", "thread_id": "0199aaaa-bbbb-cccc-dddd-eeeeffff0000"})
    secret = "sk" + "_live_" + "Ab3dEf6hIj9kLm2nOp5qRs8t"
    text = ""
    for piece in ["The answer is ", "two owners are live. ", "A key: " + secret[:10], secret[10:] + " done."]:
        text += piece
        out({"type": "item.updated", "item": {"id": "m1", "type": "agent_message", "text": text}})
    out({"type": "item.completed", "item": {"id": "m1", "type": "agent_message", "text": text}})
    out({"type": "turn.completed"})
""")


class CodexResponderTests(Tmp):
    def setUp(self):
        super().setUp()
        bindir = self.base / "bin"
        bindir.mkdir()
        self.codex = bindir / "codex"
        self.codex.write_text(FAKE_CODEX)
        self.codex.chmod(0o755)
        (bindir / "mode").write_text("ok")
        self.bindir = bindir
        mc_chat.ensure_dirs()
        mc_chat.secret()
        runner = FakeRunner({"codex-login-status": (0, "Logged in using ChatGPT"),
                             "codex-pool-status": (0, "subscription: ok")})
        self.responder = CodexResponder(self.hub, self.health, runner, str(self.codex), self.root)
        self.responder.TIMEOUT_S = 3

    def mode(self, value):
        (self.bindir / "mode").write_text(value)

    def send(self, text="how many owners?", key="codexkey-1"):
        return mc_chat.new_message("codex", text, client_key=key)[0]

    def test_streams_a_redacted_reply_with_a_locked_down_invocation(self):
        record = self.send()
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "should-not-pass", "GH_TOKEN": "nope"}):
            self.responder.step()
        replies = [r for r in mc_chat.outbox() if r["reply_to"] == record["id"]]
        self.assertTrue(replies[-1]["final"])
        self.assertIn("two owners are live", replies[-1]["text"])
        for reply in replies:
            self.assertNotIn("Ab3dEf6hIj9kLm2n", reply["text"])
        self.assertEqual(mc_chat.state(record["id"])["status"], "answered")
        seen = json.loads((self.bindir / "argv.json").read_text())
        argv = seen["argv"]
        self.assertIn("--json", argv)
        self.assertIn('sandbox_mode="read-only"', argv)
        self.assertIn('approval_policy="never"', argv)
        self.assertNotIn("danger-full-access", " ".join(argv))
        self.assertEqual(Path(seen["cwd"]).resolve(), (self.root / "codex" / "cwd").resolve())
        self.assertEqual(os.listdir(seen["cwd"]), [])
        self.assertFalse([k for k in seen["env"] if "KEY" in k or "TOKEN" in k])
        self.assertIn("untrusted dashboard text begins", seen["prompt"])
        # second message resumes the same thread
        self.send(key="codexkey-2")
        self.responder.step()
        argv2 = json.loads((self.bindir / "argv.json").read_text())["argv"]
        self.assertEqual(argv2[-3:], ["resume", "0199aaaa-bbbb-cccc-dddd-eeeeffff0000", "-"])

    def test_failure_and_timeout_end_in_failed(self):
        self.mode("fail")
        record = self.send()
        self.responder.step()
        self.assertEqual(mc_chat.state(record["id"])["status"], "failed")
        self.assertIn("model refused", mc_chat.state(record["id"])["reason"])
        self.mode("hang")
        record = self.send(key="codexkey-3")
        started = time.time()
        self.responder.step()
        self.assertLess(time.time() - started, 15)
        self.assertEqual(mc_chat.state(record["id"])["status"], "failed")

    def test_unavailable_when_not_subscription_or_blocked(self):
        for runner, words in ((FakeRunner({"codex-login-status": (0, "Logged in using an API key")}), "subscription"),
                              (FakeRunner({"codex-login-status": (0, "Logged in using ChatGPT"),
                                           "codex-pool-status": (0, "subscription: BLOCKED until 2999-01-01T00:00:00Z")}),
                               "blocked")):
            with self.subTest(words=words):
                responder = CodexResponder(self.hub, self.health, runner, str(self.codex), self.root)
                record = self.send(key="unavail-" + words[:6])
                responder.step()
                self.assertEqual(mc_chat.state(record["id"])["status"], "unavailable")
                self.assertIn(words, mc_chat.state(record["id"])["reason"])
        self.assertFalse((self.bindir / "argv.json").exists(), "codex exec never ran")


class ServerHarness(Tmp):
    """A real server on an ephemeral 127.0.0.1 port with fake collectors' runner and no background threads."""

    def setUp(self):
        super().setUp()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()
        web = self.base / "web"
        (web / "js").mkdir(parents=True)
        (web / "index.html").write_text("<!doctype html><title>t</title>")
        (web / "js" / "main.js").write_text("console.log(1)")
        self.app = mcs.App(port=self.port, root=self.root, initiatives=None, remote=False, fabric_bin=None,
                           runner=FakeRunner(), wal_roots=[(self.base / "nowals", "claude")], start_threads=False)
        self.server = mcs.Server(self.app, web, mcs.make_logger(self.root))
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin = f"http://127.0.0.1:{self.port}"

    def request(self, method, path, headers=None, body=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Host": host or f"127.0.0.1:{self.port}"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def login(self):
        code = mcs.mint_code(mc_chat.secret(), self.app.auth.launch_generation)
        resp, _ = self.request("GET", "/launch?c=" + code, {"Sec-Fetch-Site": "none"})
        self.assertEqual(resp.status, 303)
        cookie = resp.getheader("Set-Cookie").split(";")[0]
        resp, data = self.request("GET", "/api/state", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(resp.status, 200)
        return cookie, json.loads(data)["csrf"]

    def post(self, cookie, csrf, body, origin=None, ctype="application/json"):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        return self.request("POST", "/api/chat", {"Cookie": cookie, "X-MC-CSRF": csrf, "Origin": origin or self.origin,
                                                  "Content-Type": ctype}, payload)


class Security(ServerHarness):
    def test_launch_code_is_single_use_and_expires(self):
        code = mcs.mint_code(mc_chat.secret(), self.app.auth.launch_generation)
        first, _ = self.request("GET", "/launch?c=" + code)
        again, _ = self.request("GET", "/launch?c=" + code)
        self.assertEqual((first.status, again.status), (303, 401))
        self.assertEqual(first.getheader("Location"), "/")
        cookie = first.getheader("Set-Cookie")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        old = mcs.mint_code(mc_chat.secret(), self.app.auth.launch_generation, now=time.time() - 61)
        self.assertEqual(self.request("GET", "/launch?c=" + old)[0].status, 401)
        forged = mcs.mint_code(b"k" * 32, self.app.auth.launch_generation)
        self.assertEqual(self.request("GET", "/launch?c=" + forged)[0].status, 401)

    def test_dns_rebinding_host_is_refused_everywhere(self):
        cookie, csrf = self.login()
        for path in ("/", "/api/state", "/api/events", "/healthz", "/launch?c=x"):
            resp, _ = self.request("GET", path, {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"}, host="evil.com")
            self.assertEqual(resp.status, 403, path)
        resp, _ = self.request("GET", "/api/state", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"},
                               host=f"evil.com:{self.port}")
        self.assertEqual(resp.status, 403)

    def test_cross_site_reads_are_refused(self):
        cookie, _ = self.login()
        for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
                        {"Origin": "http://127.0.0.1:1"}, {"Origin": "null"}, {}):
            for path in ("/api/state", "/api/events", "/js/main.js"):
                resp, _ = self.request("GET", path, dict(headers, Cookie=cookie))
                self.assertEqual(resp.status, 403, (path, headers))

    def test_unauthenticated_and_pre_set_cookies_are_refused(self):
        resp, _ = self.request("GET", "/api/state", {"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(resp.status, 401)
        resp, _ = self.request("GET", "/api/state", {"Sec-Fetch-Site": "same-origin", "Cookie": "mc_sid=attacker-chosen"})
        self.assertEqual(resp.status, 401)
        resp, body = self.request("GET", "/", {"Sec-Fetch-Site": "none"})
        self.assertEqual(resp.status, 401)
        self.assertIn(b"server.py open", body)

    def test_post_needs_origin_csrf_and_bounds(self):
        cookie, csrf = self.login()
        mc_chat.register_target("sess-1", os.getpid())
        good = {"to": "claude", "session": "sess-1", "text": "hi", "client_key": "post-key-1"}
        self.assertEqual(self.post(cookie, "wrong", good)[0].status, 403)
        self.assertEqual(self.post(cookie, csrf, good, origin="http://127.0.0.1:1")[0].status, 403)
        self.assertEqual(self.post(cookie, csrf, good, origin="null")[0].status, 403)
        self.assertEqual(self.post(cookie, csrf, good, ctype="text/plain")[0].status, 415)
        self.assertEqual(self.post(cookie, csrf, b"x" * (mcs.MAX_BODY + 1))[0].status, 413)
        resp, data = self.post(cookie, csrf, good)
        self.assertEqual(resp.status, 201)
        again, data2 = self.post(cookie, csrf, good)
        self.assertEqual(again.status, 200)
        self.assertEqual(json.loads(data)["id"], json.loads(data2)["id"])
        conflict, conflict_data = self.post(cookie, csrf, dict(good, text="different instruction"))
        self.assertEqual(conflict.status, 409)
        self.assertEqual(json.loads(conflict_data)["error"], "key-conflict")
        bad = dict(good, client_key="post-key-2", text="a\x00b")
        self.assertEqual(self.post(cookie, csrf, bad)[0].status, 400)
        nomain = dict(good, client_key="post-key-3", session="sess-none")
        self.assertEqual(self.post(cookie, csrf, nomain)[0].status, 409)

    def test_security_headers_and_no_cors(self):
        cookie, _ = self.login()
        resp, _ = self.request("GET", "/", {"Cookie": cookie, "Sec-Fetch-Site": "none"})
        self.assertEqual(resp.status, 200)
        self.assertIn("frame-ancestors 'none'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))
        resp, _ = self.request("OPTIONS", "/api/chat", {"Origin": "http://evil.com"})
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    def test_log_has_no_query_strings(self):
        code = mcs.mint_code(mc_chat.secret(), self.app.auth.launch_generation)
        self.request("GET", "/launch?c=" + code)
        for handler in mcs.make_logger(self.root).handlers:
            handler.flush()
        log = (self.root / "log" / "server.log").read_text()
        self.assertIn("/launch", log)
        self.assertNotIn(code, log)

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_sse_streams_and_caps_clients(self):
        cookie, _ = self.login()
        conns = []
        for n in range(self.app.hub.max_clients):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", "/api/events", headers={"Host": f"127.0.0.1:{self.port}", "Cookie": cookie,
                                                        "Sec-Fetch-Site": "same-origin"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            conns.append((conn, resp))
        self.addCleanup(lambda: [c.close() for c, _ in conns])
        time.sleep(0.2)
        resp, _ = self.request("GET", "/api/events", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(resp.status, 503)
        self.app.hub.publish(ev.make("wal", "claude-wal", "pulse!", eid="w:pulse"))
        line = b""
        deadline = time.time() + 5
        while b"pulse!" not in line and time.time() < deadline:
            line += conns[0][1].fp.readline()
        self.assertIn(b"pulse!", line)


class Budget(ServerHarness):
    def test_connection_cap_is_the_spec_value(self):
        self.assertEqual(mcs.MAX_CONNECTIONS, 32)  # AC-9: at most 32 concurrent connections

    def test_full_house_of_authenticated_connections_refuses_without_deadlock(self):
        held = []
        self.addCleanup(lambda: [s.close() for pair in held for s in pair])
        with self.server.conn_lock:
            for n in range(mcs.MAX_CONNECTIONS):
                pair = socket.socketpair()
                held.append(pair)
                self.server.live[pair[0]] = [float(n), True]  # every slot authenticated: nothing to evict
        extra = socket.socketpair()
        held.append(extra)
        worker = threading.Thread(target=self.server.process_request, args=(extra[0], ("127.0.0.1", 1)), daemon=True)
        worker.start()
        worker.join(3)
        self.assertFalse(worker.is_alive(), "process_request deadlocked on its own connection lock")
        self.assertNotIn(extra[0], self.server.live)
        extra[1].settimeout(2)
        self.assertEqual(extra[1].recv(1), b"", "the refused connection is closed")
        acquired = self.server.conn_lock.acquire(timeout=2)
        self.assertTrue(acquired, "the lock is free again")
        self.server.conn_lock.release()

    def test_idle_unauthenticated_sockets_do_not_lock_out_the_user(self):
        idle = []
        self.addCleanup(lambda: [s.close() for s in idle])
        for _ in range(200):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
            idle.append(sock)
        time.sleep(0.3)
        self.assertLessEqual(len(self.server.live), 32, "connections stay bounded (AC-9)")
        started = time.time()
        cookie, _ = self.login()
        resp, _ = self.request("GET", "/", {"Cookie": cookie, "Sec-Fetch-Site": "none"})
        self.assertEqual(resp.status, 200)
        self.assertLess(time.time() - started, 2.0)

    def test_collector_intervals(self):
        intervals = {c.name: c.interval for c in self.app.collectors}
        self.assertEqual(intervals["wals"], 2.0)
        self.assertGreaterEqual(intervals["owners"], 60)
        self.assertGreaterEqual(intervals["github"], 60)
        self.assertGreaterEqual(intervals["goodqa"], 10)
        self.assertGreaterEqual(intervals["t2-dev"], 60)

    def test_hub_rate_limit_summarises_bursts(self):
        hub = ev.Hub(max_rate=20)
        sent = sum(hub.publish(ev.make("wal", "x", "n", eid=f"w:{n}")) for n in range(500))
        self.assertEqual(sent, 20)
        self.assertEqual(hub.suppressed, 480)
        hub.window[0] -= 2
        hub.publish(ev.make("wal", "x", "later", eid="w:later"))
        self.assertTrue(any(e["kind"] == "system" and e["count"] == 480 for e in hub.recent()))

    def test_quiet_floods_never_starve_work_items(self):
        hub = ev.Hub(max_rate=20)
        quiet = sum(hub.publish(ev.make("wal", "x", "tool", eid=f"q:{n}", quiet=True)) for n in range(100))
        loud = sum(hub.publish(ev.make("wal", "x", "intent: real work", eid=f"l:{n}")) for n in range(10))
        self.assertEqual((quiet, loud), (10, 10), "quiet activity takes at most half the budget")
        hub.window[0] -= 2
        hub.publish(ev.make("wal", "x", "later", eid="w:later2"))
        burst = [e for e in hub.recent() if e["kind"] == "system"][-1]
        self.assertTrue(burst.get("quiet"), "a burst of only tool activity is summarised quietly")

    def test_slow_sse_client_is_dropped_not_buffered(self):
        client = ev.Client(maxlen=5)
        for n in range(10):
            client.push(b"x")
        self.assertIsNone(client.take(0))


if __name__ == "__main__":
    unittest.main()
