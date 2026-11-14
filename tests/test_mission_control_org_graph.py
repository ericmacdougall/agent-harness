"""Org graph for the Topology tab (GoodQA goodqa#15950): real fields only, structure, changes, privacy."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))

import collectors as col  # noqa: E402
import demo  # noqa: E402
import events as ev  # noqa: E402
import org_graph as og  # noqa: E402

SESSION = "sess-0000-4000-8000-000000000001"


def write_transcript(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def assistant(model=None, effort=None, advisor=None, ts="2026-11-14T04:00:00Z", tools=()):
    rec = {"type": "assistant", "timestamp": ts, "message": {"role": "assistant", "content": list(tools)}}
    if model:
        rec["message"]["model"] = model
    if effort:
        rec["effort"] = effort
    if advisor:
        rec["advisorModel"] = advisor
    return rec


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "projects"
        self.sub = self.root / "-proj" / SESSION / "subagents"
        self.sub.mkdir(parents=True)

    def agent(self, agent, *, kind="general-purpose", parent=None, records=None):
        meta = {"agentType": kind, "spawnDepth": 2 if parent else 1}
        if parent:
            meta["parentAgentId"] = parent
        (self.sub / f"agent-{agent}.meta.json").write_text(json.dumps(meta))
        write_transcript(self.sub / f"agent-{agent}.jsonl", records or [])

    def main(self, records):
        write_transcript(self.root / "-proj" / f"{SESSION}.jsonl", records)


def row(agent, state="live", task="", ticket="", kind="general-purpose", severity="info", idle=10):
    return {"agent_id": agent, "state": state, "task": task, "ticket": ticket, "type": kind, "severity": severity,
            "last_activity": "2026-11-14T04:00:00Z", "idle_s": idle, "runtime": "claude"}


class Hub:
    def __init__(self):
        self.snaps, self.clients = [], [1]

    def snapshot(self, name, data):
        self.snaps.append((name, data))


class Runner:
    def __init__(self, tickets=None, fail=()):
        self.tickets, self.fail, self.calls = tickets or {}, set(fail), []

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.calls.append((kind, args))
        assert kind == "ah-ticket-get"
        if args[0] in self.fail:
            return 1, ""
        issue = self.tickets.get(args[0])
        return 0, json.dumps({"issue": issue or {}})


def collector(fx, rows, runner=None):
    hub = Hub()
    health = col.Health(hub)
    graph = og.OrgGraph(hub, health, runner or Runner(), owners_fn=lambda: rows, session_fn=lambda: SESSION,
                        transcripts=og.Transcripts(fx.root), escalation_root=None, host="testhost")
    return graph, hub, health


def nodes(snapshot, kind=None):
    return {n["id"]: n for n in snapshot["nodes"] if kind is None or n["kind"] == kind}


class TranscriptFacts(unittest.TestCase):
    def test_fields_come_from_the_transcript(self):  # AC-1, AC-2
        fx = Fixture()
        fx.agent("a1", records=[assistant("claude-opus-5-5", "high", "claude-fable-5-2")])
        facts = og.Transcripts(fx.root).facts(fx.sub / "agent-a1.jsonl")
        self.assertEqual((facts["model"], facts["effort"], facts["advisor_model"]),
                         ("claude-opus-5-5", "high", "claude-fable-5-2"))

    def test_missing_fields_are_unknown(self):  # AC-2
        fx = Fixture()
        fx.agent("a1", records=[{"type": "user", "timestamp": "2026-11-14T04:00:00Z", "message": {"content": "x"}}])
        facts = og.Transcripts(fx.root).facts(fx.sub / "agent-a1.jsonl")
        self.assertEqual((facts["model"], facts["effort"], facts["advisor_model"]), ("unknown",) * 3)

    def test_malformed_and_truncated_lines_are_skipped(self):  # NEG-1
        fx = Fixture()
        path = fx.sub / "agent-a1.jsonl"
        fx.agent("a1", records=[assistant("claude-sonnet-5", "low")])
        with open(path, "a") as handle:
            handle.write('{"type": "assistant", "message": {"model": "trunc\n[1,2]\n"not a dict"\n')
        facts = og.Transcripts(fx.root).facts(path)
        self.assertEqual(facts["model"], "claude-sonnet-5")

    def test_tail_is_byte_bounded(self):  # AC-9
        fx = Fixture()
        filler = [{"type": "user", "message": {"content": "x" * 1000}} for _ in range(300)]
        fx.agent("a1", records=[assistant("old-model", "low")] + filler)
        facts = og.Transcripts(fx.root, tail_bytes=8192).facts(fx.sub / "agent-a1.jsonl")
        self.assertEqual(facts["model"], "unknown")  # the old record is outside the bounded tail

    def test_only_allowlisted_scalars_leave_the_reader(self):  # AC-9
        fx = Fixture()
        secretish = "the body of a message must never leave"
        fx.agent("a1", records=[assistant("claude-opus-5-5", "high", tools=[
            {"type": "tool_use", "id": "toolu_1", "name": "SendMessage", "input": {"to": "a2", "message": secretish,
                                                                                 "summary": secretish}},
            {"type": "tool_use", "id": "toolu_2", "name": "Bash", "input": {"command": secretish}}])])
        facts = og.Transcripts(fx.root).facts(fx.sub / "agent-a1.jsonl")
        self.assertNotIn(secretish, json.dumps(facts))
        self.assertEqual(facts["messages"], [{"id": "toolu_1", "to": "a2", "at": "2026-11-14T04:00:00Z"}])

    def test_odd_values_are_not_shown(self):
        fx = Fixture()
        fx.agent("a1", records=[assistant("<img src=x>", "high; rm")])
        facts = og.Transcripts(fx.root).facts(fx.sub / "agent-a1.jsonl")
        self.assertEqual((facts["model"], facts["effort"]), ("unknown", "unknown"))

    def test_symlinked_transcript_is_refused(self):  # NEG-4
        fx = Fixture()
        outside = Path(fx.tmp.name) / "outside.jsonl"
        write_transcript(outside, [assistant("claude-opus-5-5", "high")])
        os.symlink(outside, fx.sub / "agent-a9.jsonl")
        reader = og.Transcripts(fx.root)
        self.assertIsNone(reader.agent_path(SESSION, "a9", ".jsonl"))
        self.assertFalse(reader.facts(fx.sub / "agent-a9.jsonl")["read"])


class Structure(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        fx = self.fx
        fx.main([assistant("claude-opus-5-5", "medium", "claude-fable-5-2")])
        fx.agent("own1", kind="task-owner", records=[assistant("claude-opus-5-5", "high")])
        fx.agent("sub1", kind="general-purpose", parent="own1", records=[assistant("claude-sonnet-5", "medium")])
        fx.agent("rev1", kind="red-team", parent="own1", records=[assistant("claude-opus-5-5", "high")])
        fx.agent("rev2", kind="red-team", records=[assistant("claude-opus-5-5", "medium")])
        fx.agent("cyc1", parent="cyc2")
        fx.agent("cyc2", parent="cyc1")
        self.rows = [row("own1", task="Build goodqa#10", ticket="goodqa#10", kind="task-owner"),
                     row("sub1", task="Slice goodqa#11", ticket="goodqa#11"),
                     row("rev1", task="review", ticket="goodqa#11", kind="red-team"),
                     row("rev2", task="lonely review goodqa#99", ticket="goodqa#99", kind="red-team"),
                     row("cyc1"), row("cyc2")]
        tickets = {"goodqa#11": {"number": 11, "title": "Slice", "status": "in_progress",
                                 "links": {"blocks": [{"number": 12}], "blockedBy": [{"number": 13}]},
                                 "parent": {"number": 10}},
                   "goodqa#12": {"number": 12, "title": "Next", "status": "todo",
                                 "links": {"blocks": [{"number": 14}], "blockedBy": []}}}
        self.graph, self.hub, self.health = collector(fx, self.rows, Runner(tickets))

    def tick_until_tickets(self):
        now = 1_000_000.0
        for i in range(8):
            self.graph.tick(now + i)
        return self.graph.snapshot()

    def test_coordinator_and_agent_fields(self):  # AC-1
        snap = self.tick_until_tickets()
        self.assertEqual(snap["schema"], "mc.orggraph/1")
        coord = nodes(snap)["coordinator"]
        self.assertEqual((coord["model"], coord["effort"], coord["advisor_model"], coord["machine"]),
                         ("claude-opus-5-5", "medium", "claude-fable-5-2", "testhost"))
        for node in snap["nodes"]:
            if node["kind"] in ("owner", "subagent", "reviewer"):
                for field in ("model", "advisor_model", "effort", "machine", "last_activity"):
                    self.assertTrue(node[field], (node["id"], field))

    def test_roles_and_parents(self):  # AC-3
        snap = self.tick_until_tickets()
        all_nodes = nodes(snap)
        self.assertEqual(all_nodes["own1"]["kind"], "owner")
        self.assertEqual(all_nodes["sub1"]["kind"], "subagent")
        self.assertEqual(all_nodes["sub1"]["owner"], "own1")
        self.assertIn({"from": "own1", "to": "sub1", "kind": "spawn"}, snap["edges"])
        self.assertEqual(all_nodes["own1"]["mission"], "Build goodqa#10")

    def test_reviewer_pairs_on_parent_and_ticket_only(self):  # AC-3, NEG-3
        snap = self.tick_until_tickets()
        all_nodes = nodes(snap)
        self.assertEqual((all_nodes["rev1"]["reviews"], all_nodes["rev1"]["pairing_source"]), ("sub1", "parent+ticket"))
        self.assertEqual(all_nodes["rev2"]["reviews"], "unknown")

    def test_parent_cycle_does_not_hang(self):  # NEG-2
        snap = self.tick_until_tickets()
        self.assertIn("cyc1", nodes(snap))

    def test_work_dag_layers(self):  # AC-3
        snap = self.tick_until_tickets()
        work = nodes(snap, "work")
        self.assertEqual(work["work:goodqa#11"]["layer"], 0)
        self.assertEqual(work["work:goodqa#11"]["holders"], ["sub1"])  # under the sub-agent, not the owner
        self.assertEqual(work["work:goodqa#12"]["layer"], 1)           # next in line, one layer deeper
        self.assertEqual(work["work:goodqa#14"]["layer"], 2)
        self.assertEqual(work["work:goodqa#13"]["via"], "blocked_by")
        self.assertIn({"from": "work:goodqa#10", "to": "work:goodqa#11", "kind": "parent"}, snap["edges"])
        self.assertIn({"from": "work:goodqa#11", "to": "work:goodqa#12", "kind": "next"}, snap["edges"])

    def test_restricted_rows_show_no_task(self):  # AC-9
        rows = [row("own1", task="", ticket="goodqa#10", kind="task-owner")]
        self.fx.agent("own1", kind="task-owner", records=[assistant("claude-opus-5-5", "high")])
        meta = self.fx.sub / "agent-own1.meta.json"
        meta.write_text(json.dumps({"agentType": "task-owner", "spawnDepth": 1, "description": "Solve interview helper"}))
        graph, _, _ = collector(self.fx, rows)
        graph.tick(1.0)
        node = nodes(graph.snapshot())["own1"]
        self.assertEqual((node["task"], node["ticket"], node["restricted"]), ("restricted", "", True))

    def test_ticket_failure_keeps_last_copy_and_marks_stale(self):  # NEG-5
        snap = self.tick_until_tickets()
        self.graph.runner.fail.add("goodqa#11")
        self.graph.ticket_at["goodqa#11"] = 0.0
        for i in range(8):
            self.graph.tick(2_000_000.0 + i)
        work = nodes(self.graph.snapshot(), "work")["work:goodqa#11"]
        self.assertTrue(work["stale"])
        self.assertEqual(work["title"], "Slice")
        self.assertFalse([c for c in self.graph.snapshot()["changes"] if c.get("node") == "work:goodqa#11"])
        del snap


class Changes(unittest.TestCase):
    def test_spawn_state_assign_and_message_changes(self):  # AC-4
        fx = Fixture()
        fx.main([assistant("claude-opus-5-5", "medium")])
        fx.agent("own1", kind="task-owner", records=[assistant("claude-opus-5-5", "high")])
        rows = [row("own1", kind="task-owner", ticket="goodqa#10")]
        graph, hub, _ = collector(fx, rows)
        graph.tick(1.0)
        self.assertEqual(graph.snapshot()["changes"], [])           # the first snapshot animates nothing
        fx.agent("sub1", parent="own1", records=[assistant("claude-sonnet-5", "low")])
        rows.append(row("sub1", ticket="goodqa#11"))
        write_transcript(fx.sub / "agent-own1.jsonl", [assistant("claude-opus-5-5", "high", tools=[
            {"type": "tool_use", "id": "toolu_9", "name": "SendMessage", "input": {"to": "sub1", "message": "go"}}])])
        graph.tick(2.0)
        types = [(c["type"], c.get("node") or c.get("to")) for c in graph.snapshot()["changes"]]
        self.assertIn(("spawned", "sub1"), types)
        self.assertIn(("message", "sub1"), types)
        rows[1]["state"] = "done"
        rows[0]["ticket"] = "goodqa#12"
        graph.tick(3.0)
        types = [(c["type"], c.get("node")) for c in graph.snapshot()["changes"]]
        self.assertIn(("finished", "sub1"), types)
        self.assertIn(("assigned", "own1"), types)
        self.assertTrue(any(name == "orggraph" for name, _ in hub.snaps))

    def test_unchanged_graph_is_not_republished(self):
        fx = Fixture()
        fx.agent("own1", kind="task-owner", records=[assistant("claude-opus-5-5", "high")])
        graph, hub, _ = collector(fx, [row("own1", kind="task-owner")])
        graph.tick(1.0)
        graph.tick(2.0)
        self.assertEqual(sum(1 for name, _ in hub.snaps if name == "orggraph"), 1)

    def test_dag_link_change(self):  # AC-4
        prev = og.build(session=SESSION, coordinator={}, agents=[dict(row("o1"), read=True)],
                        tickets={}, escalation={}, host="h", now=1.0)
        cur = og.build(session=SESSION, coordinator={}, agents=[dict(row("o1", ticket="goodqa#1"), read=True)],
                       tickets={"goodqa#1": {"blocks": ["goodqa#2"]}}, escalation={}, host="h", now=2.0)
        kinds = {c["type"] for c in og.diff(prev, cur, 2.0)}
        self.assertTrue({"added", "dag", "assigned"} <= kinds)

    def test_cap_keeps_live_agents(self):  # NEG-6
        agents = [dict(row(f"d{i}", state="done", idle=10), read=False) for i in range(og.MAX_AGENTS + 5)]
        agents.append(dict(row("live1"), read=False))
        snap = og.build(session=SESSION, coordinator={}, agents=agents, tickets={}, escalation={}, host="h", now=1.0)
        self.assertIn("live1", nodes(snap))
        self.assertEqual(snap["counts"]["hidden_agents"], 6)


class Escalation(unittest.TestCase):
    def test_escalation_level_by_dispatch_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "task.json").write_text(json.dumps({"escalations": [{"from": "R0", "to": "R1", "reason": "material"},
                                                                         {"from": "R1", "to": "R2", "reason": "again"}],
                                                          "dispatches": [{"agent_id": "a1"}]}))
            found = og.escalations(Path(tmp), now=time.time())
        self.assertEqual(found["a1"]["level"], 2)
        self.assertEqual(found["a1"]["to"], "R2")


class Demo(unittest.TestCase):
    def test_demo_fixture_graph(self):  # AC-9: fixture transcripts only, under the demo home
        with tempfile.TemporaryDirectory() as tmp:
            projects = demo.seed_transcripts(Path(tmp), time.time())
            self.assertTrue(str(projects).startswith(tmp))
            rows = [r for r in demo.owners_payload(time.time())["owners"]]
            for r in rows:
                r["runtime"] = "claude"
            hub = Hub()
            graph = og.OrgGraph(hub, col.Health(hub), demo.DemoRunner(), owners_fn=lambda: rows,
                                session_fn=lambda: demo.DEMO_SESSION, transcripts=og.Transcripts(projects),
                                escalation_root=None, host="demo-host")
            for i in range(10):
                graph.tick(1000.0 + i)
            snap = graph.snapshot()
            all_nodes = nodes(snap)
            self.assertEqual(all_nodes["a1live0demo"]["model"], "claude-opus-5-5")
            self.assertEqual(all_nodes["a3fini0demo"]["model"], "unknown")
            self.assertEqual(all_nodes["b2rev00demo"]["reviews"], "b1sub00demo")
            self.assertTrue(nodes(snap, "work"))

    def test_merged_pull_request_becomes_a_push_event(self):
        event = col.GitHub.convert({"type": "PullRequestEvent", "id": "1", "created_at": "2026-11-14T04:00:00Z",
                                    "repo": {"name": "o/r"}, "payload": {"action": "closed", "number": 7,
                                    "pull_request": {"merged": True, "number": 7, "base": {"ref": "main"},
                                                     "head": {"ref": "feat/x"}}}})
        self.assertEqual(event["kind"], "push")
        self.assertIn("merged PR #7", event["summary"])
        self.assertIsNone(ev.validate(event))
        self.assertIsNone(col.GitHub.convert({"type": "PullRequestEvent", "id": "2", "repo": {"name": "o/r"},
                                              "payload": {"action": "closed", "pull_request": {"merged": False}}}))


class CapRole(unittest.TestCase):  # goodqa#15920: the collector's owner-cap role decides, as the owner panel does
    def test_role_from_collector_wins(self):
        fx = Fixture()
        rows = [dict(row("aaaa1111", state="live", kind="general-purpose"), role="helper", serves="bbbb2222"),
                dict(row("bbbb2222", state="live", kind="task-owner"), role="live"),
                dict(row("cccc3333", state="live", kind="task-owner"), role="parked")]   # running, but slot freed
        graph, _, _ = collector(fx, rows)
        graph.tick(1.0)
        snap = graph.snapshot()
        owners = nodes(snap, "owner")
        self.assertEqual(set(owners), {"bbbb2222", "cccc3333"})
        self.assertEqual(nodes(snap)["aaaa1111"]["owner"], "bbbb2222")       # nested under the owner it serves
        self.assertEqual(snap["counts"]["live_owners"], 1)                   # the cap's number, not running states
        self.assertEqual((owners["bbbb2222"]["live"], owners["cccc3333"]["live"]), (True, False))


class DerivedInitiatives(unittest.TestCase):  # stale topology/initiatives fix: live owners + GoodQA, not the file
    FILE = [{"id": "prodmove", "initiative": "Production move", "ticket": "goodqa#14518", "state": "In progress"},
            {"id": "mc", "initiative": "Mission control", "ticket": "goodqa#15950", "milestones_done": 1,
             "milestones_total": 4, "next_step": "PR"}]

    def rows(self):
        return [
            {"agent_id": "a1", "role": "live", "source": "ah", "ticket": "GoodQA goodqa#15950", "task": "org graph"},
            {"agent_id": "a2", "role": "live", "source": "ah", "ticket": "", "task": "fix goodqa#15961 session pin"},
            {"agent_id": "a3", "role": "parked", "source": "ah", "ticket": "goodqa#14518", "task": "old"},
            {"agent_id": "a4", "role": "helper", "source": "ah", "ticket": "goodqa#15999", "task": "review"},
            {"agent_id": "a5", "role": "live", "source": "ah", "ticket": "goodqa#16000", "task": "solve tuning"},
        ]

    def test_live_tickets_become_rows_and_stale_file_rows_are_hidden(self):
        tickets = {"goodqa#15950": {"title": "Live org graph", "status": "in_progress"}}
        snap = {"items": [col.clean_initiative(r, n) for n, r in enumerate(self.FILE)], "stale": False, "error": "",
                "mtime": 1000.0}
        out = og.derive_initiatives(snap, self.rows(), tickets, now=1000.0 + 4 * 86400)
        ids = {i["ticket"]: i for i in out["items"]}
        self.assertEqual(set(ids), {"goodqa#15950", "goodqa#15961"})       # parked, helper and restricted rows: no
        self.assertEqual(out["untracked"], 0)
        mc = ids["goodqa#15950"]
        self.assertEqual((mc["initiative"], mc["state"], mc["source"]), ("Live org graph", "In progress", "live"))
        self.assertEqual((mc["milestones_done"], mc["next_step"]), (1, "PR"))  # the file still adds its plan
        self.assertEqual(mc["owner"], "a1")
        self.assertEqual(ids["goodqa#15961"]["initiative"], "fix goodqa#15961 session pin")  # no ticket read: task text
        self.assertEqual(ids["goodqa#15961"]["state"], "unknown")
        self.assertEqual((out["derived"], out["hidden_file_rows"]), (2, 1))  # prodmove hidden: the file is 4 d old

    def test_fresh_file_rows_stay(self):
        snap = {"items": [col.clean_initiative(r, n) for n, r in enumerate(self.FILE)], "mtime": 1000.0}
        out = og.derive_initiatives(snap, [], {}, now=2000.0)
        self.assertEqual([i["source"] for i in out["items"]], ["file", "file"])
        self.assertEqual(out["hidden_file_rows"], 0)

    def test_live_owner_without_ticket_gets_a_flagged_row(self):  # PR 242 panel: no live owner left unlinked
        rows = [{"agent_id": "a534e2ba26fdfb490", "role": "live", "source": "ah", "ticket": "", "task": "PR 238 rescue"},
                {"agent_id": "a950cdca38f9f893e", "role": "live", "source": "ah", "ticket": "", "task": ""},
                {"agent_id": "a92175d46df0c8388", "role": "live", "source": "ah", "ticket": "", "task": "solve tuning"}]
        out = og.derive_initiatives({"items": [], "mtime": None}, rows, {}, now=1.0)
        titles = {i["owner"]: (i["initiative"], i["state"]) for i in out["items"]}
        self.assertEqual(titles["a534e2ba26fdfb490"], ("PR 238 rescue", "No ticket"))
        self.assertEqual(titles["a950cdca38f9f893e"][0], "Untracked work (no ticket)")
        self.assertEqual(titles["a92175d46df0c8388"][0], "Untracked work (no ticket)")   # restricted: no task text
        self.assertEqual(out["untracked"], 3)

    def test_stale_owner_read_is_a_gap_line(self):
        fx = Fixture()
        graph, _, _ = collector(fx, [dict(row("bbbb2222"), role="live", source="ah", ah_stale=True)])
        graph.tick(1.0)
        self.assertTrue(any("last ah owners read failed" in g for g in graph.snapshot()["gaps"]))
        codex, _, _ = collector(fx, [dict(row("bbbb2222"), role="live", source="ah"),
                                     {"agent_id": "codex-x", "runtime": "codex", "source_stale": True}])
        codex.tick(1.0)
        self.assertFalse(any("last ah owners read failed" in g for g in codex.snapshot()["gaps"]))

    def test_restricted_task_never_becomes_a_title(self):
        rows = [{"agent_id": "a9", "role": "live", "source": "ah", "ticket": "goodqa#1", "task": "solve interview prep"}]
        out = og.derive_initiatives({"items": [], "mtime": None}, rows, {}, now=1.0)
        self.assertEqual(out["items"], [])


class FeedAdditions(unittest.TestCase):
    def test_review_verdict_becomes_a_feed_row(self):  # reviewer approved/rejected cue source
        entry = {"event": "review_result", "verdict": "BLOCK", "ticket": "GoodQA #15585", "range": "a..b"}
        self.assertTrue(col._meaningful(entry))
        self.assertEqual(col._note(entry), "BLOCK GoodQA #15585 a..b")
        self.assertFalse(col._meaningful({"event": "review_result", "verdict": "<b>x</b>"}))

    def test_inbox_counts_open_and_stale_asks(self):
        fx = Fixture()
        hub = Hub()
        graph = og.OrgGraph(hub, col.Health(hub), Runner(), owners_fn=lambda: [], session_fn=lambda: SESSION,
                            transcripts=og.Transcripts(fx.root), escalation_root=None, host="h", inbox_fn=lambda: (3, 1))
        graph.tick(1.0)
        user = nodes(graph.snapshot())["user"]
        self.assertEqual((user["inbox"], user["inbox_stale"]), (3, 1))

    def test_inbox_before_asks_report_is_loading_not_zero(self):  # startup race: never a false 0 on the user node
        fx = Fixture()
        hub = Hub()
        graph = og.OrgGraph(hub, col.Health(hub), Runner(), owners_fn=lambda: [], session_fn=lambda: SESSION,
                            transcripts=og.Transcripts(fx.root), escalation_root=None, host="h", inbox_fn=lambda: None)
        graph.tick(1.0)
        user = nodes(graph.snapshot())["user"]
        self.assertIsNone(user["inbox"])
        self.assertIsNone(user["inbox_stale"])

    def test_session_without_claude_transcript_is_named_not_silent(self):  # goodqa#15961: newest WAL may be Codex
        fx = Fixture()
        hub = Hub()
        other = "01a1d873-d7c9-7752-83a9-b10a1cb85371"
        graph = og.OrgGraph(hub, col.Health(hub), Runner(), owners_fn=lambda: [], session_fn=lambda: other,
                            transcripts=og.Transcripts(fx.root), escalation_root=None, host="h")
        graph.tick(1.0)
        snap = graph.snapshot()
        self.assertEqual(snap["session"], other)
        self.assertTrue(any(other[:8] in g and "goodqa#15961" in g for g in snap["gaps"]), snap["gaps"])
        empty = og.OrgGraph(hub, col.Health(hub), Runner(), owners_fn=lambda: [], session_fn=lambda: "",
                            transcripts=og.Transcripts(fx.root), escalation_root=None, host="h")
        empty.tick(1.0)
        self.assertTrue(any("No session" in g for g in empty.snapshot()["gaps"]))
        # the coordinating session with a transcript carries no such line
        fx.main([assistant(model="claude-opus-5-5")])
        graph2, _, _ = collector(fx, [])
        graph2.tick(1.0)
        self.assertFalse(any("goodqa#15961" in g for g in graph2.snapshot()["gaps"]))

    def test_initiatives_snapshot_keeps_the_file_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "initiatives.json")
            path.write_text(json.dumps([{"id": "x", "initiative": "X"}]))
            hub = Hub()
            from safeio import Reader
            item = col.Initiatives(hub, col.Health(hub), Reader([tmp]), str(path))
            item.tick(1.0)
            self.assertEqual(item.snapshot()["mtime"], path.stat().st_mtime)



class RestrictedProducerShape(unittest.TestCase):
    """Review A-2: the real `ah owners` shape for a restricted row is task None, restricted True and the ticket kept.
    Run it end to end (collector, initiatives, graph): no ticket title or task text may reach the UI."""

    class Health:
        def ok(self, *a):
            pass
        error = off = ok

    def test_restricted_ah_row_never_shows_its_ticket_or_title(self):
        hub = Hub()
        hub.publish = lambda *a, **k: None
        owners = col.Owners(hub, self.Health(), runner=None, tailer=None)
        ah_row = {"agent_id": "a1234567890abcdef", "type": "task-owner", "task": None, "restricted": True,
                  "owner": True, "state": "live", "severity": "info", "idle_s": 5, "ticket": "goodqa#777",
                  "last_activity": "", "last_reply": "secret reply", "stream": "secret stream"}
        owners._rows({"session": "s", "owners": [ah_row]}, 1.0)
        row = owners.rows[0]
        self.assertEqual((row["restricted"], row["ticket"], row["task"], row["stream"], row["last_reply"]),
                         (True, "", "", "", ""))
        self.assertEqual(owners.tickets(), [])
        tickets = {"goodqa#777": {"title": "SECRET interview loop", "status": "in_progress"}}
        out = og.derive_initiatives({"items": [], "mtime": None}, owners.rows, tickets, now=2.0)
        self.assertNotIn("SECRET", json.dumps(out))
        agent = {"agent_id": row["agent_id"], "type": row["type"], "state": row["state"], "task": row["task"],
                 "ticket": row["ticket"], "restricted": row["restricted"], "owner_flag": True,
                 "cap_role": row.get("role"), "description": ""}
        snap = og.build(session="s", coordinator={}, agents=[agent], tickets=tickets, escalation={}, host="h", now=2.0)
        self.assertNotIn("SECRET", json.dumps(snap))
        self.assertNotIn("goodqa#777", json.dumps(snap))

    def _owners_then_status(self, owner_rows, entries, read=True):
        hub = Hub()
        hub.publish = lambda *a, **k: None
        owners = col.Owners(hub, self.Health(), runner=None, tailer=None)
        if read:
            owners._rows({"session": "s", "owners": owner_rows}, 1.0)
        ledger = col.Ledger(Hub(), self.Health(), runner=None, session_fn=lambda: "s",
                            visible_fn=lambda: owners.unrestricted[1] if owners.unrestricted[0] == "s" else None)
        return {r["id"]: r["note"] for r in ledger._status({"verified": entries}, 0)["verified"]}

    ROWS = [{"agent_id": "a1234567890abcdef", "type": "task-owner", "task": None, "restricted": True, "owner": True,
             "state": "done", "severity": "info", "idle_s": 7 * 3600, "ticket": "goodqa#777", "last_activity": ""},
            {"agent_id": "a3", "type": "fixer", "task": "org graph", "restricted": False, "state": "done",
             "severity": "info", "idle_s": 7 * 3600, "ticket": "", "last_activity": ""}]
    ENTRIES = [
        {"id": "w1", "agent": "a1234567890abcdef", "at": "2026-11-13T01:00:00Z", "event": "result",
         "note": "candidate Jane scored 7/10"},
        {"id": "w2", "agent": "a3", "at": "2026-11-13T01:00:01Z", "event": "result", "note": "mock Interview prep"},
        {"id": "w3", "agent": "a3", "at": "2026-11-13T01:00:02Z", "event": "result", "note": "org graph shipped"},
        {"id": "w4", "agent": "a9", "at": "2026-11-13T01:00:03Z", "event": "result", "note": "unknown agent note"},
        {"id": "w5", "agent": "main", "at": "2026-11-13T01:00:04Z", "event": "status", "note": "merged PR 245"}]

    def test_status_view_hides_restricted_and_unknown_agents_notes(self):  # review A-2 and A-2b (7 h, filtered out)
        notes = self._owners_then_status(self.ROWS, self.ENTRIES)
        self.assertNotIn("Jane", json.dumps(notes))
        self.assertEqual(notes["w2"], "restricted")
        self.assertEqual(notes["w3"], "org graph shipped")   # known unrestricted, even though done 7 h ago
        self.assertTrue(notes["w4"].startswith("note hidden"))
        self.assertEqual(notes["w5"], "merged PR 245")

    def test_before_the_first_owner_read_only_main_notes_show(self):  # review A-2b
        notes = self._owners_then_status(self.ROWS, self.ENTRIES, read=False)
        self.assertEqual(notes["w5"], "merged PR 245")
        self.assertTrue(all(notes[k].startswith(("note hidden", "restricted")) for k in ("w1", "w2", "w3", "w4")))


    def test_restricted_row_drops_its_last_wal_note(self):  # review R-1
        class Tailer:
            last_items = {}

            def last_for(self, *a):
                return {"at": "2026-11-13T01:00:00Z", "event": "result", "note": "candidate Jane scored 7/10"}
        hub = Hub()
        hub.publish = lambda *a, **k: None
        owners = col.Owners(hub, self.Health(), runner=None, tailer=Tailer())
        owners._rows({"session": "s", "owners": [dict(self.ROWS[0], state="live", idle_s=5)]}, 1.0)
        self.assertIsNone(owners.rows[0]["last_item"])
        self.assertNotIn("Jane", json.dumps(owners.rows))

    def test_feed_hides_restricted_and_unknown_agents_notes(self):  # review R-2
        published = []
        hub = Hub()
        hub.publish = lambda e, *a, **k: published.append(e)
        tailer = col.WalTailer(hub, self.Health(), reader=None, roots=[])
        tailer.note_visible = lambda runtime, session, agent: agent == "aknown"
        cases = [("aknown", "org graph shipped"), ("aknown", "mock interview loop notes"),
                 ("a1234567890abcdef", "candidate Jane scored 7/10"), ("main", "merged PR 245")]
        for i, (agent, note) in enumerate(cases):
            tail = col._Tail(i + 1, 0, "claude", "s", agent)
            tailer._emit(tail, {"event": "result", "note": note, "at": "2026-11-13T01:00:00Z"}, "result")
        text = json.dumps(published)
        self.assertIn("org graph shipped", text)
        self.assertIn("merged PR 245", text)
        self.assertNotIn("interview", text)
        self.assertNotIn("Jane", text)

if __name__ == "__main__":
    unittest.main()
