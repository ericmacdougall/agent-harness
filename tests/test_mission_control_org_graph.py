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


if __name__ == "__main__":
    unittest.main()
