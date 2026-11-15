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
    graph.visibility_fn = lambda: (True, ())   # an owner read landed and restricted nothing
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

    def test_one_failing_ticket_does_not_starve_the_others(self):  # PR 243 review F3
        rows = [row(f"own{n}", ticket=f"goodqa#{n}", kind="task-owner") for n in (1, 2, 3)]
        for n in (1, 2, 3):
            self.fx.agent(f"own{n}", kind="task-owner")
        runner = Runner({f"goodqa#{n}": {"title": f"T{n}", "status": "in_progress"} for n in (1, 2, 3)})
        graph, _, _ = collector(self.fx, rows, runner)
        base = 1_000_000.0
        for i in range(3):                       # every ticket read once while healthy
            graph.tick(base + 5.0 * i)
        self.assertEqual(set(graph.tickets), {"goodqa#1", "goodqa#2", "goodqa#3"})
        runner.fail.update({"goodqa#1"})        # then #1 fails persistently: a nonzero `ah ticket get`
        runner.calls.clear()
        t = 0.0
        for step in range(400):                  # about 33 minutes at the 5 s cadence, over six ticket TTLs
            t = base + og.TICKET_TTL_S + 5.0 * step
            graph.tick(t)
        reads = {n: sum(1 for _, args in runner.calls if args[0] == f"goodqa#{n}") for n in (1, 2, 3)}
        self.assertGreaterEqual(reads[2], 5, reads)    # healthy tickets keep refreshing about once per TTL
        self.assertGreaterEqual(reads[3], 5, reads)
        self.assertGreaterEqual(reads[1], 2, reads)    # the failing one is retried, with backoff, not every tick
        self.assertLess(reads[1], 100, reads)
        self.assertTrue(graph.ticket_stale["goodqa#1"])
        self.assertEqual(graph.tickets["goodqa#1"]["title"], "T1")   # the last good payload is kept
        self.assertGreaterEqual(t - graph.ticket_at["goodqa#2"], 0)
        self.assertLess(t - graph.ticket_at["goodqa#2"], og.TICKET_TTL_S + 30)

    def test_a_response_without_an_issue_backs_off_too(self):  # PR 243 review F3: the no-issue path
        rows = [row(f"own{n}", ticket=f"goodqa#{n}", kind="task-owner") for n in (1, 2)]
        for n in (1, 2):
            self.fx.agent(f"own{n}", kind="task-owner")
        runner = Runner({"goodqa#2": {"title": "T2", "status": "todo"}})   # goodqa#1 answers {"issue": {}}
        runner.run = (lambda real: lambda kind, *a, **k: (0, "{}") if a[0] == "goodqa#1" else real(kind, *a, **k))(
            runner.run)
        graph, _, _ = collector(self.fx, rows, runner)
        for step in range(200):
            graph.tick(5.0 * step)
        self.assertIn("goodqa#2", graph.tickets)
        self.assertTrue(graph.ticket_stale["goodqa#1"])


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
                        tickets={}, escalation={}, host="h", now=1.0, visible=og.ticket_visibility(True, ()))
        cur = og.build(session=SESSION, coordinator={}, agents=[dict(row("o1", ticket="goodqa#1"), read=True)],
                       tickets={"goodqa#1": {"blocks": ["goodqa#2"]}}, escalation={}, host="h", now=2.0, visible=og.ticket_visibility(True, ()))
        kinds = {c["type"] for c in og.diff(prev, cur, 2.0)}
        self.assertTrue({"added", "dag", "assigned"} <= kinds)

    def test_cap_keeps_live_agents(self):  # NEG-6
        agents = [dict(row(f"d{i}", state="done", idle=10), read=False) for i in range(og.MAX_AGENTS + 5)]
        agents.append(dict(row("live1"), read=False))
        snap = og.build(session=SESSION, coordinator={}, agents=agents, tickets={}, escalation={}, host="h", now=1.0, visible=og.ticket_visibility(True, ()))
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
            graph.visibility_fn = lambda: (True, ())   # as the server wires it once the demo owner read lands
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
        def __init__(self):
            self.on_aged = {}   # PR 234 v11: the ledger registers its parts' ageing hook here

        def ok(self, *a, **k):
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
        snap = og.build(session="s", coordinator={}, agents=[agent], tickets=tickets, escalation={}, host="h", now=2.0, visible=og.ticket_visibility(True, ()))
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
        # PR 234 v6: ah status always sends every list; a payload missing one is refused, so the fixture sends them all
        payload = {key: [] for key in col.Ledger.STATUS_LISTS}
        payload["verified"] = entries
        payload["owners"] = {"counts": {}}   # PR 234 v7: ah status always sends its owners view
        return {r["id"]: r["note"] for r in ledger._status(payload, 0)["verified"]}

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

    def test_any_owner_row_naming_restricted_work_is_scrubbed(self):  # review P-1 (Codex and supervised rows)
        codex = {"agent_id": "codex:t:main", "runtime": "codex", "task": "Observed native Codex WAL", "stream": "",
                 "name": "proj", "last_reply": "", "state": "observed",
                 "last_item": {"note": "solve tuning: candidate Jane", "progress_note": ""}}
        plain = dict(codex, agent_id="codex:t2:main", last_item={"note": "org graph shipped"})
        scrubbed = col.scrub_restricted_row(codex)
        self.assertEqual((scrubbed["restricted"], scrubbed["last_item"]), (True, None))
        self.assertNotIn("Jane", json.dumps(scrubbed))
        self.assertEqual(col.scrub_restricted_row(plain)["last_item"]["note"], "org graph shipped")

    def test_asks_naming_restricted_work_or_from_restricted_owners_are_hidden(self):  # review P-2
        sys.path.insert(0, str(REPO / "harness" / "hooks"))
        by_text = col.Asks.item("s", {"id": "w1", "owner": "a2", "note": "interview rubric for candidate Jane D",
                                      "reason": "needs your call"}, frozenset(), frozenset({"a2"}))
        # provenance names the owner by its WAL stem, `agent-<id>` (P recheck); the owner reads use the bare id
        by_owner = col.Asks.item("s", {"id": "w2", "owner": "agent-a1234567890abcdef", "note": "pick a slot",
                                       "reason": "x"}, frozenset({"a1234567890abcdef"}), frozenset({"a2"}))
        unknown = col.Asks.item("s", {"id": "w4", "owner": "agent-a9", "note": "rubric for candidate Jane D",
                                      "reason": "x"}, frozenset(), frozenset({"a2"}))
        self.assertNotIn("Jane", json.dumps(unknown))   # fail closed: an owner not known unrestricted
        plain = col.Asks.item("s", {"id": "w3", "owner": "a2", "note": "approve PR 245 merge", "reason": "gate"},
                              frozenset(), frozenset({"a2"}))
        self.assertNotIn("Jane", json.dumps(by_text))
        self.assertNotIn("pick a slot", json.dumps(by_owner))
        self.assertFalse(by_text["approvable"] or by_owner["approvable"])
        self.assertEqual(plain["text"], "approve PR 245 merge")

    def test_a_restricted_owners_ticket_is_never_tracked(self):  # P recheck: the initiatives-file edge
        import server as mcs
        self.assertTrue(mcs._same_ticket_in("GoodQA goodqa#777", frozenset({"goodqa#777"})))
        self.assertFalse(mcs._same_ticket_in("goodqa#7770", frozenset({"goodqa#777"})))
        hub = Hub()
        hub.publish = lambda *a, **k: None
        owners = col.Owners(hub, self.Health(), runner=None, tailer=None)
        owners._rows({"session": "s", "owners": [dict(self.ROWS[0], state="live", idle_s=5)]}, 1.0)
        self.assertEqual(owners.restricted_tickets, frozenset({"goodqa#777"}))


class RestrictedFileRowIntegration(unittest.TestCase):
    """PR 243 review F1: a fresh initiatives-file row on a restricted owner's ticket must not publish its title, ticket
    or plan through /api/state or any SSE initiatives frame. Runs the real App wiring (owners -> initiatives)."""

    SECRETS = ("SECRET-TITLE", "SECRET-PLAN", "SECRET-NOTE", "SECRET-TICKET", "goodqa#777")

    def app(self, owners):
        from unittest import mock
        sys.path.insert(0, str(REPO / "tests"))
        import server as mcs
        from test_mission_control import FakeRunner
        from test_mission_control_session_pin import MAIN, Home
        h = Home()
        self.addCleanup(h.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(h.home / "mc")})
        patcher.start()
        self.addCleanup(patcher.stop)
        (h.home / "mc").mkdir()
        path = h.home / "mc" / "initiatives.json"
        path.write_text(json.dumps([
            {"id": "hush", "initiative": "SECRET-TITLE loop", "ticket": "GoodQA goodqa#777",
             "next_step": "SECRET-PLAN call the candidate", "note": "SECRET-NOTE", "milestones_done": 1,
             "milestones_total": 3},
            {"id": "plain", "initiative": "Visible plan row", "ticket": "goodqa#15950", "next_step": "ship PR"}]))
        runner = FakeRunner({"ah-owners": lambda *a: (0, json.dumps({"read": col.whole_read(), "session": a[0], "owners": list(owners)})),
                             "ah-ticket-get": (0, json.dumps({"issue": {"title": "SECRET-TICKET", "status": "todo"}}))})
        app = mcs.App(port=47998, root=h.home / "mc", initiatives=str(path), remote=False, fabric_bin=None,
                      runner=runner, wal_roots=[(h.home / "nowals", "claude")], start_threads=False, session=MAIN,
                      wals_root=h.claude, projects_root=h.home / "projects")
        frames = []
        real = app.hub.snapshot
        app.hub.snapshot = lambda name, data: (frames.append((name, json.loads(json.dumps(data, default=str)))),
                                               real(name, data))[1]
        return app, frames

    @staticmethod
    def owner(**extra):
        return {"agent_id": "a1234567890abcdef", "type": "task-owner", "task": None, "restricted": True, "owner": True,
                "state": "live", "severity": "info", "idle_s": 5, "ticket": "goodqa#777", "last_activity": "",
                "role": "live", **extra}

    def assert_hidden(self, app, frames, *, visible=True):
        state = json.dumps(app.state(), default=str)
        initiatives = [d for n, d in frames if n == "initiatives"]
        self.assertTrue(initiatives, "the initiatives snapshot was published")
        for text in [state] + [json.dumps(d) for d in initiatives]:
            for secret in self.SECRETS:
                self.assertNotIn(secret, text)
        if visible:   # the check is not vacuous: unrestricted file rows still show, in state and the latest frame
            self.assertIn("Visible plan row", state)
            self.assertIn("Visible plan row", json.dumps(initiatives[-1]))

    def test_restricted_owner_read_first(self):
        app, frames = self.app([self.owner()])
        now = time.time()
        app.owners.run(now)
        self.assertEqual(app.owners.restricted_tickets, frozenset({"goodqa#777"}))
        app.initiatives.run(now)
        app.org.run(now)
        self.assert_hidden(app, frames)

    def test_initiatives_published_before_the_first_owner_read(self):  # the server loop's real collector order
        app, frames = self.app([self.owner()])
        self.assertLess(app.collectors.index(app.initiatives), app.collectors.index(app.owners))
        now = time.time()
        app.initiatives.run(now)      # no owner read yet: ticketed file rows are withheld (fail closed)
        app.owners.run(now)
        app.org.run(now)              # the restricted set is known now: republished with the plain row back
        self.assert_hidden(app, frames)

    def test_owner_scrubbed_by_restricted_text_hides_its_ticket_row(self):  # ah says restricted False, text says so
        app, frames = self.app([self.owner(restricted=False, task="mock interview prep")])
        now = time.time()
        app.owners.run(now)
        app.initiatives.run(now)
        app.org.run(now)
        self.assert_hidden(app, frames)

    def polled(self, app):
        """Run the comment collector a few times; the refs it asked GoodQA for and the ticket events it published."""
        events = []
        real = app.hub.publish
        app.hub.publish = lambda event, *a, **k: (events.append(json.loads(json.dumps(event, default=str))),
                                                  real(event, *a, **k))[1]
        app.runner.outputs["ah-ticket-comments"] = lambda ref: (0, json.dumps({"comments": [
            {"id": f"c-{ref[-3:]}", "createdAt": "2026-11-14T04:00:00Z", "body": f"SECRET-COMMENT on {ref}"}]}))
        for i in range(4):
            try:
                app.tickets.run(time.time() + i)
            except Exception:  # noqa: BLE001 - a failed read is the collector's own business here
                pass
        asked = [args[0] for kind, args, _t in app.runner.calls if kind == "ah-ticket-comments"]
        return asked, [e for e in events if e.get("kind") == "ticket"]

    def test_comment_polling_fails_closed_before_the_owner_read(self):  # PR 262 v2 receipt F2
        app, _frames = self.app([self.owner()])
        app.initiatives.run(time.time())   # the file names goodqa#777 and goodqa#15950; no owner read yet
        self.assertEqual(app.tracked_tickets(), [])
        asked, events = self.polled(app)
        self.assertEqual((asked, events), ([], []), "nothing is polled while restriction is unknown")

    def test_comment_polling_skips_restricted_tickets_after_the_owner_read(self):  # F2, and the control
        app, _frames = self.app([self.owner()])
        now = time.time()
        app.owners.run(now)
        app.initiatives.run(now)
        asked, events = self.polled(app)
        self.assertNotIn("goodqa#777", asked)
        self.assertIn("goodqa#15950", asked, "an unrestricted ticket is still polled (not vacuous)")
        self.assertFalse(any("777" in json.dumps(e) for e in events), events)

    def test_a_pin_move_makes_restriction_unknown_until_the_new_sessions_read(self):  # PR 262 v3 receipt F1
        app, frames = self.app([self.owner()])
        from test_mission_control_session_pin import OTHER   # on the path once app() has set it up
        now = time.time()
        app.owners.run(now)            # session A (MAIN): goodqa#777 restricted there, goodqa#15950 visible
        app.initiatives.run(now)
        app.org.run(now)
        self.assertIn("goodqa#15950", app.tracked_tickets(), "A's read is known for A (the control: not vacuous)")
        self.assertNotIn("goodqa#777", " ".join(app.tracked_tickets()))
        # the pin moves to B; B's owner read is delayed and then keeps failing. In B, goodqa#777's work is
        # unrestricted in A's read but B's restrictions are unknown, so nothing may be polled, shown or fetched.
        app.config_pin = OTHER
        self.assertEqual(app.pin()["display"], OTHER)
        self.assertEqual(app.tracked_tickets(), [], "a read for A authorizes nothing in B (fail closed)")
        self.assertFalse(app.org.visible()("goodqa#15950"))
        self.assertEqual(app.restriction(), (False, frozenset()))
        app.runner.outputs["ah-owners"] = (1, "")   # B's owner read fails
        for i in range(3):
            try:
                app.owners.run(now + 10 + i)
            except Exception:  # noqa: BLE001 - the failed read is the collector's own business
                pass
            self.assertEqual(app.tracked_tickets(), [], f"still unknown after failed B read {i}")
        asked, events = self.polled(app)
        self.assertEqual((asked, events), ([], []), "nothing is polled across the pin change")
        app.initiatives.run(now + 20)
        app.org.run(now + 20)
        latest = [d for n, d in frames if n == "initiatives"][-1]
        self.assertNotIn("Visible plan row", json.dumps(latest), "ticketed rows wait for B's read")
        self.assertNotIn("SECRET-TITLE", json.dumps(latest))
        # B's read lands: B restricts goodqa#15950, so the set comes from B, never from A
        app.runner.outputs["ah-owners"] = lambda *a: (0, json.dumps({"read": col.whole_read(), "session": a[0],
                                                                      "owners": [self.owner(ticket="goodqa#15950")]}))
        app.owners.run(now + 30)
        self.assertEqual(app.restriction(), (True, frozenset({"goodqa#15950"})))
        self.assertNotIn("goodqa#15950", app.tracked_tickets())
        self.assertFalse(app.org.visible()("goodqa#15950"))
        self.assertTrue(app.org.visible()("goodqa#777"), "B's read, not A's, decides now")

    def pinned_away_unrestricted(self):
        """An app whose session A has a live, unrestricted owner on goodqa#15950 with its task text populated, read and
        shown in A (the control), then pinned to B whose owner reads fail: the PR 262 v4 F1 fixture."""
        owner = self.owner(restricted=False, ticket="goodqa#15950", task="A-ONLY-TASK ship the plain row")
        app, frames = self.app([owner])
        from test_mission_control_session_pin import MAIN, OTHER  # on the path once app() set it up
        now = time.time()
        app.owners.run(now)
        app.initiatives.run(now)
        app.org.run(now)
        shown = json.dumps([d for n, d in frames if n == "initiatives"][-1])
        self.assertIn("goodqa#15950", shown, "the live row is shown in A (control)")
        self.assertIn("SECRET-TICKET", shown, "with its GoodQA title (control)")
        app.config_pin = OTHER
        app.runner.outputs["ah-owners"] = (1, "")
        return app, frames, now

    def test_live_owner_initiatives_wait_for_the_new_sessions_read(self):  # PR 262 v4 receipt F1
        app, frames, now = self.pinned_away_unrestricted()
        mark = len(frames)
        for i in range(3):   # B's owner read keeps failing; A's live row stays cached in owners.rows
            try:
                app.owners.run(now + 10 + i)
            except Exception:  # noqa: BLE001 - the failed read is the collector's own business
                pass
            app.initiatives.publish(None)
            app.org.run(now + 10 + i)
            state = app.state()
            for part in ("initiatives", "orggraph"):
                text = json.dumps(state[part], default=str)
                for secret in ("A-ONLY-TASK", "goodqa#15950", "SECRET-TICKET"):
                    self.assertNotIn(secret, text, f"{part} after failed B read {i}")
        published = [json.dumps(d) for n, d in frames[mark:] if n in ("initiatives", "orggraph")]
        self.assertTrue(published, "frames were published during the failed reads (not vacuous)")
        for text in published:
            for secret in ("A-ONLY-TASK", "goodqa#15950", "SECRET-TICKET"):
                self.assertNotIn(secret, text)

    def test_a_comment_read_in_flight_across_a_pin_move_is_discarded(self):  # PR 262 v4 receipt F4
        app, _frames = self.app([self.owner()])
        from test_mission_control_session_pin import MAIN, OTHER  # on the path once app() set it up
        now = time.time()
        app.owners.run(now)
        app.initiatives.run(now)
        self.assertIn("goodqa#15950", app.tracked_tickets())
        events = []
        real = app.hub.publish
        app.hub.publish = lambda event, *a, **k: (events.append(json.loads(json.dumps(event, default=str))),
                                                  real(event, *a, **k))[1]

        def moving(ref):   # the ledger thread moves the pin while this 20 s read is in flight
            app.config_pin = OTHER
            return 0, json.dumps({"comments": [{"id": "c-inflight", "createdAt": "2026-11-14T04:00:00Z",
                                                "body": f"INFLIGHT-COMMENT on {ref}"}]})
        app.runner.outputs["ah-ticket-comments"] = moving
        app.tickets.run(now + 1)
        self.assertFalse([e for e in events if e.get("kind") == "ticket"], "nothing authorized under A is published")
        self.assertNotIn("INFLIGHT-COMMENT", json.dumps(app.hub.recent(limit=500), default=str), "nor replayed")
        self.assertNotIn("goodqa#15950", app.tickets.seen, "a dropped result is not marked seen")
        # control: back on A, the same read publishes (the check is not a blanket refusal)
        app.config_pin = MAIN
        app.runner.outputs["ah-ticket-comments"] = lambda ref: (0, json.dumps({"comments": [
            {"id": "c-ok", "createdAt": "2026-11-14T04:00:00Z", "body": f"OK-COMMENT on {ref}"}]}))
        for i in range(2):
            app.tickets.run(now + 2 + i)
        self.assertTrue(any("OK-COMMENT" in json.dumps(e) for e in events), "an authorized read still publishes")

    def test_a_graph_ticket_read_in_flight_across_a_pin_move_is_not_broadcast(self):  # PR 262 v4 receipt F4
        owner = self.owner(restricted=False, ticket="goodqa#15950", task="plain work")
        app, frames = self.app([owner])
        from test_mission_control_session_pin import MAIN, OTHER  # on the path once app() set it up
        now = time.time()
        app.owners.run(now)

        def moving(*args):   # the pin moves while the graph's GoodQA read is in flight
            app.config_pin = OTHER
            return 0, json.dumps({"issue": {"title": "INFLIGHT-TITLE", "status": "todo"}})
        app.runner.outputs["ah-ticket-get"] = moving
        mark = len(frames)
        app.org.run(now + 1)
        self.assertTrue(any(k == "ah-ticket-get" for k, _a, _t in app.runner.calls), "the read happened (not vacuous)")
        for name, data in frames[mark:]:
            if name == "orggraph":
                self.assertNotIn("INFLIGHT-TITLE", json.dumps(data))
                self.assertNotIn("goodqa#15950", json.dumps(data))
        self.assertNotIn("INFLIGHT-TITLE", json.dumps(app.state()["orggraph"], default=str))

    def test_a_restricted_owner_appearing_later_republishes_without_the_row(self):  # not live: the org sig is unchanged
        owners = []
        app, frames = self.app(owners)
        now = time.time()
        app.owners.run(now)
        app.initiatives.run(now)
        app.org.run(now)
        self.assertIn("SECRET-TITLE", json.dumps([d for n, d in frames if n == "initiatives"][-1]))   # not known yet
        owners.append(self.owner(state="done", idle_s=60, role="parked"))
        app.owners.run(now + 10)
        app.org.run(now + 10)
        latest = [d for n, d in frames if n == "initiatives"][-1]
        self.assertNotIn("SECRET-TITLE", json.dumps(latest))
        self.assertNotIn("SECRET-TITLE", json.dumps(app.state(), default=str))
        self.assertIn("Visible plan row", json.dumps(latest))


if __name__ == "__main__":
    unittest.main()


class ReadFailures(unittest.TestCase):
    """PR 234 v7 audit T243-2: an unreadable transcript root, directory or file, or a bad escalation file, makes the
    org-graph read partial and says so; it is never an empty graph that reads as current. A file that does not exist
    is no failure (an agent with no meta yet)."""

    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("root reads unreadable files")
        self.fx = Fixture()
        self.fx.main([assistant("claude-opus-5-5")])
        self.fx.agent("own1", kind="task-owner", records=[assistant("claude-opus-5-5", "high")])
        self.locked = []

    def tearDown(self):
        for path in self.locked:
            os.chmod(path, 0o700)

    def lock(self, path):
        os.chmod(path, 0)
        self.locked.append(path)

    def run_graph(self, escalation_root=None):
        hub = Hub()
        health = col.Health(hub)
        graph = og.OrgGraph(hub, health, Runner(), owners_fn=lambda: [row("own1", kind="task-owner")],
                            session_fn=lambda: SESSION, transcripts=og.Transcripts(self.fx.root),
                            escalation_root=escalation_root, host="h", inbox_fn=lambda: (0, 0))
        graph.run(1_000_000.0)
        return health.rows["org-graph"], graph.snapshot()

    def test_everything_readable_is_current(self):
        health, _snap = self.run_graph()
        self.assertEqual((health["status"], health["truth"]), ("ok", "current"))

    def test_a_missing_meta_file_is_no_failure(self):
        (self.fx.sub / "agent-own1.meta.json").unlink()
        health, _snap = self.run_graph()
        self.assertEqual(health["truth"], "current")

    def test_an_unreadable_projects_root_is_partial_and_named(self):
        self.lock(self.fx.root)
        health, snap = self.run_graph()
        self.assertEqual(health["truth"], "partial", health)
        self.assertFalse(any("likely a Codex" in g for g in snap["gaps"]), snap["gaps"])
        self.assertTrue(any("could not be read" in g for g in snap["gaps"]), snap["gaps"])

    def test_an_unreadable_session_directory_is_partial(self):
        self.lock(self.fx.sub)
        health, _snap = self.run_graph()
        self.assertEqual(health["truth"], "partial", health)

    def test_an_unreadable_meta_or_transcript_is_partial(self):
        self.lock(self.fx.sub / "agent-own1.jsonl")
        health, _snap = self.run_graph()
        self.assertEqual(health["truth"], "partial", health)

    def test_a_bad_json_meta_is_partial(self):
        (self.fx.sub / "agent-own1.meta.json").write_text("{not json")
        health, _snap = self.run_graph()
        self.assertEqual(health["truth"], "partial", health)

    def test_a_bad_or_unreadable_escalation_file_is_partial(self):
        esc = Path(self.fx.tmp.name) / "escalation"
        esc.mkdir()
        (esc / "a.json").write_text("{not json")
        health, _snap = self.run_graph(esc)
        self.assertEqual(health["truth"], "partial", health)
        (esc / "a.json").write_text("{}")
        self.lock(esc / "a.json")
        health, _snap = self.run_graph(esc)
        self.assertEqual(health["truth"], "partial", health)


class EscalationReadIsBounded(unittest.TestCase):
    """PR 260 review F2 applied to 243: an escalation file swapped for a FIFO after the directory scan is refused, never
    opened blocking (the collector thread would hang), and is reported as a failed read."""

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs on this platform")
    def test_a_fifo_swapped_in_after_the_scan_is_refused(self):
        import threading
        from types import SimpleNamespace
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "a.json"
            os.mkfifo(fifo)
            now = time.time()
            # what the scan saw a moment earlier: a small regular file
            entry = SimpleNamespace(name="a.json", path=str(fifo), is_file=lambda follow_symlinks=True: True,
                                    stat=lambda follow_symlinks=True: SimpleNamespace(st_mtime=now, st_size=10))
            problems, done = [], []
            with mock.patch.object(og.os, "scandir", return_value=[entry]):
                worker = threading.Thread(target=lambda: done.append(og.escalations(Path(tmp), now=now, problems=problems)),
                                          daemon=True)
                worker.start()
                worker.join(10)
            self.assertTrue(done, "the escalation read returned (a blocking FIFO open would hang it)")
            self.assertEqual(done[0], {})
            self.assertTrue(problems, "the refused file is a failed read, so the graph read is partial")


class PayloadShapes(unittest.TestCase):
    """PR 260 v2 F4 shape rule applied to 243: an escalation file or a ticket payload of the wrong shape is a failed
    read, never an exception that aborts the org-graph tick."""

    def test_escalation_files_of_the_wrong_shape(self):
        for name, value in {"dispatches a number": {"escalations": [{"to": "R1"}], "dispatches": 5},
                            "escalations a string": {"escalations": "R1", "dispatches": [{"agent_id": "a1"}]},
                            "escalations a number": {"escalations": 3}}.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "task.json").write_text(json.dumps(value))
                problems = []
                self.assertEqual(og.escalations(Path(tmp), now=time.time(), problems=problems), {})
                self.assertTrue(problems, name)

    def test_ticket_payloads_of_the_wrong_shape(self):
        """PR 262 review F3: a wrong shape is a failed read (stale, retried, partial), never "no links"."""
        for name, bad in {"blocks a number": {"title": "T", "status": "open", "links": {"blocks": 5}},
                          "blockedBy a string": {"title": "T", "status": "open", "links": {"blockedBy": "goodqa#2"}},
                          "links a list": {"title": "T", "status": "open", "links": []},
                          "parent a number": {"title": "T", "status": "open", "parent": 7}}.items():
            with self.subTest(case=name):
                fx = Fixture()
                graph, hub, health = collector(fx, [row("o1", ticket="goodqa#1")], Runner(tickets={"goodqa#1": bad}))
                graph.run(time.time())   # must not raise
                self.assertNotIn("goodqa#1", graph.tickets, name)
                self.assertTrue(graph.ticket_stale.get("goodqa#1"), name)
                self.assertEqual(health.rows["org-graph"]["truth"], "partial", name)

    def test_a_ticket_payload_that_breaks_a_walk_is_a_failed_read(self):
        class Odd(Runner):
            def run(self, kind, *args, timeout=20.0, limit=0):
                return 0, json.dumps({"issue": {"links": {"blocks": [{"number": 1, "projectSlug": ["x"]}]}}})
        fx = Fixture()
        graph, hub, _ = collector(fx, [row("o1", ticket="goodqa#1")], Odd())
        graph.run(time.time())   # must not raise
        self.assertNotIn("goodqa#1x", json.dumps(graph.tickets))


SECRET_REF, SECRET_TITLE = "goodqa#9001", "SECRET hiring loop"


def shown_tickets(graph):
    """What the initiatives are given (visible_tickets); before PR 262's fix, the raw cache was handed over."""
    return graph.visible_tickets() if hasattr(graph, "visible_tickets") else dict(graph.tickets)


class RestrictedTicketRoutes(unittest.TestCase):
    """PR 262 review F1: a restricted ticket reaches the graph payload by no route. Each case names a different way a
    ticket id can arrive; the payload must carry no trace of it (id, number, title), and it is never fetched."""

    ROUTES = {
        "held by an unrestricted agent": dict(rows=[row("o1", ticket=SECRET_REF)], tickets={}),
        "named in an agent's task": dict(rows=[row("o1", task=f"work on GoodQA {SECRET_REF}")], tickets={}),
        "blocks link": dict(rows=[row("o1", ticket="goodqa#1")], tickets={"goodqa#1": {"links": {"blocks": [{"number": 9001}]}}}),
        "blockedBy link": dict(rows=[row("o1", ticket="goodqa#1")], tickets={"goodqa#1": {"links": {"blockedBy": [9001]}}}),
        "parent link": dict(rows=[row("o1", ticket="goodqa#1")], tickets={"goodqa#1": {"parent": {"number": 9001}}}),
        "a two-step link": dict(rows=[row("o1", ticket="goodqa#1")], tickets={"goodqa#1": {"links": {"blocks": [2]}},
                                                                             "goodqa#2": {"links": {"blocks": [9001]}}}),
    }

    def run_route(self, case, restricted=(SECRET_REF,), known=True, ticks=8):
        fx = Fixture()
        tickets = {ref: dict({"title": f"T{ref}", "status": "in_progress"}, **issue) for ref, issue in case["tickets"].items()}
        tickets[SECRET_REF] = {"title": SECRET_TITLE, "status": "in_progress"}
        runner = Runner(tickets=tickets)
        graph, hub, _ = collector(fx, case["rows"], runner)
        graph.visibility_fn = lambda: (known, restricted)
        t = 1_000_000.0
        for i in range(ticks):
            graph.run(t + i * og.TICKET_TTL_S)
        return graph, hub, runner

    def assert_no_trace(self, graph, hub, runner, name):
        blob = json.dumps([graph.snapshot(), [d for _n, d in hub.snaps], shown_tickets(graph)])
        self.assertNotIn("9001", blob, name)
        self.assertNotIn("SECRET", blob, name)
        self.assertNotIn(SECRET_REF, [args[0] for _k, args in runner.calls], f"{name}: fetched")

    def test_no_route_brings_a_restricted_ticket_into_the_payload(self):
        for name, case in self.ROUTES.items():
            with self.subTest(route=name):
                self.assert_no_trace(*self.run_route(case), name)

    def test_control_the_same_routes_show_an_unrestricted_ticket(self):  # the matrix is not vacuous
        for name, case in self.ROUTES.items():
            if name == "named in an agent's task":
                continue   # a ticket named only in task text is drawn when it is the agent's ticket ref (covered above)
            with self.subTest(route=name):
                graph, hub, runner = self.run_route(case, restricted=())
                self.assertIn(SECRET_REF, json.dumps(graph.snapshot()), name)

    def test_before_the_restriction_set_is_known_no_ticket_is_shown_or_fetched(self):
        graph, hub, runner = self.run_route(self.ROUTES["held by an unrestricted agent"], restricted=(), known=False)
        self.assertEqual(runner.calls, [])
        self.assertEqual(nodes(graph.snapshot(), "work"), {})
        self.assertEqual(shown_tickets(graph), {})

    def test_a_ticket_restricted_after_it_was_cached_is_dropped(self):
        case = self.ROUTES["blocks link"]
        state = {"restricted": ()}
        fx = Fixture()
        tickets = {"goodqa#1": {"title": "T1", "status": "in_progress", "links": {"blocks": [{"number": 9001}]}},
                   SECRET_REF: {"title": SECRET_TITLE, "status": "in_progress"}}
        runner = Runner(tickets=tickets)
        graph, hub, _ = collector(fx, case["rows"], runner)
        graph.visibility_fn = lambda: (True, state["restricted"])
        t = 1_000_000.0
        for i in range(4):
            graph.run(t + i * og.TICKET_TTL_S)
        self.assertIn(SECRET_TITLE, json.dumps(graph.snapshot()))   # cached and shown while it was not restricted
        state["restricted"] = (SECRET_REF,)
        hub.snaps.clear()
        runner.calls.clear()
        graph.run(t + 10 * og.TICKET_TTL_S)
        self.assertNotIn(SECRET_REF, graph.tickets)
        self.assert_no_trace(graph, hub, runner, "restricted after caching")

    def test_the_served_snapshot_follows_a_restriction_made_between_ticks(self):
        state = {"restricted": ()}
        fx = Fixture()
        runner = Runner(tickets={SECRET_REF: {"title": SECRET_TITLE, "status": "in_progress"}})
        graph, hub, _ = collector(fx, [row("o1", ticket=SECRET_REF, task=f"build {SECRET_REF}")], runner)
        graph.visibility_fn = lambda: (True, state["restricted"])
        graph.run(1_000_000.0)
        graph.run(1_000_000.0 + og.TICKET_TTL_S)
        self.assertIn(SECRET_TITLE, json.dumps(graph.snapshot()))
        state["restricted"] = (SECRET_REF,)   # the owner read lands between two org-graph ticks
        blob = json.dumps(graph.snapshot())
        self.assertNotIn("9001", blob)
        self.assertNotIn("SECRET", blob)
        self.assertEqual(nodes(graph.snapshot())["o1"]["task"], "restricted")

    def test_a_cue_for_a_node_already_gone_is_filtered_by_the_set(self):  # PR 262 v2 receipt F1
        snap = {"nodes": [{"id": "o1", "kind": "owner", "ticket": "", "task": "x", "live": True},
                          {"id": "work:goodqa#1", "kind": "work", "ref": "goodqa#1"},
                          {"id": f"work:{SECRET_REF}", "kind": "work", "ref": SECRET_REF}],
                "edges": [{"from": "work:goodqa#1", "to": f"work:{SECRET_REF}", "kind": "next"}],
                "counts": {"owner": 1, "subagent": 0, "reviewer": 0, "work": 2, "live_owners": 1, "hidden_agents": 0},
                "changes": [{"type": "removed", "node": f"work:{SECRET_REF}", "kind": "work"},
                            {"type": "assigned", "node": "o1", "ticket": SECRET_REF},
                            {"type": "dag", "edge": {"from": "work:goodqa#1", "to": f"work:{SECRET_REF}", "kind": "next"}},
                            {"type": "message", "from": "coordinator", "to": "o1"}]}
        visible = og.ticket_visibility(True, (SECRET_REF,))
        gone_first = dict(snap, nodes=snap["nodes"][:2], counts=dict(snap["counts"], work=1))   # node already absent
        for name, case in (("node present", snap), ("node already gone", gone_first)):
            with self.subTest(case=name):
                out = og._without_hidden(case, visible)
                self.assertNotIn("9001", json.dumps(out), name)
                self.assertEqual(out["counts"]["work"], 1, name)
                self.assertEqual([c["type"] for c in out["changes"]], ["message"], name)
        hidden_only = dict(snap, nodes=snap["nodes"][:1] + snap["nodes"][2:], counts=dict(snap["counts"], work=1))
        self.assertEqual(og._without_hidden(hidden_only, visible)["counts"]["work"], 0, "counts follow the filter")

    def test_initiatives_get_only_visible_tickets(self):
        graph, _hub, _runner = self.run_route(self.ROUTES["blocks link"], restricted=())
        graph.visibility_fn = lambda: (True, (SECRET_REF,))
        rows = [dict(row("o1", ticket=SECRET_REF), role="live", source="ah")]
        out = og.derive_initiatives({"items": [], "mtime": None}, rows, shown_tickets(graph), now=1.0)
        self.assertNotIn("SECRET", json.dumps(out))


class TicketReadsInTheEnvelope(unittest.TestCase):
    """PR 262 review F3: a failed or malformed ticket read makes the graph read partial and the initiative built on
    that ticket last known; recovery clears both."""

    def test_good_then_failed_then_malformed_then_good(self):
        fx = Fixture()
        good = {"title": "Build it", "status": "in_progress"}
        runner = Runner(tickets={"goodqa#5": good})
        graph, hub, health = collector(fx, [row("o1", ticket="goodqa#5")], runner)
        published = []
        graph.on_initiatives = lambda: published.append(1)
        live_rows = [dict(row("o1", ticket="goodqa#5"), role="live", source="ah")]

        def step(at):
            graph.run(at)
            item = og.derive_initiatives({"items": [], "mtime": None}, live_rows, shown_tickets(graph), now=at)["items"][0]
            return health.rows["org-graph"]["truth"], nodes(graph.snapshot(), "work")["work:goodqa#5"]["stale"], item
        t = 1_000_000.0
        truth, stale, item = step(t)
        self.assertEqual((truth, stale, item["state"], item["stale"]), ("current", False, "In progress", False))
        runner.fail = {"goodqa#5"}
        before = len(published)
        truth, stale, item = step(t + og.TICKET_TTL_S + 1)
        self.assertEqual((truth, stale, item["state"], item["stale"]), ("partial", True, "In progress (last known)", True))
        self.assertGreater(len(published), before, "the initiatives republish on a failed read")
        runner.fail = set()
        runner.tickets["goodqa#5"] = dict(good, links={"blocks": "goodqa#6"})
        truth, stale, item = step(t + 2 * og.TICKET_TTL_S + 1)
        self.assertEqual((truth, stale, item["stale"]), ("partial", True, True), "malformed is failed, not current")
        runner.tickets["goodqa#5"] = dict(good, status="in_review")
        truth, stale, item = step(t + 3 * og.TICKET_TTL_S + 1)
        self.assertEqual((truth, stale, item["state"], item["stale"]), ("current", False, "In review", False))


class NodeTruthFromOwnerRows(unittest.TestCase):
    """PR 243 on main: an agent node whose ah owners row is the last good copy (a failed ah read) says so."""

    def test_a_stale_ah_row_makes_its_node_stale(self):
        fx = Fixture()
        rows = [dict(row("o1"), source="ah", ah_stale=True), dict(row("o2"), source="ah"),
                dict(row("o3"), source="ah", source_stale=True)]
        graph, hub, _ = collector(fx, rows)
        graph.run(time.time())
        got = nodes(graph.snapshot())
        self.assertEqual((got["o1"]["stale"], got["o2"]["stale"], got["o3"]["stale"]), (True, False, True))

    def test_a_row_from_another_source_is_not_marked_by_ah_staleness(self):
        fx = Fixture()
        graph, hub, _ = collector(fx, [dict(row("o1"), source="native", ah_stale=True)])
        graph.run(time.time())
        self.assertFalse(nodes(graph.snapshot())["o1"]["stale"])
