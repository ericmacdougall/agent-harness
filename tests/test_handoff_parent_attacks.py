"""Red-team reproducers for 05849d35 (handoff-to-parent ack): each must leave the handoff unacked."""
import json
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WT / "tests"))
sys.path.insert(0, str(WT))
from tests.test_dropped_gate import Base, NOW, SESSION, iso, jl, ah  # noqa: E402


class Attacks(Base):
    def _meta(self, agent, **kw):
        m = self.home / ".claude" / "projects" / "proj" / SESSION / "subagents" / f"agent-{agent}.meta.json"
        m.parent.mkdir(parents=True, exist_ok=True)
        m.write_text(json.dumps(kw))

    def _rows(self, now):
        return {r["agent_id"]: r for r in self.owners(now=now)["owners"]}

    def _child_handoff(self, parent, at):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-dropowner.jsonl", [{"at": iso(at), "event": "handoff", "note": "to my parent: result ready"}])
        jl(w / "main.jsonl", [{"at": iso(at), "event": "subagent_stop", "agent_id": "dropowner", "agent_type": "task-owner"}])
        self._meta("dropowner", agentType="task-owner", parentAgentId=parent, finished=True)

    def test_A_finished_parent_with_a_live_sibling_takes_a_later_handoff(self):
        """Parent finished (done) BEFORE the child handed off; a live sibling keeps it in live_parents."""
        w = self.home / ".claude" / "wals" / SESSION
        later = NOW + ah.HANDOFF_ACK_S + 1
        jl(w / "agent-a1111111.jsonl", [{"at": iso(NOW - 3000), "event": "result", "note": "my report, sent"}])
        jl(w / "main.jsonl", [{"at": iso(NOW - 3000), "event": "subagent_stop", "agent_id": "a1111111",
                               "agent_type": "task-owner"},
                              {"at": iso(NOW - 3000), "event": "subagent", "agent_id": "sib", "agent_type": "red-team"}])
        self._meta("a1111111", agentType="task-owner", finished=True)
        self._meta("sib", agentType="red-team", parentAgentId="a1111111")
        jl(w / "agent-sib.jsonl", [{"at": iso(later - 20), "event": "intent", "note": "still reviewing"}])
        self._child_handoff("a1111111", NOW)  # handed off 50 min after the parent already returned
        by = self._rows(later)
        self.assertIn("handoff-unacked", by["dropowner"]["flags"])  # expected safe behaviour

    def test_B_helper_parent_waiting_on_a_dead_agent(self):
        """Non-owner parent stopped with 'waiting on <dead agent>': the wait-target check skips non-owners."""
        w = self.home / ".claude" / "wals" / SESSION
        later = NOW + ah.HANDOFF_ACK_S + 1
        jl(w / "main.jsonl", [{"at": iso(NOW - 500), "event": "subagent", "agent_id": "helperpar",
                               "agent_type": "general-purpose"},
                              {"at": iso(NOW - 400), "event": "subagent_stop", "agent_id": "helperpar",
                               "agent_type": "general-purpose"}])
        jl(w / "agent-helperpar.jsonl", [{"at": iso(NOW - 400), "event": "status", "note": "waiting on a2222222"}])
        self._child_handoff("helperpar", NOW)
        by = self._rows(later)
        self.assertIn("handoff-unacked", by["dropowner"]["flags"])

    def test_C_forged_parent_id_names_any_live_owner(self):
        """A main-spawned owner whose meta names an unrelated live owner as parent is acked."""
        w = self.home / ".claude" / "wals" / SESSION
        later = NOW + ah.HANDOFF_ACK_S + 1
        jl(w / "agent-aliveowner.jsonl", [{"at": iso(later - 30), "event": "intent", "note": "unrelated work"}])
        self._child_handoff("aliveowner", NOW)
        by = self._rows(later)
        self.assertIn("handoff-unacked", by["dropowner"]["flags"])
