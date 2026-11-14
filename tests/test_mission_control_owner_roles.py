"""Owner roles for the Mission Control owners panel (goodqa#15920).

AC-1: the rows Mission Control calls live are exactly the ones tier_gate.live_owner_ids counts against the owner cap
for the same `ah owners` snapshot. AC-4: helpers are never counted and point at the owner they serve. AC-6/NEG-3: Codex
rows get the same three roles. NEG-5: parent cycles terminate. NEG-6: a slot-holding owner survives the 60-row cap."""
import json
import os
import sys
import tempfile
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
import tier_gate  # noqa: E402

LIVE_WAIT = {"kind": "waiting", "ref": "wabc", "reason": "named wait", "until": 1e12, "live": True}
CLOSED = {"kind": "closed", "ref": "", "reason": "merged", "until": None, "live": True}
RESUMED = {"kind": "resumed", "ref": "", "reason": "", "until": None, "live": True}

# (agent_id, type, owner flag, state, idle_s, disposition, decision_required, parent, ticket)
FIXTURE = [
    ("a0000000000000001", "task-owner", True, "live", 30, None, False, None, "goodqa#1"),
    ("a0000000000000002", "general-purpose", False, "working", 60, None, False, None, "goodqa#2"),
    ("a0000000000000003", "task-owner", True, "quiet", 900, None, False, None, "goodqa#3"),
    ("a0000000000000004", "task-owner", True, "SILENT-HIGH", 4000, None, False, None, "goodqa#4"),
    ("a0000000000000005", "task-owner", True, "SILENT", 4000, CLOSED, False, None, "goodqa#5"),
    ("a0000000000000006", "task-owner", True, "SILENT", 4000, LIVE_WAIT, False, None, "goodqa#6"),
    ("a0000000000000007", "task-owner", True, "SILENT", 4000, LIVE_WAIT, True, None, "goodqa#7"),
    ("a0000000000000008", "task-owner", True, "SILENT", 4000, RESUMED, False, None, "goodqa#8"),
    ("a0000000000000009", "general-purpose", False, "idle-helper", 600, None, False, None, "goodqa#9"),
    ("a000000000000000a", "general-purpose", False, "idle-helper", 5000, None, False, None, None),
    ("a000000000000000b", "task-owner", True, "finishing", 20, None, False, None, "goodqa#11"),
    ("a000000000000000c", "general-purpose", False, "handoff", 300, None, False, None, "goodqa#12"),
    ("a000000000000000d", "general-purpose", False, "returned", 300, None, False, None, None),
    ("a000000000000000e", "task-owner", True, "DROPPED", 9000, None, True, None, "goodqa#14"),
    ("a000000000000000f", "task-owner", True, "done", 100, None, False, None, None),
    ("a0000000000000010", "task-owner", True, "waiting-on-wabc", 100, None, False, None, None),
    # helpers: a live red-team spawned by an owner, one by main tied by ticket, one with no owner, one owner-flagged
    ("a0000000000000011", "red-team", False, "live", 10, None, False, "a0000000000000001", None),
    ("a0000000000000012", "reviewer", False, "live", 10, None, False, None, "goodqa#2"),
    ("a0000000000000013", "click-tester", False, "done", 10, None, False, None, "goodqa#none"),
    ("a0000000000000014", "fixer", True, "live", 10, None, False, None, None),
    # nested helper chain and a cycle
    ("a0000000000000015", "Explore", False, "live", 10, None, False, "a0000000000000011", None),
    ("a0000000000000016", "Plan", False, "live", 10, None, False, "a0000000000000017", None),
    ("a0000000000000017", "Plan", False, "live", 10, None, False, "a0000000000000016", None),
    ("a0000000000000018", "red-team", False, "handoff", 10, None, False, "a000000000000000c", None),
    ("a0000000000000019", "", False, "live", 10, None, False, None, None),
    ("a000000000000001a", "invented-type", False, "live", 10, None, False, None, None),
    # idle-helper boundary (30 min), unknown idle, None type, closed+decision_required, a task-named WAL owner
    ("a000000000000001b", "general-purpose", False, "idle-helper", 1799, None, False, None, None),
    ("a000000000000001c", "general-purpose", False, "idle-helper", 1801, None, False, None, None),
    ("a000000000000001d", "general-purpose", False, "idle-helper", None, None, False, None, None),
    ("a000000000000001e", None, False, "live", 10, None, False, None, None),
    ("a000000000000001f", "task-owner", True, "SILENT", 4000, CLOSED, True, None, None),
    ("deploy-fix-wal", "task-wal", True, "working", 50, None, False, None, None),
]


def ah_rows():
    out = []
    for agent, kind, owner, state, idle, disp, decision, parent, ticket in FIXTURE:
        row = {"agent_id": agent, "type": kind, "owner": owner, "state": state, "idle_s": idle, "parent": parent,
               "ticket": ticket, "decision_required": decision, "task": f"task {agent[-2:]}"}
        if disp:
            row["disposition"] = dict(disp)
        out.append(row)
    return out


class Runner:
    def __init__(self, payload):
        self.payload = payload

    def run(self, kind, *args, timeout=20.0, limit=0):
        assert kind == "ah-owners"
        return 0, json.dumps(self.payload)


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="mc-roles-")
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(Path(tmp.name) / "mc")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.hub = ev.Hub(max_rate=10_000)
        self.health = col.Health(self.hub)

    def collect(self, rows):
        owners = col.Owners(self.hub, self.health, Runner({"session": "s1", "owners": rows}), None)
        owners.run(time.time())
        return owners.rows


class CapParity(Base):
    def test_live_rows_equal_tier_gate_live_owner_ids(self):
        rows = ah_rows()
        policy = tier_gate.tiers.load_policy(REPO / "harness" / "hooks" / "model_tiers.json")
        with mock.patch.object(tier_gate, "_owners_with_deadline", return_value={"owners": ah_rows()}):
            expected = set(tier_gate.live_owner_ids("s1", policy))
        mc = self.collect(rows)
        live = {r["agent_id"] for r in mc if r.get("role") == "live"}
        self.assertEqual(live, expected)
        self.assertLess(len(live), len(mc), "the old panel counted every row; the cap counts only live owners")
        # pinned by hand too, so a change in tier_gate shows up here as a reviewed diff, not silently
        self.assertEqual(sorted(a[-2:] for a in live),
                         ["01", "02", "03", "04", "07", "08", "09", "14", "19", "1a", "1b", "1e", "1f", "al"])

    def test_every_row_has_a_role_and_helpers_are_not_live(self):
        mc = {r["agent_id"]: r for r in self.collect(ah_rows())}
        self.assertTrue(all(r.get("role") in ("live", "parked", "helper") for r in mc.values()))
        for helper in ("11", "12", "13", "15", "16", "17", "18"):
            self.assertEqual(mc["a00000000000000" + helper]["role"], "helper", helper)
        self.assertEqual(mc["a0000000000000014"]["role"], "live", "an owner-flagged helper type is an owner (cap rule)")
        for parked in ("05", "06", "0a", "0b", "0c", "0d", "0e", "0f", "10", "1c"):
            self.assertEqual(mc["a00000000000000" + parked]["role"], "parked", parked)
        self.assertNotIn("a000000000000001d", mc, "an idle-helper with unknown idle is terminal history (6 h rule)")
        self.assertEqual(mc["deploy-fix-wal"]["role"], "live", "a task-named WAL owner counts, whatever its runtime")


class Session(Base):
    def test_rows_name_the_session_ah_counted_and_follow_a_change(self):
        payload = {"session": "s1", "owners": ah_rows()[:2]}
        owners = col.Owners(self.hub, self.health, Runner(payload), None)
        owners.run(time.time())
        self.assertEqual({r["session"] for r in owners.rows}, {"s1"})
        payload["session"] = "s2-newer"
        owners.run(time.time() + 61)
        self.assertEqual({r["session"] for r in owners.rows}, {"s2-newer"}, "the label follows the session ah reports")


class AhFreshness(Base):
    def test_a_healthy_codex_row_never_hides_a_stale_ah_read(self):
        """Code inspection F1: an ah row merged with a supervised Codex row keeps ah's role; the merge must not let the
        supervisor's fresh source_stale make that cached role look current."""
        from types import SimpleNamespace
        payload = {"session": "s1", "owners": [{"agent_id": "codex-sup", "agent": "main", "thread": "T1", "runtime": "codex",
                                                "type": "task-owner", "owner": True, "state": "live", "idle_s": 5}]}
        calls = {"code": 0}
        runner = SimpleNamespace(run=lambda kind, *a, **k: (calls["code"], json.dumps(payload)))
        owners = col.Owners(self.hub, self.health, runner, None)
        owners.supervised = SimpleNamespace(rows=[{"agent_id": "openai:sup", "name": "sup", "runtime": "codex", "thread": "T1",
                                                   "state": "live", "source_stale": False, "type": "owner"}])
        owners.run(time.time())
        merged = [r for r in owners.rows if r.get("thread") == "T1"]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "ah")
        self.assertFalse(merged[0]["ah_stale"])
        calls["code"] = 1                                   # ah read fails; the supervisor stays healthy
        owners.run(time.time() + 61)
        merged = [r for r in owners.rows if r.get("thread") == "T1"][0]
        self.assertFalse(merged["source_stale"], "the supervisor's own freshness wins the merge")
        self.assertTrue(merged["ah_stale"], "but the ah snapshot is still marked stale")
        calls["code"] = 0                                   # recovery
        owners.run(time.time() + 122)
        self.assertFalse([r for r in owners.rows if r.get("thread") == "T1"][0]["ah_stale"])


class Identity(Base):
    """Code inspection F1/F2 at e6f4032: identity changes in publish() must keep ah's count and helper links."""

    def make(self, owners_rows, code=None):
        from types import SimpleNamespace
        payload = {"session": "s1", "owners": owners_rows}
        state = {"code": 0}
        runner = SimpleNamespace(run=lambda kind, *a, **k: (state["code"], json.dumps(payload)))
        owners = col.Owners(self.hub, self.health, runner, None)
        owners.supervised = SimpleNamespace(rows=[{"agent_id": "openai:sup", "name": "sup", "runtime": "codex",
                                                   "state": "live", "source_stale": False, "type": "owner"}])
        return owners, state

    def test_threadless_ah_alias_keeps_headline_parity_session_staleness_and_recovers(self):
        rows = [{"agent_id": "codex-sup", "type": "task-owner", "owner": True, "state": "live", "idle_s": 5}]
        with mock.patch.object(tier_gate, "_owners_with_deadline", return_value={"owners": rows}):
            expected = set(tier_gate.live_owner_ids("s1", tier_gate.tiers.load_policy(REPO / "harness" / "hooks" / "model_tiers.json")))
        self.assertEqual(expected, {"codex-sup"})
        owners, state = self.make(rows)
        owners.run(time.time())
        sup = [r for r in owners.rows if r["agent_id"] == "openai:sup"]
        self.assertEqual(len(owners.rows), 1, "the alias folds into the supervisor row, shown once")
        self.assertEqual((sup[0]["source"], sup[0]["role"], sup[0]["session"]), ("ah", "live", "s1"))
        self.assertIn("codex-sup", sup[0]["alias_ids"])
        self.assertEqual(sum(1 for r in owners.rows if r.get("source") == "ah" and r.get("role") == "live"), len(expected))
        state["code"] = 1
        owners.run(time.time() + 61)
        self.assertTrue([r for r in owners.rows if r["agent_id"] == "openai:sup"][0]["ah_stale"])
        state["code"] = 0
        owners.run(time.time() + 122)
        sup = [r for r in owners.rows if r["agent_id"] == "openai:sup"][0]
        self.assertFalse(sup["ah_stale"])
        self.assertEqual(sup["source"], "ah")

    def test_helper_parent_link_follows_a_combined_owner(self):
        rows = [{"agent_id": "codex-sup", "type": "task-owner", "owner": True, "state": "live", "idle_s": 5},
                {"agent_id": "a00000000000c0de", "type": "red-team", "owner": False, "state": "live", "idle_s": 5,
                 "parent": "codex-sup"},
                {"agent_id": "a00000000000beef", "type": "task-owner", "owner": True, "state": "live", "idle_s": 5}]
        owners, _ = self.make(rows)
        owners.run(time.time())
        helper = [r for r in owners.rows if r["agent_id"] == "a00000000000c0de"][0]
        self.assertEqual(helper["serves"], "openai:sup", "explicit parent resolved through the alias, not lost")


class Serves(Base):
    def test_helpers_point_at_the_owner_they_serve(self):
        mc = {r["agent_id"]: r for r in self.collect(ah_rows())}
        self.assertEqual(mc["a0000000000000011"]["serves"], "a0000000000000001", "parent")
        self.assertEqual(mc["a0000000000000015"]["serves"], "a0000000000000001", "parent chain through a helper")
        self.assertEqual(mc["a0000000000000012"]["serves"], "a0000000000000002", "ticket fallback for main-spawned")
        self.assertEqual(mc["a0000000000000018"]["serves"], "a000000000000000c", "a parked owner keeps its helpers")
        self.assertIsNone(mc["a0000000000000013"]["serves"], "no owner: shown as such, never dropped")
        self.assertIsNone(mc["a0000000000000016"]["serves"], "a parent cycle terminates with no owner")
        self.assertIsNone(mc["a0000000000000001"]["serves"], "owners serve nobody")

    def test_malformed_parent_is_dropped(self):
        rows = ah_rows()
        rows[16]["parent"] = "../../etc; rm"
        mc = {r["agent_id"]: r for r in self.collect(rows)}
        self.assertIsNone(mc["a0000000000000011"]["parent"])


class Truncation(Base):
    def test_slot_holding_owner_survives_the_sixty_row_cap(self):
        rows = [{"agent_id": f"a{i:016x}", "type": "task-owner", "owner": True, "state": "done", "idle_s": 5}
                for i in range(100, 180)]
        rows.append({"agent_id": "a00000000000beef", "type": "task-owner", "owner": True, "state": "SILENT-HIGH",
                     "idle_s": 50_000})
        rows.append({"agent_id": "a00000000000dead", "type": "task-owner", "owner": True, "state": "DROPPED",
                     "idle_s": 60_000})
        mc = self.collect(rows)
        self.assertEqual(len(mc), 60)
        self.assertIn("a00000000000beef", {r["agent_id"] for r in mc if r["role"] == "live"})
        self.assertIn("a00000000000dead", {r["agent_id"] for r in mc}, "an alarm row is not cut by the cap either")


class CodexRoles(unittest.TestCase):
    def test_codex_roles(self):
        self.assertEqual(col.codex_role({"state": "live"}), "live")
        self.assertEqual(col.codex_role({"state": "observed", "agent": "main"}), "live")
        for state in ("idle", "waiting", "blocked", "error", "offline", "stopped", "stale", "unknown", None):
            self.assertEqual(col.codex_role({"state": state}), "parked", state)
        self.assertEqual(col.codex_role({"state": "observed", "agent": "worker1"}), "helper")

    def test_codex_sub_agent_serves_its_thread_main(self):
        rows = [{"agent_id": "codex:t1:main", "runtime": "codex", "thread": "t1", "agent": "main", "role": "live"},
                {"agent_id": "codex:t1:w", "runtime": "codex", "thread": "t1", "agent": "w", "role": "helper"},
                {"agent_id": "codex:t2:w", "runtime": "codex", "thread": "t2", "agent": "w", "role": "helper"}]
        col._serves(rows)
        self.assertEqual(rows[1]["serves"], "codex:t1:main")
        self.assertIsNone(rows[2]["serves"])


class Policy(unittest.TestCase):
    def test_policy_reads_model_tiers_caps(self):
        policy = col.owner_policy(REPO / "harness" / "hooks")
        caps = json.loads((REPO / "harness" / "hooks" / "model_tiers.json").read_text())["caps"]
        self.assertEqual(policy["helper_types"], frozenset(caps["helper_types"]))
        self.assertEqual(policy["owner_types"], frozenset(caps["owner_types"]))

    def test_missing_policy_falls_back_to_defaults_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = col.owner_policy(tmp)
        self.assertIn("red-team", policy["helper_types"])
        self.assertTrue(policy["fallback"])
        self.assertFalse(col.owner_policy(REPO / "harness" / "hooks")["fallback"])

    def test_policy_honours_the_tier_policy_override_and_rereads_on_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tiers.json"
            path.write_text(json.dumps({"caps": {"owner_types": ["task-owner"], "helper_types": ["red-team", "custom-helper"]}}))
            with mock.patch.dict(os.environ, {"AGENT_HARNESS_TIER_POLICY": str(path)}):
                self.assertIn("custom-helper", col.owner_policy()["helper_types"])
                path.write_text(json.dumps({"caps": {"owner_types": ["task-owner"], "helper_types": ["red-team"]}}))
                os.utime(path, ns=(time.time_ns(), time.time_ns() + 10**9))
                self.assertNotIn("custom-helper", col.owner_policy()["helper_types"])

    def test_mirrored_constants_equal_tier_gate(self):
        self.assertEqual(col.OWNER_RUNNING, tier_gate.RUNNING_STATES)
        self.assertEqual(col.IDLE_OWNER_MAX_S, tier_gate.IDLE_OWNER_MAX_S)
        self.assertEqual(list(col.HELPER_TYPES_DEFAULT), tier_gate.HELPER_TYPES_DEFAULT)
        self.assertEqual(set(col.OWNER_TYPES_DEFAULT), tier_gate.owner_types({}))
        self.assertEqual(set(col.HELPER_TYPES_DEFAULT), tier_gate.helper_types({}))


if __name__ == "__main__":
    unittest.main()
