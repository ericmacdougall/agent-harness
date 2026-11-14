"""Spawn gate for the initiative lifecycle (GoodQA goodqa#15952 AC-2, NEG-6, NEG-7, NEG-16, NEG-19, NEG-21).

The user (queue 2026-11-14T04:40:13Z #69c80ac14ad8): "when i tell you do something that is initiative/owner worthy, it
starts as pending - and requires us to agree on acceptence gates". An owner spawn names its goal with [goal:<id>]; the
goal must be ACTIVE, READY or LEGACY, or PENDING with [goal:<id>:scoping] on a goal main created. Helpers are untouched.

Failing first: against main 98e33c5d tier_gate has no lifecycle_gate and the hook prints nothing for an untagged owner.
The ledger is built through the real mission_coverage CLI (test_lifecycle.LBase); the hook is run both in process and as
the installed-style subprocess `tier_gate.py hook` under a temp AH_HOME, in warn and enforce modes.
"""
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(HOOKS))
import test_lifecycle as tl  # noqa: E402
import lifecycle as lcm  # noqa: E402
import mission_coverage as mc  # noqa: E402
import model_tiers as tiers  # noqa: E402
import tier_gate as gate  # noqa: E402

SID = tl.SESSION
GID = tl.GID


def agent(prompt, subagent_type="task-owner", description="work"):
    return {"tool_name": "Agent", "session_id": SID,
            "tool_input": {"subagent_type": subagent_type, "prompt": prompt, "description": description}}


class SpawnBase(tl.LBase):
    def setUp(self):
        super().setUp()
        os.environ.pop("HARNESS_LIFECYCLE_GATE", None)
        self.policy = tiers.load_policy()

    def check(self, data, mode="warn", ladder_denies=False):
        policy = json.loads(json.dumps(self.policy))
        policy["caps"]["lifecycle_gate"] = mode
        tool = data["tool_name"]
        command = str((data.get("tool_input") or {}).get("command") or "")
        return gate.lifecycle_gate(data, tool, command, policy, data.get("session_id"), ladder_denies)

    def denied(self, data, needle, mode="enforce"):
        out = self.check(data, mode)
        self.assertEqual(out["verdict"], "deny", out)
        self.assertIn(needle, out["reason"])
        return out

    def allowed(self, data, mode="enforce"):
        out = self.check(data, mode)
        self.assertEqual(out["verdict"], "allow", out)
        return out


class Tags(unittest.TestCase):
    def test_tag_forms(self):
        self.assertEqual(lcm.goal_tags(["[goal:lc-goal] go"]), (("lc-goal", False), ""))
        self.assertEqual(lcm.goal_tags(["x", "[goal:lc-goal:scoping]"]), (("lc-goal", True), ""))
        self.assertEqual(lcm.goal_tags(["[goal:lc-goal] and again [goal:lc-goal]"]), (("lc-goal", False), ""))

    def test_malformed_tag_is_untagged(self):
        for text in ("[goal:../x]", "[goal:LC]", "[goal:lc-goal:owner]", "[goal:]"):
            tag, problem = lcm.goal_tags([text])
            self.assertIsNone(tag, text)
            self.assertIn("malformed", problem)

    def test_conflicting_tags(self):
        tag, problem = lcm.goal_tags(["[goal:a1] then [goal:b2]"])
        self.assertIsNone(tag)
        self.assertIn("conflicting", problem)
        self.assertIn("conflicting", lcm.goal_tags(["[goal:a1]", "[goal:a1:scoping]"])[1])

    def test_tag_in_code_is_ignored(self):
        self.assertEqual(lcm.goal_tags(["see `[goal:lc-goal]`"]), (None, ""))
        self.assertEqual(lcm.goal_tags(["```\n[goal:lc-goal]\n```"]), (None, ""))
        self.assertEqual(lcm.goal_tags(["```\n[goal:lc-goal]"]), (None, ""))  # an unclosed fence hides the rest


class Verdicts(SpawnBase):
    def test_active_and_ready_tags_pass(self):
        self.to_active()
        self.allowed(agent(f"[goal:{GID}] build it"))
        self.evidence_all()
        self.ok(["ready", "--goal", GID, "--ask", tl.DONE_ASK])
        self.allowed(agent(f"[goal:{GID}] fix the last bug"))

    def test_untagged_owner(self):
        self.to_active()
        self.denied(agent("build it"), "without a [goal:<id>] tag")
        self.denied(agent("build it", subagent_type="general-purpose"), "without a [goal:<id>] tag")
        self.denied(agent("build it", subagent_type="invented-type"), "without a [goal:<id>] tag")

    def test_helpers_are_untouched(self):
        self.seed_old_goals(ids=())
        self.propose()
        for helper in ("red-team", "click-tester", "Explore", "fixer"):
            out = self.check(agent(f"[goal:{GID}] look", subagent_type=helper), "enforce")
            self.assertEqual(out["verdict"], "none", helper)

    def test_pending_agreed_done_unknown_are_refused(self):
        self.seed_old_goals(ids=())
        self.propose()
        self.denied(agent(f"[goal:{GID}] build"), "is PENDING")
        self.ok(["agree", "--goal", GID, "--user-source", self.agreed_answer()])
        self.denied(agent(f"[goal:{GID}] build"), "is AGREED")
        self.denied(agent("[goal:nope-goal] build"), "not in the mission ledger")

    def test_done_goal_is_refused(self):
        self.to_ready()
        self.ok(["done", "--goal", GID, "--user-source", self.done_answer()])
        self.denied(agent(f"[goal:{GID}] more"), "is DONE")

    def test_legacy_passes_with_context(self):
        self.seed_old_goals(ids=("old-a",))
        self.ok(["migrate-lifecycle"])
        out = self.allowed(agent("[goal:old-a] keep going"))
        self.assertIn("LEGACY", out["context"])

    def test_hand_set_active_reads_pending_and_is_refused(self):
        self.seed_old_goals(ids=())
        self.propose()
        path = mc.goals_path(self.home)
        doc = json.loads(path.read_text())
        doc["goals"][-1]["lifecycle"]["state"] = "active"
        path.write_text(json.dumps(doc))
        self.denied(agent(f"[goal:{GID}] build"), "audit chain")  # tampered ledger: one-line deny in enforce
        self.assertEqual(self.check(agent(f"[goal:{GID}] build"), "warn")["verdict"], "deny")

    def test_malformed_or_conflicting_tag_refused(self):
        self.to_active()
        self.denied(agent("[goal:../x] build"), "malformed goal tag")
        self.denied(agent(f"[goal:{GID}] and [goal:old-b] build"), "conflicting goal tags")
        self.denied(agent(f"```\n[goal:{GID}]\n``` build"), "without a [goal:<id>] tag")

    def test_workflow_needs_a_tag_whatever_its_input(self):
        self.to_active()
        wf = {"tool_name": "Workflow", "session_id": SID, "tool_input": {"script": "run()", "args": {"n": 3}}}
        self.denied(wf, "without a [goal:<id>] tag")
        wf["tool_input"]["args"]["note"] = f"[goal:{GID}]"
        self.allowed(wf)
        # a tag inside a JS template literal of the script is the script's own text, not a quoted example
        script = {"tool_name": "Workflow", "session_id": SID,
                  "tool_input": {"script": "```js\nawait agent(`[goal:%s] build the parser`)\n```" % GID}}
        self.allowed(script)
        self.allowed({"tool_name": "Workflow", "session_id": SID,
                      "tool_input": {"script": "const a = `x`;\nawait agent(`[goal:%s] go`)" % GID}})
        self.seed_old_goals(ids=())
        self.ok(["add", "--goal", "p1", "--title", "P"])
        self.denied({"tool_name": "Workflow", "session_id": SID, "tool_input": {"args": "[goal:p1]"}}, "is PENDING")

    def test_bash_launch_is_warn_only(self):
        self.to_active()
        os.environ["HARNESS_LIFECYCLE_GATE"] = "enforce"
        out = self.check({"tool_name": "Bash", "session_id": SID,
                          "tool_input": {"command": "claude -p 'build it'"}}, "enforce")
        self.assertEqual((out["verdict"], out["mode"]), ("deny", "warn"))
        prose = self.check({"tool_name": "Bash", "session_id": SID,
                            "tool_input": {"command": "git commit -m 'claude fix'"}}, "enforce")
        self.assertEqual(prose["verdict"], "none")
        review = self.check({"tool_name": "Bash", "session_id": SID,
                             "tool_input": {"command": "codex exec '[review:x] look'"}}, "enforce")
        self.assertEqual(review["verdict"], "none")

    def test_no_ledger_gives_context_only(self):
        out = self.check(agent("build it"), "enforce")
        self.assertEqual(out["verdict"], "allow")
        self.assertIn("no mission ledger", out["context"])
        self.assertEqual(self.check(agent("build it"), "warn")["context"], "")

    def test_env_can_only_strengthen(self):
        os.environ["HARNESS_LIFECYCLE_GATE"] = "warn"
        self.assertEqual(gate.lifecycle_mode({"caps": {"lifecycle_gate": "enforce"}}), "enforce")
        os.environ["HARNESS_LIFECYCLE_GATE"] = "off"
        self.assertEqual(gate.lifecycle_mode({"caps": {"lifecycle_gate": "enforce"}}), "enforce")
        os.environ["HARNESS_LIFECYCLE_GATE"] = "enforce"
        self.assertEqual(gate.lifecycle_mode({"caps": {}}), "enforce")
        os.environ.pop("HARNESS_LIFECYCLE_GATE")
        self.assertEqual(gate.lifecycle_mode({"caps": {}}), "warn")

    def test_policy_value_is_validated(self):
        policy = json.loads(json.dumps(self.policy))
        policy["caps"]["lifecycle_gate"] = "enforced"
        with self.assertRaises(tiers.TierError):
            tiers.validate(policy)
        self.assertEqual(self.policy["caps"]["lifecycle_gate"], "warn")  # shipped default (ASSUMPTION A5)

    def test_gate_bug_stays_inside_the_gate(self):
        self.to_active()
        orig = lcm.spawn_verdict
        lcm.spawn_verdict = lambda *a, **k: 1 / 0
        try:
            out = self.check(agent(f"[goal:{GID}] build"), "warn")
        finally:
            lcm.spawn_verdict = orig
        self.assertEqual((out["verdict"], out["mode"]), ("deny", "warn"))
        self.assertIn("ZeroDivisionError", out["reason"])


class Scoping(SpawnBase):
    def test_scoping_on_main_created_pending_goal(self):
        self.seed_old_goals(ids=())
        self.propose()
        out = self.allowed(agent(f"[goal:{GID}:scoping] survey"))
        self.assertIn("no code", out["context"])
        self.assertTrue(out["facts"]["reserved"])
        # NEG-16: a second scoping spawn for the goal within 24 h is handled like an untagged one
        self.denied(agent(f"[goal:{GID}:scoping] survey again"), "handled as an untagged owner")

    def test_warn_mode_uses_no_reservation(self):
        self.seed_old_goals(ids=())
        self.propose()
        for _ in range(3):
            out = self.allowed(agent(f"[goal:{GID}:scoping] survey"), mode="warn")
            self.assertFalse(out["facts"]["reserved"])
        self.allowed(agent(f"[goal:{GID}:scoping] survey"))  # enforce still has its slot

    def test_no_reservation_when_the_ladder_refused(self):
        self.seed_old_goals(ids=())
        self.propose()
        out = self.check(agent(f"[goal:{GID}:scoping] survey"), "enforce", ladder_denies=True)
        self.assertFalse(out["facts"]["reserved"])
        self.allowed(agent(f"[goal:{GID}:scoping] survey"))

    def test_scoping_refused_on_an_owner_added_goal(self):
        self.seed_old_goals(ids=())
        self.ok(["add", "--goal", "o1", "--title", "O"], owner=True)
        self.denied(agent("[goal:o1:scoping] survey"), "not created or proposed by main")

    def test_draft_amendment_ac2a_is_off_by_default(self):
        self.assertIs(self.policy["caps"]["lifecycle_pending_build"], False)
        self.seed_old_goals(ids=())
        self.ok(["add", "--goal", "np1", "--title", "N"])
        self.propose()
        self.denied(agent(f"[goal:{GID}] build"), "is PENDING")
        self.policy["caps"]["lifecycle_pending_build"] = True
        out = self.allowed(agent(f"[goal:{GID}] build"))
        self.assertIn("AC-2a", out["context"])
        self.denied(agent("[goal:np1] build"), "is PENDING")  # no proposal registered: still refused

    def test_scoping_on_active_goal_is_just_active(self):
        self.to_active()
        self.allowed(agent(f"[goal:{GID}:scoping] survey"))

    def test_session_quota_of_two(self):
        self.seed_old_goals(ids=())
        for gid in ("s1", "s2", "s3"):
            self.ok(["add", "--goal", gid, "--title", gid])
        self.allowed(agent("[goal:s1:scoping] a"))
        self.allowed(agent("[goal:s2:scoping] b"))
        self.denied(agent("[goal:s3:scoping] c"), "2 scoping owners")
        other = agent("[goal:s3:scoping] c")
        other["session_id"] = "99999999-2222-4333-8444-555555555555"
        self.allowed(other)

    def test_reservations_expire_after_24_hours(self):
        state = mc.state_root(self.home)
        old = time.time() - lcm.SCOPING_TTL_S - 5
        self.assertEqual(lcm.reserve_scoping(state, "g1", SID, old, True), "")
        self.assertEqual(lcm.reserve_scoping(state, "g1", SID, time.time(), True), "")
        self.assertIn("already had", lcm.reserve_scoping(state, "g1", SID, time.time(), False))

    def test_symlinked_reservation_file_is_refused(self):
        state = mc.state_root(self.home)
        state.mkdir(parents=True, exist_ok=True)
        (state / "lifecycle-scoping.jsonl").symlink_to(self.home / "elsewhere")
        with self.assertRaises(lcm.LifecycleError):
            lcm.reserve_scoping(state, "g1", SID, time.time(), True)


def _reserve(args):
    state, goal, session = args
    return lcm.reserve_scoping(state, goal, session, time.time(), True)


class Concurrency(unittest.TestCase):
    """NEG-21: concurrent reservations; exactly one wins each race."""

    def race(self, jobs):
        with multiprocessing.get_context("spawn").Pool(len(jobs)) as pool:
            return pool.map(_reserve, jobs)

    def test_one_goal_two_spawns(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.race([(tmp, "g1", "sess-a"), (tmp, "g1", "sess-b")] * 4)
            self.assertEqual(sum(1 for r in out if r == ""), 1, out)

    def test_last_session_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(lcm.reserve_scoping(tmp, "g0", "sess", time.time(), True), "")
            out = self.race([(tmp, "g%d" % i, "sess") for i in range(1, 7)])
            self.assertEqual(sum(1 for r in out if r == ""), 1, out)


class HookProcess(SpawnBase):
    """The hook as Claude Code runs it: `tier_gate.py hook` reading the PreToolUse payload on stdin."""

    def run_hook(self, data, mode=None):
        env = dict(os.environ)
        env.pop("HARNESS_LIFECYCLE_GATE", None)
        if mode == "enforce":
            env["HARNESS_LIFECYCLE_GATE"] = "enforce"
        proc = subprocess.run([sys.executable, str(HOOKS / "tier_gate.py"), "hook"], input=json.dumps(data),
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout or "{}").get("hookSpecificOutput") or {}

    def test_warn_and_enforce_output(self):
        self.seed_old_goals(ids=())
        self.propose()
        warn = self.run_hook(agent(f"[goal:{GID}] build"))
        self.assertNotEqual(warn.get("permissionDecision"), "deny")
        self.assertIn("lifecycle gate (warn mode): would deny", warn.get("additionalContext", ""))
        enforce = self.run_hook(agent(f"[goal:{GID}] build"), mode="enforce")
        self.assertEqual(enforce.get("permissionDecision"), "deny")
        self.assertIn("is PENDING", enforce.get("permissionDecisionReason", ""))
        scoping = self.run_hook(agent(f"[goal:{GID}:scoping] survey"), mode="enforce")
        self.assertNotEqual(scoping.get("permissionDecision"), "deny", scoping)
        self.assertIn("no code", scoping.get("additionalContext", ""))
        helper = self.run_hook(agent("look around", subagent_type="Explore"), mode="enforce")
        self.assertNotIn("lifecycle", json.dumps(helper))


if __name__ == "__main__":
    unittest.main()
