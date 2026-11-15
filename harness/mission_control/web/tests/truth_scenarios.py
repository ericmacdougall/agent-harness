"""Status-truth scenarios from the real Ledger collector and Health rows (review PR 234 v3 F1, v2 F2).

Prints one JSON object: scenario name -> {"ledger": <ledger snapshot>, "health": [<health rows>]}. The node test
status-truth.test.mjs renders each one, so the page is tested against what the server actually publishes after a
timeout, a nonzero exit or invalid JSON, a failure after a good empty read, a partial read and each recovery.
Run by the node test with `python3 -I <this file>`; it reads and writes no files."""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
MC = HERE.parents[2]
sys.path.insert(0, str(MC.parent / "hooks"))
sys.path.insert(0, str(MC))
os.environ.setdefault("MC_HOOKS", str(MC.parent / "hooks"))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402

SID = "baab765b-d85c-46b4-b7b9-588eb912c770"
T0 = 1_800_000_000.0  # fixed epoch: 2027-01-15 08:00 UTC
GOALS = {"goals": []}
REQS = {"total": 0, "truncated": False, "requirements": []}
EMPTY = {"session": SID, "since_s": 43200, "entries": 4, "unread": [], "owners": {}, **{k: [] for k in col.Ledger.STATUS_LISTS}}
PARTIAL = dict(EMPTY, unread=[{"wal": "agent-x.jsonl", "agent": "x", "reason": "Permission denied"}])
FAILS = {"timeout": (124, ""), "nonzero": (1, "Traceback: boom"), "invalid_json": (0, "{not json")}


class Runner:
    def __init__(self):
        self.status = (0, json.dumps(EMPTY))

    def run(self, kind, *args, timeout=20.0, limit=0):
        if kind == "ah-status":
            return self.status
        return 0, json.dumps(GOALS if kind == "ah-goals" else REQS)


def scenario(steps, other_health=("asks", "owners", "initiatives", "wals", "chat"), failed=()):
    hub = ev.Hub()
    health = col.Health(hub)
    runner = Runner()
    ledger = col.Ledger(hub, health, runner, lambda: SID)
    for name in other_health:
        health.ok(name, "fixture")
    for name in failed:
        health.error(name, f"RuntimeError: {name} read failed")
    for n, status in enumerate(steps):
        runner.status = status
        ledger.run(T0 + 60 * n)
    return {"ledger": ledger.snapshot(), "health": health.snapshot()}


def main():
    good = (0, json.dumps(EMPTY))
    out = {}
    for name, failure in FAILS.items():
        out[f"initial_{name}"] = scenario([failure])
        out[f"stale_after_empty_{name}"] = scenario([good, failure])
        out[f"recovered_initial_{name}"] = scenario([failure, good])
        out[f"recovered_stale_{name}"] = scenario([good, failure, good])
    out["current_empty"] = scenario([good])
    out["partial"] = scenario([(0, json.dumps(PARTIAL))])
    out["stale_after_partial"] = scenario([(0, json.dumps(PARTIAL)), FAILS["nonzero"]])
    # the status read is fine, but the asks source never read: Blockers also rest on asks, so it is unknown
    out["asks_never_read"] = scenario([good], other_health=("owners", "initiatives", "wals", "chat"), failed=("asks",))
    print(json.dumps(out, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
