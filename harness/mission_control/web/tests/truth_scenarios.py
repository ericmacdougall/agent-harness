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
GOALS = {"state": "ok", "warnings": [], "goals": []}
REQS = {"read": col.whole_read(), "total": 0, "truncated": False, "requirements": []}
EMPTY = {"read": col.whole_read(), "session": SID, "since_s": 43200, "entries": 4, "unread": [], "owners": {"counts": {}}, **{k: [] for k in col.Ledger.STATUS_LISTS}}
PARTIAL = dict(EMPTY, unread=[{"wal": "agent-x.jsonl", "agent": "x", "reason": "Permission denied"}])
FAILS = {"timeout": (124, ""), "nonzero": (1, "Traceback: boom"), "invalid_json": (0, "{not json")}


class Runner:
    def __init__(self):
        self.status = (0, json.dumps(EMPTY))

    def run(self, kind, *args, timeout=20.0, limit=0):
        if kind == "ah-status":
            return self.status
        return 0, json.dumps(GOALS if kind == "ah-goals" else REQS)


# every source a dataset rests on (collectors.FEEDS), so a scenario breaks exactly the one it names
OTHERS = tuple(sorted({s for sources in col.FEEDS.values() for s in sources if not s.startswith("ledger:")}))


def scenario(steps, other_health=OTHERS, failed=()):
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
    return {"ledger": ledger.snapshot(), "health": health.snapshot(), "reads": col.Truth(hub, health, ledger, lambda: SID).reads()}


SID_B = "ffffffff-0000-4000-8000-000000000000"


def moved(steps, served=False, watch=False):
    """review PR 234 v6: main's session moves. `steps` are (session, status) pairs; a status of None moves main without
    a ledger tick. The page gets what was pushed (the hub snapshot), or with `served` what /api/state serves; `watch`
    runs one pass of the server's session watch first (follow(); there is none at ec6d0edd, so nothing happens)."""
    hub = ev.Hub()
    health = col.Health(hub)
    runner = Runner()
    main = {"id": SID}
    ledger = col.Ledger(hub, health, runner, lambda: main["id"])
    for name in OTHERS:
        health.ok(name, "fixture")
    for n, (session, status) in enumerate(steps):
        main["id"] = session
        if status is not None:
            runner.status = status
            ledger.run(T0 + 60 * n)
    if watch:
        getattr(ledger, "follow", lambda: None)()
    return {"ledger": ledger.snapshot() if served else hub.snapshots.get("ledger"), "health": health.snapshot(),
            "reads": col.Truth(hub, health, ledger, lambda: main["id"]).reads()}


def main():
    if "--feeds" in sys.argv:
        print(json.dumps(col.FEEDS))
        return
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
    out["asks_never_read"] = scenario([good], other_health=tuple(n for n in OTHERS if n != "asks"), failed=("asks",))
    # v5 F1: a good read for main's session, then the owners snapshot drops main's session to "" and the ledger ticks
    out["session_dropped"] = moved([(SID, good), ("", good)])
    # main moved to another session; the ledger thread has not ticked since (inside a slow read, or between cadences)
    out["session_moved_served"] = moved([(SID, good), (SID_B, None)], served=True)
    out["session_moved_watched"] = moved([(SID, good), (SID_B, None)], watch=True)
    out["session_moved_failed"] = moved([(SID, good), (SID_B, FAILS["nonzero"])])
    out["session_moved_read"] = moved([(SID, good), (SID_B, good)])
    print(json.dumps(out, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
