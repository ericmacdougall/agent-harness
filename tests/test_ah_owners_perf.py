"""goodqa#15963: `ah owners` must stay inside tier_gate's 4 s deadline on a 2,400-agent session.

Count-based (deterministic) checks fail against the previous implementation: it stat-ed every agent in every
project's subagents dir (agents x dirs) and rewrote every index file on every call. A golden comparison runs the
origin/main implementation (AH_OLD_PY, when given) on the same fixture. Wall-clock numbers are reported in the
ticket, never asserted here.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
import ah  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"
NOW = 1_794_600_000.0


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        for r in rows:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


def build(home: Path, agents: int, dirs: int):
    """A session with `agents` sub-agents over `dirs` project dirs; transcripts live in one of them, as in reality.
    Covers live, SILENT-HIGH, idle-helper, DROPPED, done, returned, handoff, restricted and transcript-only rows."""
    w = home / ".claude" / "wals" / SESSION
    proj = home / ".claude" / "projects"
    for d in range(dirs):
        (proj / f"-p{d}").mkdir(parents=True)
    sub = proj / "-p0" / SESSION / "subagents"
    sub.mkdir(parents=True)
    main = []
    for i in range(agents):
        aid = f"a{i:016x}"
        kind = ("task-owner", "fixer", "general-purpose", "red-team")[i % 4]
        main.append({"at": iso(NOW - 9000), "event": "subagent", "agent_id": aid, "agent_type": kind})
        mode = i % 7
        if mode == 0:     # live owner with a ticket
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": f"build GoodQA goodqa#{i}"}])
        elif mode == 1:   # silent (high)
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 7300), "event": "intent", "note": "quiet work"}])
        elif mode == 2:   # stopped without a result: DROPPED for owners, returned for helpers
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 4000), "event": "intent", "note": "dropped"}])
            main.append({"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": aid, "agent_type": kind})
        elif mode == 3:   # done
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 500), "event": "intent", "note": "x"},
                                          {"at": iso(NOW - 200), "event": "result", "note": "all done"}])
            main.append({"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": aid, "agent_type": kind})
        elif mode == 4:   # handoff
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 900), "event": "handoff", "note": "over to main"}])
            main.append({"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": aid, "agent_type": kind})
        elif mode == 5:   # restricted task text
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 40), "event": "intent", "note": "Solve interview prep"}])
        # mode 6: no WAL at all; transcript only
        meta = {"agentType": kind, "description": f"d{i}"}
        if mode == 3:
            meta["finished"] = True
        (sub / f"agent-{aid}.meta.json").write_text(json.dumps(meta))
        t = sub / f"agent-{aid}.jsonl"
        t.write_text("{}\n")
        age = 20 if mode == 6 else 8000      # mode 6: the transcript is newer than any WAL
        os.utime(t, (NOW - age, NOW - age))
    jl(w / "main.jsonl", main)


def load_old():
    path = os.environ.get("AH_OLD_PY")
    if not path:
        return None
    spec = importlib.util.spec_from_file_location("ah_old", path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(Path(path).parent))
    spec.loader.exec_module(mod)
    return mod


def strip(data):
    return {k: v for k, v in data.items() if k != "generated"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "h"
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)

    def home_copy(self, name):
        dest = Path(self.tmp.name) / name
        shutil.copytree(self.home, dest, symlinks=True)
        return dest


class Counts(Base):
    AGENTS, DIRS = 240, 120

    def setUp(self):
        super().setUp()
        build(self.home, self.AGENTS, self.DIRS)

    def test_stat_and_scandir_calls_do_not_grow_with_agents_times_dirs(self):  # AC-1 (R4, M3)
        """Adding 120 empty project dirs may cost a few calls per dir, never one per agent per dir (old: +28,800)."""
        def count(home):
            calls = {"stat": 0, "scandir": 0, "lstat": 0}
            real = {name: getattr(os, name) for name in calls}

            def wrap(name):
                def f(*a, **k):
                    calls[name] += 1
                    return real[name](*a, **k)
                return f
            with mock.patch.object(os, "stat", wrap("stat")), mock.patch.object(os, "scandir", wrap("scandir")), \
                    mock.patch.object(os, "lstat", wrap("lstat")), \
                    mock.patch.dict(os.environ, {"AH_HOME": str(home), "HOME": str(home)}):
                ah.owners(home, SESSION, now=NOW)
            return sum(calls.values()), calls
        small = Path(self.tmp.name) / "small"
        build(small, self.AGENTS, self.DIRS)
        more = Path(self.tmp.name) / "more"   # same depth as `small`, so realpath costs match
        build(more, self.AGENTS, self.DIRS * 2)
        (few, few_calls), (many, many_calls) = count(small), count(more)
        self.assertLess(many - few, 4 * self.DIRS, (few_calls, many_calls))

    def test_an_unchanged_second_call_writes_no_index_file(self):  # AC-1 (R1: no unconditional rewrites)
        ah.owners(self.home, SESSION, now=NOW)
        with mock.patch.object(ah, "atomic_json", wraps=ah.atomic_json) as write:
            ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual(write.call_count, 0)

    def test_an_appended_wal_is_picked_up(self):  # NEG-2
        first = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}
        aid = "a" + f"{4:016x}"     # mode 4: handoff
        self.assertEqual(first[aid]["state"], "handoff")
        jl(self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl",
           [{"at": iso(NOW - 10), "event": "intent", "note": "back at it"}])
        again = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}
        self.assertNotEqual(again[aid]["state"], "handoff")

    def test_a_replaced_wal_of_the_same_size_is_reread(self):  # NEG-3
        aid = "a" + f"{3:016x}"     # mode 3: done
        path = self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl"
        ah.owners(self.home, SESSION, now=NOW)
        text = path.read_text().replace('"result"', '"status"')   # same length, new content, new inode
        path.unlink()
        path.write_text(text)
        row = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}[aid]
        fresh = self.home_copy("fresh")
        expect = {r["agent_id"]: r for r in ah.owners(fresh, SESSION, now=NOW)["owners"]}[aid]
        self.assertEqual(row, expect)

    def test_corrupt_combined_cache_is_rebuilt(self):  # NEG-1
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        cache = ah._owners_cache_path(ah.state_dir(self.home, "ah-index"), SESSION)
        cache.write_text('{"schema": 1, "wal": {"x": ')
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)
        cache.write_text(json.dumps({"schema": 1, "wal": {k: {"fp": [0, 0, 0], "s": {"bogus": 1}}
                                                           for k in ("a", "b")}, "meta": []}))
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)

    def test_stale_tmp_files_are_cleaned_only_when_old_and_orphaned(self):  # M1
        index = ah.state_dir(self.home, "ah-index")
        index.mkdir(parents=True, exist_ok=True)
        old_dead = index / "wal-x.json.999999.tmp"
        old_alive = index / f"wal-y.json.{os.getpid()}.tmp"
        young_dead = index / "wal-z.json.999998.tmp"
        for p in (old_dead, old_alive, young_dead):
            p.write_text("{}")
        for p in (old_dead, old_alive):
            os.utime(p, (NOW - 7200, NOW - 7200))
        os.utime(young_dead, (NOW - 60, NOW - 60))
        ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual((old_dead.exists(), old_alive.exists(), young_dead.exists()), (False, True, True))

    def test_an_interrupted_cold_run_still_leaves_progress(self):  # NEG-6 (R8)
        calls = {"n": 0}
        real = ah.summarize_agent_wal

        def boom(path, index_dir):
            calls["n"] += 1
            if calls["n"] > 120:
                raise KeyboardInterrupt  # stands in for tier_gate's deadline alarm
            return real(path, index_dir)
        with mock.patch.object(ah, "summarize_agent_wal", boom), mock.patch.object(ah, "OWNERS_CACHE_SAVE_EVERY", 50), \
                self.assertRaises(KeyboardInterrupt):
            ah.owners(self.home, SESSION, now=NOW)
        cache = json.loads(ah._owners_cache_path(ah.state_dir(self.home, "ah-index"), SESSION).read_text())
        self.assertGreaterEqual(len(cache["wal"]), 100)


class Golden(Base):
    """Same rows as origin/main for the same input, cold, warm and over an index the old code wrote (R5)."""

    def setUp(self):
        super().setUp()
        self.old = load_old()
        if self.old is None:
            self.skipTest("set AH_OLD_PY to origin/main's harness/hooks/ah.py to run the golden comparison")
        build(self.home, 140, 60)

    def test_same_output_as_the_previous_implementation(self):
        old_home, new_home, mixed = self.home_copy("old"), self.home_copy("new"), self.home_copy("mixed")
        with mock.patch.dict(os.environ, {"AH_HOME": str(old_home), "HOME": str(old_home)}):
            want = strip(self.old.owners(old_home, SESSION, now=NOW))
        states = {r["state"] for r in want["owners"]}
        self.assertTrue({"live", "DROPPED", "done", "returned", "handoff", "idle-helper"} <= states, states)
        self.assertTrue(any(s.startswith("SILENT") for s in states), states)
        self.assertTrue(any(r["restricted"] for r in want["owners"]))
        with mock.patch.dict(os.environ, {"AH_HOME": str(new_home), "HOME": str(new_home)}):
            self.assertEqual(strip(ah.owners(new_home, SESSION, now=NOW)), want, "cold")
            self.assertEqual(strip(ah.owners(new_home, SESSION, now=NOW)), want, "warm")
        with mock.patch.dict(os.environ, {"AH_HOME": str(mixed), "HOME": str(mixed)}):
            self.old.owners(mixed, SESSION, now=NOW)   # an index the old code wrote, then the new code reads it
            self.assertEqual(strip(ah.owners(mixed, SESSION, now=NOW)), want, "old index")


if __name__ == "__main__":
    unittest.main()
